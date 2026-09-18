// Copyright 2026 The Nerve Lab
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

use std::io::{IsTerminal, Read};
use std::path::PathBuf;
use std::time::Duration;

use anyhow::{anyhow, bail, Context};
use clap::{Args, Parser, Subcommand};
use zeroize::Zeroizing;

use matrix_notify::matrix::{self, Credentials, CrossSigningReport, LoginOptions, Notifier, SendOptions};
use matrix_notify::message::{Message, RunInfo, Status};
use matrix_notify::state::{self, StateKey};
use matrix_notify::store;
use matrix_notify::target::RoomTarget;

/// Post end-to-end encrypted messages to a Matrix room from CI.
#[derive(Parser)]
#[command(name = "matrix-notify", version, about, long_about = None)]
struct Cli {
    /// State directory (session + crypto store). Default: $MATRIX_NOTIFY_HOME or ~/.matrix-notify
    #[arg(long, global = true, env = "MATRIX_NOTIFY_STORE")]
    store: Option<PathBuf>,

    /// Log level (error, warn, info, debug, trace); also RUST_LOG
    #[arg(long, global = true, default_value = "warn")]
    log: String,

    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// First-time setup: create the bot device, bootstrap cross-signing, print the state secret
    Login(LoginArgs),
    /// Send a message to a room (m.notice by default)
    Send(SendArgs),
    /// Encrypted state archive: export, import, keygen, fingerprint
    State {
        #[command(subcommand)]
        cmd: StateCmd,
    },
    /// Show the identity in the store and check it against the server
    Whoami {
        /// Print JSON
        #[arg(long)]
        json: bool,
    },
    /// Create or update a GitHub Actions repository secret (needs a token with secrets: write)
    GithubSecret(GithubSecretArgs),
}

#[derive(Args)]
struct GithubSecretArgs {
    /// Secret name
    #[arg(long, default_value = "MATRIX_STATE")]
    name: String,
    /// owner/repo (default: $GITHUB_REPOSITORY)
    #[arg(long, env = "GITHUB_REPOSITORY")]
    repo: String,
    /// GitHub API base URL
    #[arg(long, env = "GITHUB_API_URL", default_value = "https://api.github.com")]
    api_url: String,
    /// Name of the environment variable holding the token (never passed on the command line)
    #[arg(long, default_value = "GH_TOKEN")]
    token_env: String,
    /// File with the secret value, or `-` for stdin
    #[arg(long = "value-file", default_value = "-")]
    value_file: String,
}

#[derive(Args)]
struct LoginArgs {
    /// Server name (hippius.com) or homeserver URL (https://chat.hippius.com)
    #[arg(long, default_value = "hippius.com")]
    homeserver: String,
    /// Localpart or full user id of the bot (ci or @ci:hippius.com)
    #[arg(long, required_unless_present = "token")]
    user: Option<String>,
    /// Read the password from stdin (first line)
    #[arg(long, conflicts_with = "token")]
    password_stdin: bool,
    /// Access token for an existing device (e.g. issued by MAS); read from stdin with `-`
    #[arg(long, conflicts_with = "password_stdin")]
    token: Option<String>,
    /// Device display name. Default: "matrix-notify (<GITHUB_REPOSITORY>)" or "matrix-notify"
    #[arg(long)]
    device_name: Option<String>,
    /// Replace an existing cross-signing identity with one owned by this device
    #[arg(long)]
    reset_cross_signing: bool,
    /// Room(s) to join now so the snapshot already knows them (alias or id)
    #[arg(long = "join")]
    join: Vec<String>,
    /// Encrypt the printed state with this key instead of generating one
    #[arg(long, env = "MATRIX_STATE_KEY", hide_env_values = true)]
    key: Option<String>,
    /// Do not print the encrypted state (only log in)
    #[arg(long)]
    no_export: bool,
}

#[derive(Args)]
struct SendArgs {
    /// Room alias (#ci:hippius.com), room id (!x:hippius.com) or matrix.to link
    #[arg(long, env = "MATRIX_ROOM")]
    room: String,
    /// Message text; `-` reads stdin
    #[arg(long, required_unless_present = "format")]
    message: Option<String>,
    /// Treat the message as Markdown and attach an HTML formatted_body
    #[arg(long)]
    markdown: bool,
    /// Render a compact card from GITHUB_* environment variables
    #[arg(long, value_parser = ["github-run"])]
    format: Option<String>,
    /// Job status for --format github-run (success|failure|cancelled)
    #[arg(long, env = "MATRIX_NOTIFY_STATUS")]
    status: Option<String>,
    /// Send m.notice (default: on). Use --no-notice for m.text
    #[arg(long, default_value_t = true, action = clap::ArgAction::Set, num_args = 0..=1, default_missing_value = "true")]
    notice: bool,
    /// Alias for --notice=false
    #[arg(long, conflicts_with = "notice")]
    no_notice: bool,
    /// Send plaintext if the room is not encrypted (default: refuse)
    #[arg(long)]
    allow_unencrypted: bool,
    /// Force a short sync before sending (otherwise only when the room is unknown)
    #[arg(long)]
    sync: bool,
    /// Overall network timeout in seconds
    #[arg(long, default_value_t = 60)]
    timeout: u64,
    /// Print the event id as JSON on stdout
    #[arg(long)]
    json: bool,
}

#[derive(Subcommand)]
enum StateCmd {
    /// Generate a fresh 32-byte key (hex)
    Keygen,
    /// Encrypt the store into a single base64 blob
    Export {
        /// Output file, or `-` for stdout
        #[arg(long, default_value = "-")]
        out: String,
        #[arg(long, env = "MATRIX_STATE_KEY", hide_env_values = true)]
        key: String,
    },
    /// Restore the store from a blob (base64 text or raw)
    Import {
        /// Input file, or `-` for stdin
        #[arg(long = "in", default_value = "-")]
        input: String,
        #[arg(long, env = "MATRIX_STATE_KEY", hide_env_values = true)]
        key: String,
    },
    /// Print the identity fingerprint (changes only when the secret must be re-published)
    Fingerprint,
}

fn main() {
    let cli = Cli::parse();
    init_logging(&cli.log);
    let rt = tokio::runtime::Builder::new_multi_thread().enable_all().build().expect("tokio runtime");
    let code = match rt.block_on(run(cli)) {
        Ok(()) => 0,
        Err(e) => {
            eprintln!("error: {e:#}");
            1
        }
    };
    // Give the SDK's background tasks a moment to release SQLite handles.
    rt.shutdown_timeout(Duration::from_secs(2));
    std::process::exit(code);
}

fn init_logging(level: &str) {
    let filter = tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| {
        tracing_subscriber::EnvFilter::new(format!(
            "{level},matrix_sdk_crypto=warn,matrix_sdk_base=warn,matrix_sdk_sqlite=warn"
        ))
    });
    tracing_subscriber::fmt().with_env_filter(filter).with_writer(std::io::stderr).with_target(false).init();
}

async fn run(cli: Cli) -> anyhow::Result<()> {
    let dir = store::resolve_dir(cli.store.as_deref())?;
    match cli.cmd {
        Cmd::Login(a) => cmd_login(&dir, a).await,
        Cmd::Send(a) => cmd_send(&dir, a).await,
        Cmd::State { cmd } => cmd_state(&dir, cmd),
        Cmd::Whoami { json } => cmd_whoami(&dir, json).await,
        Cmd::GithubSecret(a) => cmd_github_secret(a).await,
    }
}

fn read_stdin_trimmed() -> anyhow::Result<Zeroizing<String>> {
    let mut s = Zeroizing::new(String::new());
    std::io::stdin().read_to_string(&mut s).context("reading stdin")?;
    let trimmed = s.trim_end_matches(['\n', '\r']).to_owned();
    Ok(Zeroizing::new(trimmed))
}

fn read_stdin_line() -> anyhow::Result<Zeroizing<String>> {
    let mut s = Zeroizing::new(String::new());
    std::io::stdin().read_line(&mut s).context("reading stdin")?;
    let trimmed = s.trim_end_matches(['\n', '\r']).to_owned();
    Ok(Zeroizing::new(trimmed))
}

fn default_device_name() -> String {
    match std::env::var("GITHUB_REPOSITORY").ok().filter(|s| !s.is_empty()) {
        Some(repo) => format!("matrix-notify ({repo})"),
        None => "matrix-notify".to_owned(),
    }
}

async fn cmd_login(dir: &std::path::Path, a: LoginArgs) -> anyhow::Result<()> {
    let credentials = if let Some(token) = a.token {
        let token = if token == "-" { read_stdin_line()?.to_string() } else { token };
        Credentials::Token(token)
    } else {
        let user = a.user.clone().ok_or_else(|| anyhow!("--user is required"))?;
        if !a.password_stdin {
            bail!("provide the password with --password-stdin (or use --token)");
        }
        if std::io::stdin().is_terminal() {
            eprintln!("password: (input is not hidden; pipe it in to avoid echo)");
        }
        let password = read_stdin_line()?;
        if password.is_empty() {
            bail!("empty password on stdin");
        }
        Credentials::Password { user, password: password.to_string() }
    };

    let key = match &a.key {
        Some(k) => StateKey::from_hex(k)?,
        None => StateKey::generate()?,
    };
    let generated_key = a.key.is_none();

    let join = a.join.iter().map(|r| RoomTarget::parse(r)).collect::<Result<Vec<_>, _>>()?;
    let report = matrix::login(
        dir,
        LoginOptions {
            homeserver: a.homeserver,
            credentials,
            device_name: a.device_name.unwrap_or_else(default_device_name),
            reset_cross_signing: a.reset_cross_signing,
            join,
        },
    )
    .await?;

    eprintln!("logged in as {} device {} via {}", report.user_id, report.device_id, report.homeserver);
    match &report.cross_signing {
        CrossSigningReport::Bootstrapped => eprintln!("cross-signing: bootstrapped, device is self-signed"),
        CrossSigningReport::Present => eprintln!("cross-signing: already present, device is self-signed"),
        CrossSigningReport::NotSignedByExistingIdentity => eprintln!(
            "cross-signing: WARNING an identity created by another session exists; this device is not signed by it.\n  \
             Either verify this device from that session, or re-run with --reset-cross-signing."
        ),
        CrossSigningReport::NeedsInteractiveAuth(why) => {
            eprintln!("cross-signing: WARNING not bootstrapped: {why}")
        }
    }
    for r in &report.joined {
        eprintln!("joined {r}");
    }

    if a.no_export {
        eprintln!("state left in {}", dir.display());
        return Ok(());
    }

    store::prepare_export(dir)?;
    let blob = state::export(dir, &key)?;
    eprintln!();
    eprintln!("Add these two repository secrets (Settings > Secrets and variables > Actions):");
    eprintln!();
    if generated_key {
        eprintln!("  MATRIX_STATE_KEY   (new key, keep it safe)");
    } else {
        eprintln!("  MATRIX_STATE_KEY   (the key you provided)");
    }
    eprintln!("  MATRIX_STATE       ({} bytes of base64)", blob.len());
    eprintln!();
    println!("MATRIX_STATE_KEY={}", key.to_hex().as_str());
    println!("MATRIX_STATE={blob}");
    Ok(())
}

async fn cmd_send(dir: &std::path::Path, a: SendArgs) -> anyhow::Result<()> {
    let target = RoomTarget::parse(&a.room)?;
    let notice = a.notice && !a.no_notice;

    let text = match a.message.as_deref() {
        Some("-") => Some(read_stdin_trimmed()?.to_string()),
        Some(m) => Some(m.to_owned()),
        None => None,
    };

    let message = match a.format.as_deref() {
        Some("github-run") => {
            let status_str = a
                .status
                .as_deref()
                .ok_or_else(|| anyhow!("--format github-run needs --status success|failure|cancelled"))?;
            let status = Status::parse(status_str).ok_or_else(|| {
                anyhow!("unknown --status {status_str:?} (expected success|failure|cancelled)")
            })?;
            let info = RunInfo::from_env();
            if info.repository.is_empty() || info.run_id.is_empty() {
                bail!("--format github-run needs GITHUB_REPOSITORY and GITHUB_RUN_ID in the environment");
            }
            let mut m = info.render(status, text.as_deref(), a.markdown);
            m.notice = notice;
            m
        }
        Some(other) => bail!("unknown --format {other:?}"),
        None => {
            let text = text.ok_or_else(|| anyhow!("--message is required"))?;
            if text.trim().is_empty() {
                bail!("refusing to send an empty message");
            }
            if a.markdown {
                Message::markdown(&text, notice)
            } else {
                Message::plain(text, notice)
            }
        }
    };

    let timeout = Duration::from_secs(a.timeout);
    let notifier = Notifier::open(dir, false, timeout).await?;
    let opts = SendOptions { allow_unencrypted: a.allow_unencrypted, sync: a.sync, timeout };
    let report = notifier.send(&target, message, &opts).await?;
    let fingerprint = notifier.close().await?;

    if a.json {
        println!(
            "{}",
            serde_json::json!({
                "room_id": report.room_id,
                "event_id": report.event_id,
                "encrypted": report.encrypted,
                "recipients": report.recipients,
                "identity_fingerprint": fingerprint,
            })
        );
    } else {
        eprintln!(
            "sent {} to {} ({}, {} members)",
            report.event_id,
            report.room_id,
            if report.encrypted { "encrypted" } else { "PLAINTEXT" },
            report.recipients
        );
    }
    Ok(())
}

fn cmd_state(dir: &std::path::Path, cmd: StateCmd) -> anyhow::Result<()> {
    match cmd {
        StateCmd::Keygen => {
            println!("{}", StateKey::generate()?.to_hex().as_str());
            Ok(())
        }
        StateCmd::Export { out, key } => {
            let key = StateKey::from_hex(&key)?;
            if !store::has_session(dir) {
                bail!("nothing to export: {} has no session", dir.display());
            }
            store::prepare_export(dir)?;
            let blob = state::export(dir, &key)?;
            state::write_output(&out, &blob)?;
            eprintln!("exported {} bytes of base64", blob.len());
            Ok(())
        }
        StateCmd::Import { input, key } => {
            let key = StateKey::from_hex(&key)?;
            let bytes = if input == "-" {
                let mut v = Vec::new();
                std::io::stdin().read_to_end(&mut v).context("reading stdin")?;
                v
            } else {
                std::fs::read(&input).with_context(|| format!("reading {input}"))?
            };
            if bytes.iter().all(u8::is_ascii_whitespace) {
                bail!("empty state input (is the MATRIX_STATE secret set?)");
            }
            let written = state::import(dir, &key, &bytes)?;
            if !written.iter().any(|f| f == store::SESSION_FILE) {
                bail!("archive did not contain {}", store::SESSION_FILE);
            }
            eprintln!("imported {} file(s) into {}", written.len(), dir.display());
            Ok(())
        }
        StateCmd::Fingerprint => {
            let s = store::Session::load(dir)?;
            println!("{}", s.identity_fingerprint());
            Ok(())
        }
    }
}

async fn cmd_whoami(dir: &std::path::Path, json: bool) -> anyhow::Result<()> {
    let notifier = Notifier::open(dir, true, Duration::from_secs(30)).await?;
    let w = notifier.whoami().await?;
    let fingerprint = notifier.close().await?;
    if json {
        println!(
            "{}",
            serde_json::json!({
                "homeserver": w.homeserver,
                "user_id": w.user_id,
                "device_id": w.device_id,
                "device_name": w.device_name,
                "cross_signed": w.cross_signed,
                "has_cross_signing_keys": w.has_cross_signing_keys,
                "joined_rooms": w.joined_rooms,
                "server_ok": w.server_ok,
                "identity_fingerprint": fingerprint,
            })
        );
    } else {
        println!("homeserver:    {}", w.homeserver);
        println!("user:          {}", w.user_id);
        println!(
            "device:        {} ({})",
            w.device_id,
            w.device_name.as_deref().unwrap_or("no display name")
        );
        println!(
            "cross-signed:  {}",
            match w.cross_signed {
                Some(true) => "yes",
                Some(false) => "no",
                None => "unknown",
            }
        );
        println!("signing keys:  {}", if w.has_cross_signing_keys { "present" } else { "absent" });
        println!("server check:  {}", if w.server_ok { "ok" } else { "FAILED (token rejected?)" });
        println!(
            "rooms:         {}",
            if w.joined_rooms.is_empty() { "-".to_owned() } else { w.joined_rooms.join(", ") }
        );
    }
    if !w.server_ok {
        bail!("homeserver rejected the session token");
    }
    Ok(())
}

async fn cmd_github_secret(a: GithubSecretArgs) -> anyhow::Result<()> {
    let token = std::env::var(&a.token_env)
        .ok()
        .filter(|t| !t.trim().is_empty())
        .ok_or_else(|| anyhow!("environment variable {} is not set", a.token_env))?;
    let value = if a.value_file == "-" {
        read_stdin_trimmed()?
    } else {
        Zeroizing::new(
            std::fs::read_to_string(&a.value_file)
                .with_context(|| format!("reading {}", a.value_file))?
                .trim_end_matches(['\n', '\r'])
                .to_owned(),
        )
    };
    if value.is_empty() {
        bail!("refusing to store an empty secret");
    }
    let client = matrix_notify::github::SecretsClient::new(&a.api_url, &a.repo, token.trim())?;
    client.put_secret(&a.name, &value).await?;
    eprintln!("secret {} updated on {}", a.name, a.repo);
    Ok(())
}
