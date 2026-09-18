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

//! Everything that talks to the homeserver: first-time login, session
//! restore, encrypted send, `whoami`.
//!
//! Design notes
//!
//! * A run never persists its conversation state (see
//!   [`crate::store::hygiene`]). Each `send` therefore starts a fresh Megolm
//!   session for the room and shares it over fresh Olm sessions. The device
//!   identity, cross-signing keys and access token are the only long-lived
//!   pieces.
//! * `send` refuses to post to a room whose encryption state is not
//!   `Encrypted` unless explicitly allowed, so a misconfigured room cannot
//!   silently downgrade the whole point of the tool.
//! * No refresh tokens are requested: the access token in the snapshot must
//!   keep working across runs without being rotated.

use std::path::{Path, PathBuf};
use std::time::Duration;

use anyhow::{anyhow, bail, Context};
use matrix_sdk::authentication::matrix::MatrixSession;
use matrix_sdk::config::{RequestConfig, SyncSettings};
use matrix_sdk::encryption::{BackupDownloadStrategy, EncryptionSettings};
use matrix_sdk::ruma::api::client::filter::{FilterDefinition, LazyLoadOptions, RoomEventFilter, RoomFilter};
use matrix_sdk::ruma::api::client::sync::sync_events::v3::Filter;
use matrix_sdk::ruma::api::client::uiaa::{AuthData, MatrixUserIdentifier, Password, UserIdentifier};
use matrix_sdk::ruma::{OwnedRoomId, OwnedUserId, RoomOrAliasId, UserId};
use matrix_sdk::{Client, Room, RoomState, SessionMeta, SessionTokens};
use serde::Deserialize;
use tracing::{debug, info, warn};

use crate::message::Message;
use crate::store::Session;
use crate::target::RoomTarget;

const USER_AGENT: &str = concat!("matrix-notify/", env!("CARGO_PKG_VERSION"));

/// How to authenticate at `login`.
pub enum Credentials {
    Password {
        user: String,
        password: String,
    },
    /// A MAS- or admin-issued access token for an existing device.
    Token(String),
}

pub struct LoginOptions {
    pub homeserver: String,
    pub credentials: Credentials,
    pub device_name: String,
    /// Replace an existing cross-signing identity with a fresh one owned by
    /// this device (other sessions of the bot become unverified).
    pub reset_cross_signing: bool,
    /// Rooms to join right away so the snapshot already knows them.
    pub join: Vec<RoomTarget>,
}

#[derive(Debug)]
pub struct LoginReport {
    pub user_id: String,
    pub device_id: String,
    pub homeserver: String,
    pub cross_signing: CrossSigningReport,
    pub joined: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CrossSigningReport {
    /// We created the identity; this device is self-signed.
    Bootstrapped,
    /// Identity existed and we hold the private keys (device self-signed).
    Present,
    /// Identity exists on the server but was created elsewhere: this device
    /// is not signed by it. Message still sends; readers see a grey shield.
    NotSignedByExistingIdentity,
    /// Server required interactive auth we could not satisfy.
    NeedsInteractiveAuth(String),
}

pub struct SendOptions {
    pub allow_unencrypted: bool,
    /// Run a short sync before sending even if the room is already known.
    pub sync: bool,
    pub timeout: Duration,
}

#[derive(Debug)]
pub struct SendReport {
    pub room_id: OwnedRoomId,
    pub event_id: String,
    pub encrypted: bool,
    pub recipients: usize,
}

#[derive(Debug)]
pub struct WhoAmI {
    pub homeserver: String,
    pub user_id: String,
    pub device_id: String,
    pub device_name: Option<String>,
    pub cross_signed: Option<bool>,
    pub has_cross_signing_keys: bool,
    pub joined_rooms: Vec<String>,
    /// Whether the server accepted the token (`/account/whoami`).
    pub server_ok: bool,
}

fn encryption_settings() -> EncryptionSettings {
    EncryptionSettings {
        auto_enable_cross_signing: false,
        backup_download_strategy: BackupDownloadStrategy::Manual,
        auto_enable_backups: false,
    }
}

fn request_config(timeout: Duration) -> RequestConfig {
    RequestConfig::new().timeout(timeout).retry_limit(3)
}

/// Sync filter for a send-only bot: lazy-loaded members, one timeline event
/// per room, no presence. Keeps the state store (and so the secret) small.
fn lean_filter() -> Filter {
    let mut def = FilterDefinition::default();
    def.room = RoomFilter::default();
    def.room.state = RoomEventFilter::default();
    def.room.state.lazy_load_options = LazyLoadOptions::Enabled { include_redundant_members: false };
    def.room.timeline = RoomEventFilter::default();
    def.room.timeline.limit = Some(1u32.into());
    def.presence.not_types = vec!["*".to_owned()];
    Filter::FilterDefinition(def)
}

async fn build_client(
    homeserver: &str,
    dir: &Path,
    discover: bool,
    timeout: Duration,
) -> anyhow::Result<Client> {
    crate::store::ensure_private_dir(dir)?;
    let mut b = Client::builder()
        .sqlite_store(dir, None)
        .user_agent(USER_AGENT)
        .request_config(request_config(timeout))
        .with_encryption_settings(encryption_settings());
    b = if discover { b.server_name_or_homeserver_url(homeserver) } else { b.homeserver_url(homeserver) };
    b.build().await.with_context(|| format!("connecting to homeserver {homeserver}"))
}

#[derive(Deserialize)]
struct WhoAmIBody {
    user_id: OwnedUserId,
    device_id: Option<String>,
}

/// `GET /_matrix/client/v3/account/whoami` with a bare token, used before we
/// have a session to hand to the SDK.
async fn whoami_raw(homeserver: &url::Url, token: &str, timeout: Duration) -> anyhow::Result<WhoAmIBody> {
    let http = reqwest::Client::builder().user_agent(USER_AGENT).timeout(timeout).build()?;
    let url = homeserver.join("_matrix/client/v3/account/whoami")?;
    let resp = http.get(url).bearer_auth(token).send().await.context("whoami request")?;
    let status = resp.status();
    if !status.is_success() {
        let body = resp.text().await.unwrap_or_default();
        bail!("token rejected by homeserver ({status}): {}", body.chars().take(200).collect::<String>());
    }
    resp.json().await.context("parsing whoami response")
}

/// First-time setup: create (or adopt) the device, upload keys, bootstrap
/// cross-signing, optionally join rooms, and write `session.json`.
pub async fn login(dir: &Path, opts: LoginOptions) -> anyhow::Result<LoginReport> {
    if crate::store::has_session(dir) {
        bail!("{} already holds a session; use a different --store or remove it first", dir.display());
    }
    let timeout = Duration::from_secs(60);
    let client = build_client(&opts.homeserver, dir, true, timeout).await?;
    let homeserver = client.homeserver();
    info!(%homeserver, "homeserver resolved");

    let mut password_for_uiaa: Option<(String, String)> = None;
    match &opts.credentials {
        Credentials::Password { user, password } => {
            client
                .matrix_auth()
                .login_username(user, password)
                .initial_device_display_name(&opts.device_name)
                .send()
                .await
                .context("password login failed")?;
            password_for_uiaa = Some((user.clone(), password.clone()));
        }
        Credentials::Token(token) => {
            let who = whoami_raw(&homeserver, token, timeout).await?;
            let device_id = who.device_id.ok_or_else(|| {
                anyhow!("this token is not bound to a device (no device_id in whoami); matrix-notify needs a device")
            })?;
            let session = MatrixSession {
                meta: SessionMeta { user_id: who.user_id, device_id: device_id.into() },
                tokens: SessionTokens { access_token: token.clone(), refresh_token: None },
            };
            client.restore_session(session).await.context("adopting token session")?;
            if let (Some(dev), name) = (client.device_id(), &opts.device_name) {
                if let Err(e) = client.rename_device(dev, name).await {
                    warn!("could not set device display name: {e}");
                }
            }
        }
    }

    let user_id = client.user_id().ok_or_else(|| anyhow!("no user id after login"))?.to_owned();
    let device_id = client.device_id().ok_or_else(|| anyhow!("no device id after login"))?.to_owned();
    info!(%user_id, %device_id, "logged in");

    // Persist immediately: even if the steps below fail, the device exists
    // on the server and we must not lose the token that owns it.
    let session = Session {
        homeserver: homeserver.to_string(),
        server_name: opts.homeserver.clone(),
        user_id: user_id.to_string(),
        device_id: device_id.to_string(),
        access_token: client.session_tokens().map(|t| t.access_token).unwrap_or_default(),
        refresh_token: None,
    };
    session.save(dir)?;

    // Initial sync: uploads device keys + one-time keys, learns rooms.
    client
        .sync_once(SyncSettings::default().timeout(Duration::from_secs(5)).filter(lean_filter()))
        .await
        .context("initial sync")?;

    let cross_signing =
        setup_cross_signing(&client, &user_id, opts.reset_cross_signing, password_for_uiaa).await?;

    let mut joined = Vec::new();
    for target in &opts.join {
        let room = ensure_joined(&client, target, false).await?;
        joined.push(room.room_id().to_string());
    }

    client.encryption().wait_for_e2ee_initialization_tasks().await;
    // Flush any outgoing crypto requests produced above (key uploads,
    // signatures) before we snapshot.
    client.sync_once(SyncSettings::default().timeout(Duration::ZERO).filter(lean_filter())).await.ok();
    drop(client);

    Ok(LoginReport {
        user_id: user_id.to_string(),
        device_id: device_id.to_string(),
        homeserver: homeserver.to_string(),
        cross_signing,
        joined,
    })
}

async fn setup_cross_signing(
    client: &Client,
    user_id: &UserId,
    reset: bool,
    password: Option<(String, String)>,
) -> anyhow::Result<CrossSigningReport> {
    let enc = client.encryption();
    let existing = enc.get_user_identity(user_id).await.context("looking up own identity")?;
    let status = enc.cross_signing_status().await;
    let have_private = status.as_ref().is_some_and(|s| s.has_master && s.has_self_signing);

    if existing.is_some() && have_private && !reset {
        return Ok(CrossSigningReport::Present);
    }
    if existing.is_some() && !reset {
        warn!("cross-signing is already set up for {user_id} by another session; this device is not signed by it. \
               Verify it from that session, or re-run login with --reset-cross-signing.");
        return Ok(CrossSigningReport::NotSignedByExistingIdentity);
    }

    match enc.bootstrap_cross_signing(None).await {
        Ok(()) => Ok(CrossSigningReport::Bootstrapped),
        Err(e) => {
            let Some(uiaa) = e.as_uiaa_response().cloned() else {
                return Err(anyhow!(e).context("bootstrapping cross-signing"));
            };
            let Some((user, pw)) = password else {
                return Ok(CrossSigningReport::NeedsInteractiveAuth(
                    "server requires interactive auth to upload cross-signing keys; log in with a password (not --token)".into(),
                ));
            };
            let mut auth = Password::new(UserIdentifier::Matrix(MatrixUserIdentifier::new(user)), pw);
            auth.session = uiaa.session;
            match enc.bootstrap_cross_signing(Some(AuthData::Password(auth))).await {
                Ok(()) => Ok(CrossSigningReport::Bootstrapped),
                Err(e) => Ok(CrossSigningReport::NeedsInteractiveAuth(e.to_string())),
            }
        }
    }
}

/// A restored session ready to send.
pub struct Notifier {
    client: Client,
    dir: PathBuf,
    session: Session,
}

impl Notifier {
    /// Restore from `dir`. Runs [`crate::store::hygiene`] first unless
    /// `keep_sessions` (used by `whoami`, which must not mutate).
    pub async fn open(dir: &Path, keep_sessions: bool, timeout: Duration) -> anyhow::Result<Self> {
        let session = Session::load(dir)?;
        if !keep_sessions {
            let n = crate::store::hygiene(dir)?;
            debug!(removed = n, "crypto store hygiene");
        }
        let client = build_client(&session.homeserver, dir, false, timeout).await?;
        let matrix_session = MatrixSession {
            meta: SessionMeta {
                user_id: session.user_id.parse().context("session.json: bad user_id")?,
                device_id: session.device_id.as_str().into(),
            },
            tokens: SessionTokens {
                access_token: session.access_token.clone(),
                refresh_token: session.refresh_token.clone(),
            },
        };
        client.restore_session(matrix_session).await.context("restoring session")?;
        Ok(Self { client, dir: dir.to_path_buf(), session })
    }

    pub fn session(&self) -> &Session {
        &self.session
    }

    pub async fn send(
        &self,
        target: &RoomTarget,
        message: Message,
        opts: &SendOptions,
    ) -> anyhow::Result<SendReport> {
        let room = ensure_joined(&self.client, target, opts.sync).await?;
        let room_id = room.room_id().to_owned();

        // Fresh membership: a member who joined since the snapshot must get
        // the room key too.
        room.sync_members().await.context("fetching room members")?;
        let recipients = room.joined_members_count() as usize;

        let enc_state = room.latest_encryption_state().await.context("reading room encryption state")?;
        let encrypted = enc_state.is_encrypted();
        if !encrypted && !opts.allow_unencrypted {
            bail!(
                "room {} is not encrypted (state: {:?}); refusing to send plaintext. Enable encryption in the room \
                 or pass --allow-unencrypted",
                room_id,
                enc_state
            );
        }

        if encrypted {
            // Never reuse a Megolm session from the snapshot: see store::hygiene.
            room.discard_room_key().await.context("rotating room key")?;
        }

        let content = message.into_content();
        let result = tokio::time::timeout(opts.timeout, room.send(content))
            .await
            .map_err(|_| anyhow!("send timed out after {:?}", opts.timeout))?
            .context("sending message")?;
        let event_id = result.response.event_id.to_string();
        info!(%room_id, %event_id, encrypted, "message sent");

        Ok(SendReport { room_id, event_id, encrypted, recipients })
    }

    pub async fn whoami(&self) -> anyhow::Result<WhoAmI> {
        let server_ok = match self.client.whoami().await {
            Ok(r) => {
                if r.user_id != self.session.user_id.as_str() {
                    warn!("server reports {} but session.json says {}", r.user_id, self.session.user_id);
                }
                true
            }
            Err(e) => {
                warn!("whoami rejected: {e}");
                false
            }
        };
        let enc = self.client.encryption();
        let own = enc.get_own_device().await.ok().flatten();
        let status = enc.cross_signing_status().await;
        Ok(WhoAmI {
            homeserver: self.session.homeserver.clone(),
            user_id: self.session.user_id.clone(),
            device_id: self.session.device_id.clone(),
            device_name: own.as_ref().and_then(|d| d.display_name().map(str::to_owned)),
            cross_signed: own.as_ref().map(|d| d.is_cross_signed_by_owner()),
            has_cross_signing_keys: status.is_some_and(|s| s.has_master && s.has_self_signing),
            joined_rooms: self.client.joined_rooms().iter().map(|r| r.room_id().to_string()).collect(),
            server_ok,
        })
    }

    /// Persist anything the SDK may have rotated (tokens) and release the
    /// store. Returns the identity fingerprint after the run.
    pub async fn close(self) -> anyhow::Result<String> {
        let Self { client, dir, mut session } = self;
        if let Some(tokens) = client.session_tokens() {
            if tokens.access_token != session.access_token || tokens.refresh_token != session.refresh_token {
                session.access_token = tokens.access_token;
                session.refresh_token = tokens.refresh_token;
                session.save(&dir)?;
                info!("session tokens rotated; state secret must be re-exported");
            }
        }
        drop(client);
        Ok(session.identity_fingerprint())
    }
}

/// Resolve `target` to a joined [`Room`], syncing and joining as needed.
async fn ensure_joined(client: &Client, target: &RoomTarget, force_sync: bool) -> anyhow::Result<Room> {
    let (room_id, via) = match target {
        RoomTarget::Id { room_id, via } => (room_id.clone(), via.clone()),
        RoomTarget::Alias(alias) => {
            let resolved =
                client.resolve_room_alias(alias).await.with_context(|| format!("resolving alias {alias}"))?;
            (resolved.room_id, resolved.servers)
        }
    };

    let mut room = client.get_room(&room_id);
    let known_joined = room.as_ref().is_some_and(|r| r.state() == RoomState::Joined);
    if force_sync || !known_joined {
        client
            .sync_once(SyncSettings::default().timeout(Duration::ZERO).filter(lean_filter()))
            .await
            .context("sync")?;
        room = client.get_room(&room_id);
    }

    match room.as_ref().map(|r| r.state()) {
        Some(RoomState::Joined) => Ok(room.unwrap()),
        Some(RoomState::Invited) => {
            let r = room.unwrap();
            r.join().await.with_context(|| format!("accepting invite to {room_id}"))?;
            info!(%room_id, "accepted invite");
            Ok(client.get_room(&room_id).unwrap_or(r))
        }
        Some(RoomState::Banned) => bail!("this account is banned from {room_id}"),
        Some(RoomState::Left) | Some(RoomState::Knocked) | None => {
            let id_or_alias: &RoomOrAliasId = match target {
                RoomTarget::Alias(a) => {
                    let a: &matrix_sdk::ruma::RoomAliasId = a;
                    a.into()
                }
                RoomTarget::Id { room_id, .. } => {
                    let r: &matrix_sdk::ruma::RoomId = room_id;
                    r.into()
                }
            };
            let joined = client.join_room_by_id_or_alias(id_or_alias, &via).await.with_context(|| {
                format!(
                    "joining {}: the bot must be invited to (or the room must be public) {room_id}",
                    target.describe()
                )
            })?;
            info!(%room_id, "joined room");
            Ok(joined)
        }
    }
}
