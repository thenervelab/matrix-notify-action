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

//! On-disk layout of a matrix-notify store directory and the small amount of
//! SQLite surgery we do on it.
//!
//! ```text
//! <store>/
//!   session.json                 access token, user/device id, homeserver
//!   matrix-sdk-crypto.sqlite3    Olm account, cross-signing keys, devices
//!   matrix-sdk-state.sqlite3     rooms, members, sync token
//!   matrix-sdk-event-cache.sqlite3   regenerable, never exported
//! ```
//!
//! The directory is 0700 and every file we create is 0600.

use std::fs;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

/// Files that make up the portable identity. Order is the tar order.
pub const EXPORTED_FILES: &[&str] = &[SESSION_FILE, STATE_DB, CRYPTO_DB];

pub const SESSION_FILE: &str = "session.json";
pub const STATE_DB: &str = "matrix-sdk-state.sqlite3";
pub const CRYPTO_DB: &str = "matrix-sdk-crypto.sqlite3";

/// Resolve the store directory: explicit flag, then `$MATRIX_NOTIFY_HOME`,
/// then `~/.matrix-notify`.
pub fn resolve_dir(flag: Option<&Path>) -> anyhow::Result<PathBuf> {
    if let Some(p) = flag {
        return Ok(p.to_path_buf());
    }
    if let Some(p) = std::env::var_os("MATRIX_NOTIFY_HOME").filter(|s| !s.is_empty()) {
        return Ok(PathBuf::from(p));
    }
    let home = dirs::home_dir().ok_or_else(|| {
        anyhow::anyhow!("cannot determine home directory; pass --store or set MATRIX_NOTIFY_HOME")
    })?;
    Ok(home.join(".matrix-notify"))
}

/// Create `dir` (and parents) with mode 0700, or tighten an existing one.
pub fn ensure_private_dir(dir: &Path) -> std::io::Result<()> {
    fs::create_dir_all(dir)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(dir, fs::Permissions::from_mode(0o700))?;
    }
    Ok(())
}

/// Create (truncating) a file with mode 0600.
pub fn create_private_file(path: &Path) -> std::io::Result<fs::File> {
    let mut opts = fs::OpenOptions::new();
    opts.write(true).create(true).truncate(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    opts.open(path)
}

/// What we need to come back as the same device. Serialised to
/// `session.json`; never logged.
#[derive(Clone, Serialize, Deserialize)]
pub struct Session {
    /// Resolved base URL of the client-server API (after `.well-known`).
    pub homeserver: String,
    /// What the user typed (`hippius.com`), kept for display.
    pub server_name: String,
    pub user_id: String,
    pub device_id: String,
    pub access_token: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub refresh_token: Option<String>,
}

impl std::fmt::Debug for Session {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Session")
            .field("homeserver", &self.homeserver)
            .field("user_id", &self.user_id)
            .field("device_id", &self.device_id)
            .field("access_token", &"<redacted>")
            .field("refresh_token", &self.refresh_token.as_ref().map(|_| "<redacted>"))
            .finish()
    }
}

impl Session {
    pub fn path(dir: &Path) -> PathBuf {
        dir.join(SESSION_FILE)
    }

    pub fn load(dir: &Path) -> anyhow::Result<Self> {
        let path = Self::path(dir);
        let bytes = fs::read(&path).map_err(|e| {
            anyhow::anyhow!(
                "no session in {} ({e}); run `matrix-notify login` or `matrix-notify state import` first",
                dir.display()
            )
        })?;
        Ok(serde_json::from_slice(&bytes)?)
    }

    pub fn save(&self, dir: &Path) -> anyhow::Result<()> {
        ensure_private_dir(dir)?;
        let tmp = dir.join(".session.json.tmp");
        {
            let mut f = create_private_file(&tmp)?;
            serde_json::to_writer_pretty(&mut f, self)?;
            use std::io::Write;
            f.write_all(b"\n")?;
            f.sync_all()?;
        }
        fs::rename(tmp, Self::path(dir))?;
        Ok(())
    }

    /// Stable digest of the fields whose change requires re-publishing the
    /// state secret: which device we are and how we authenticate. Room
    /// state, sync tokens and one-time keys are deliberately excluded (they
    /// change on every run and are regenerable).
    pub fn identity_fingerprint(&self) -> String {
        use sha2::Digest;
        let mut h = sha2::Sha256::new();
        for part in [
            self.homeserver.as_str(),
            self.user_id.as_str(),
            self.device_id.as_str(),
            self.access_token.as_str(),
            self.refresh_token.as_deref().unwrap_or(""),
        ] {
            h.update((part.len() as u64).to_be_bytes());
            h.update(part.as_bytes());
        }
        hex::encode(h.finalize())
    }
}

/// True when the directory holds a session (i.e. `login` or `import` ran).
pub fn has_session(dir: &Path) -> bool {
    Session::path(dir).is_file()
}

/// Checkpoint the WAL and VACUUM every exported SQLite file so the export is
/// self-contained (no `-wal` sidecar) and as small as possible. Must run
/// while no SDK client holds the store open.
pub fn compact(dir: &Path) -> anyhow::Result<()> {
    for name in [STATE_DB, CRYPTO_DB] {
        let path = dir.join(name);
        if !path.is_file() {
            continue;
        }
        let conn = rusqlite::Connection::open(&path)?;
        conn.busy_timeout(std::time::Duration::from_secs(10))?;
        conn.execute_batch("PRAGMA wal_checkpoint(TRUNCATE); VACUUM;")
            .map_err(|e| anyhow::anyhow!("compacting {name}: {e}"))?;
    }
    Ok(())
}

/// Remove other users' cached devices and identities from the crypto store.
/// They are re-fetched with `/keys/query` on every run anyway (see
/// [`hygiene`]), and they are what makes the snapshot grow with room size:
/// a repository secret is capped at 48 KB. Our own rows stay.
pub fn slim(dir: &Path, own_user_id: &str) -> anyhow::Result<usize> {
    let path = dir.join(CRYPTO_DB);
    if !path.is_file() {
        return Ok(0);
    }
    let conn = rusqlite::Connection::open(&path)?;
    conn.busy_timeout(std::time::Duration::from_secs(10))?;
    let own = own_user_id.as_bytes();
    let mut removed = 0usize;
    for table in ["device", "identity"] {
        removed += conn
            .execute(&format!("DELETE FROM \"{table}\" WHERE user_id != ?1"), [own])
            .map_err(|e| anyhow::anyhow!("slimming {table}: {e}"))?;
    }
    Ok(removed)
}

/// Everything that should happen to a store before it is exported: drop
/// regenerable per-conversation state, drop other users' key cache,
/// checkpoint and vacuum. Idempotent.
pub fn prepare_export(dir: &Path) -> anyhow::Result<()> {
    let session = Session::load(dir)?;
    hygiene(dir)?;
    slim(dir, &session.user_id)?;
    compact(dir)
}

/// Tables of the SDK crypto store that hold *conversation* state rather than
/// *identity*: Olm sessions with other devices, our outbound Megolm sessions,
/// and the device-list tracking flags. See [`hygiene`].
const HYGIENE_TABLES: &[&str] = &["session", "outbound_group_session", "tracked_user"];

/// Drop per-conversation crypto state so that a run starting from a
/// snapshot never replays it.
///
/// Why this exists: a CI runner restores the same snapshot every time and
/// throws its changes away. If that snapshot contained an outbound Megolm
/// session at message index *n*, every run would encrypt at index *n* and
/// recipients would flag a replay. If it contained an Olm session whose
/// ratchet the recipient has already advanced past, the room-key share
/// would be undecryptable and the message unreadable for that device.
/// Deleting these rows forces the SDK to claim fresh one-time keys, build
/// fresh Olm sessions, re-query device lists and start a fresh Megolm
/// session for this run - the same work a first-ever send does.
///
/// The Olm *account* (device keys), cross-signing keys, and known devices
/// are left intact: that is the identity we want to keep.
pub fn hygiene(dir: &Path) -> anyhow::Result<usize> {
    let path = dir.join(CRYPTO_DB);
    if !path.is_file() {
        return Ok(0);
    }
    let conn = rusqlite::Connection::open(&path)?;
    conn.busy_timeout(std::time::Duration::from_secs(10))?;
    let mut removed = 0usize;
    for table in HYGIENE_TABLES {
        // A missing table means the SDK schema moved under us: fail loudly
        // rather than silently keep stale sessions.
        removed += conn
            .execute(&format!("DELETE FROM \"{table}\""), [])
            .map_err(|e| anyhow::anyhow!("crypto store hygiene on table {table}: {e}"))?;
    }
    Ok(removed)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn resolve_dir_precedence() {
        let flag = Path::new("/x/flag");
        assert_eq!(resolve_dir(Some(flag)).unwrap(), PathBuf::from("/x/flag"));
        // Env var and home are process-global; only check the flag path here
        // and that the fallback yields something under a home directory.
        let d = resolve_dir(None).unwrap();
        assert!(d.is_absolute());
    }

    #[test]
    fn session_round_trip_and_redaction() {
        let dir = tempfile::tempdir().unwrap();
        let s = Session {
            homeserver: "https://chat.example.org".into(),
            server_name: "example.org".into(),
            user_id: "@ci:example.org".into(),
            device_id: "ABCDEFGH".into(),
            access_token: "syt_secret".into(),
            refresh_token: None,
        };
        s.save(dir.path()).unwrap();
        let back = Session::load(dir.path()).unwrap();
        assert_eq!(back.access_token, "syt_secret");
        assert_eq!(back.identity_fingerprint(), s.identity_fingerprint());
        let dbg = format!("{back:?}");
        assert!(!dbg.contains("syt_secret"));
        assert!(dbg.contains("<redacted>"));

        let mut rotated = back.clone();
        rotated.access_token = "syt_other".into();
        assert_ne!(rotated.identity_fingerprint(), s.identity_fingerprint());

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = fs::metadata(Session::path(dir.path())).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode, 0o600);
            let dmode = fs::metadata(dir.path()).unwrap().permissions().mode() & 0o777;
            assert_eq!(dmode, 0o700);
        }
    }

    #[test]
    fn hygiene_clears_conversation_tables_only() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join(CRYPTO_DB);
        let conn = rusqlite::Connection::open(&path).unwrap();
        conn.execute_batch(
            r#"
            CREATE TABLE "kv" ("key" TEXT PRIMARY KEY NOT NULL, "value" BLOB NOT NULL);
            CREATE TABLE "session" ("session_id" BLOB PRIMARY KEY NOT NULL, "sender_key" BLOB NOT NULL, "data" BLOB NOT NULL);
            CREATE TABLE "outbound_group_session" ("room_id" BLOB PRIMARY KEY NOT NULL, "data" BLOB NOT NULL);
            CREATE TABLE "tracked_user" ("user_id" BLOB PRIMARY KEY NOT NULL, "data" BLOB NOT NULL);
            INSERT INTO kv VALUES ('account', x'01');
            INSERT INTO session VALUES (x'01', x'02', x'03');
            INSERT INTO session VALUES (x'04', x'05', x'06');
            INSERT INTO outbound_group_session VALUES (x'07', x'08');
            INSERT INTO tracked_user VALUES (x'09', x'0a');
            "#,
        )
        .unwrap();
        drop(conn);

        assert_eq!(hygiene(dir.path()).unwrap(), 4);
        let conn = rusqlite::Connection::open(&path).unwrap();
        let n: i64 = conn.query_row("SELECT count(*) FROM session", [], |r| r.get(0)).unwrap();
        assert_eq!(n, 0);
        let n: i64 = conn.query_row("SELECT count(*) FROM kv", [], |r| r.get(0)).unwrap();
        assert_eq!(n, 1, "identity rows must survive");

        // Missing store: nothing to do, not an error.
        let empty = tempfile::tempdir().unwrap();
        assert_eq!(hygiene(empty.path()).unwrap(), 0);
    }

    #[test]
    fn slim_keeps_only_own_rows() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join(CRYPTO_DB);
        let conn = rusqlite::Connection::open(&path).unwrap();
        conn.execute_batch(
            r#"
            CREATE TABLE "device" ("user_id" BLOB NOT NULL, "device_id" BLOB NOT NULL, "data" BLOB NOT NULL, PRIMARY KEY ("user_id", "device_id"));
            CREATE TABLE "identity" ("user_id" BLOB PRIMARY KEY NOT NULL, "data" BLOB NOT NULL);
            INSERT INTO device VALUES (CAST('@ci:example.org' AS BLOB), x'01', x'00');
            INSERT INTO device VALUES (CAST('@alice:example.org' AS BLOB), x'02', x'00');
            INSERT INTO device VALUES (CAST('@alice:example.org' AS BLOB), x'03', x'00');
            INSERT INTO identity VALUES (CAST('@ci:example.org' AS BLOB), x'00');
            INSERT INTO identity VALUES (CAST('@alice:example.org' AS BLOB), x'00');
            "#,
        )
        .unwrap();
        drop(conn);
        assert_eq!(slim(dir.path(), "@ci:example.org").unwrap(), 3);
        let conn = rusqlite::Connection::open(&path).unwrap();
        let n: i64 = conn.query_row("SELECT count(*) FROM device", [], |r| r.get(0)).unwrap();
        assert_eq!(n, 1);
        let n: i64 = conn.query_row("SELECT count(*) FROM identity", [], |r| r.get(0)).unwrap();
        assert_eq!(n, 1);
    }

    #[test]
    fn hygiene_fails_loudly_on_schema_drift() {
        let dir = tempfile::tempdir().unwrap();
        let conn = rusqlite::Connection::open(dir.path().join(CRYPTO_DB)).unwrap();
        conn.execute_batch(r#"CREATE TABLE "kv" ("key" TEXT PRIMARY KEY, "value" BLOB);"#).unwrap();
        drop(conn);
        let err = hygiene(dir.path()).unwrap_err().to_string();
        assert!(err.contains("session"), "{err}");
    }

    #[test]
    fn compact_truncates_wal() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join(STATE_DB);
        let conn = rusqlite::Connection::open(&path).unwrap();
        conn.execute_batch("PRAGMA journal_mode=WAL; CREATE TABLE t(x); INSERT INTO t VALUES (zeroblob(100000)); DELETE FROM t;").unwrap();
        drop(conn);
        let before = fs::metadata(&path).unwrap().len();
        compact(dir.path()).unwrap();
        let after = fs::metadata(&path).unwrap().len();
        assert!(after <= before, "{after} > {before}");
        let wal = fs::metadata(dir.path().join(format!("{STATE_DB}-wal"))).map(|m| m.len()).unwrap_or(0);
        assert_eq!(wal, 0);
    }
}
