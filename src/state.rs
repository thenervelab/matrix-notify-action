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

//! Encrypted state archive: the bot's device identity as a single blob that
//! fits in a CI secret.
//!
//! Layout (all big-endian, no padding):
//!
//! ```text
//! +--------+---------+---------+-------------------+-----------------------+
//! | "MNS1" | salt 32 | nonce 24| ciphertext (n)    | Poly1305 tag (16)     |
//! +--------+---------+---------+-------------------+-----------------------+
//! ```
//!
//! * key material: the caller's 32-byte key, run through
//!   HKDF-SHA256(salt, info = `INFO`) so the same key can protect many
//!   archives without nonce reuse concerns;
//! * cipher: XChaCha20-Poly1305, 24-byte random nonce;
//! * AAD: the 60-byte header (magic + salt + nonce), so a tampered header
//!   fails authentication like a tampered body;
//! * plaintext: gzip-compressed POSIX tar of the store files listed by
//!   [`crate::store::EXPORTED_FILES`], with fixed metadata so the same store
//!   contents produce the same tar.
//!
//! Anything that fails authentication is rejected before any byte reaches
//! the tar reader.

use std::io::{Read, Write};
use std::path::{Component, Path, PathBuf};

use base64::Engine;
use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{Key, XChaCha20Poly1305, XNonce};
use flate2::read::GzDecoder;
use flate2::write::GzEncoder;
use flate2::Compression;
use hkdf::Hkdf;
use sha2::Sha256;
use zeroize::{Zeroize, Zeroizing};

const MAGIC: &[u8; 4] = b"MNS1";
const SALT_LEN: usize = 32;
const NONCE_LEN: usize = 24;
const TAG_LEN: usize = 16;
const HEADER_LEN: usize = MAGIC.len() + SALT_LEN + NONCE_LEN;
const INFO: &[u8] = b"matrix-notify/state/v1";

/// Hard cap on the decompressed archive, well above any real store
/// (a fresh store is well under a megabyte) and low enough that a hostile
/// blob cannot exhaust memory.
const MAX_PLAINTEXT: u64 = 256 * 1024 * 1024;

#[derive(Debug, thiserror::Error)]
pub enum StateError {
    #[error("state key must be 64 hex characters (32 bytes); got {0} characters")]
    KeyLength(usize),
    #[error("state key is not valid hex")]
    KeyHex,
    #[error("input is not a matrix-notify state archive (bad magic)")]
    BadMagic,
    #[error("state archive is truncated")]
    Truncated,
    #[error("state archive failed authentication: wrong key or tampered data")]
    Authentication,
    #[error("state archive is not valid base64: {0}")]
    Base64(#[from] base64::DecodeError),
    #[error("archive entry {0:?} escapes the store directory")]
    UnsafePath(PathBuf),
    #[error("archive entry {0:?} is not a regular file")]
    NotAFile(PathBuf),
    #[error("archive is larger than the {MAX_PLAINTEXT}-byte limit")]
    TooLarge,
    #[error(transparent)]
    Io(#[from] std::io::Error),
}

/// A 32-byte symmetric key, zeroised on drop.
#[derive(Clone, Zeroize)]
#[zeroize(drop)]
pub struct StateKey([u8; 32]);

impl StateKey {
    /// Parse a key from its 64-character hex form (surrounding whitespace is
    /// tolerated because secrets are often pasted with a trailing newline).
    pub fn from_hex(s: &str) -> Result<Self, StateError> {
        let s = s.trim();
        if s.len() != 64 {
            return Err(StateError::KeyLength(s.len()));
        }
        let mut out = [0u8; 32];
        hex::decode_to_slice(s, &mut out).map_err(|_| StateError::KeyHex)?;
        Ok(Self(out))
    }

    /// Generate a fresh random key from the OS CSPRNG.
    pub fn generate() -> Result<Self, StateError> {
        let mut out = [0u8; 32];
        getrandom::getrandom(&mut out).map_err(|e| std::io::Error::other(e.to_string()))?;
        Ok(Self(out))
    }

    pub fn to_hex(&self) -> Zeroizing<String> {
        Zeroizing::new(hex::encode(self.0))
    }

    fn derive(&self, salt: &[u8]) -> Zeroizing<[u8; 32]> {
        let hk = Hkdf::<Sha256>::new(Some(salt), &self.0);
        let mut okm = Zeroizing::new([0u8; 32]);
        hk.expand(INFO, okm.as_mut()).expect("32 bytes is a valid HKDF-SHA256 output length");
        okm
    }
}

impl std::fmt::Debug for StateKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("StateKey(..)")
    }
}

/// Encrypt `plaintext` into the archive format. Public for tests; callers
/// normally use [`export`].
pub fn seal(key: &StateKey, plaintext: &[u8]) -> Result<Vec<u8>, StateError> {
    let mut salt = [0u8; SALT_LEN];
    let mut nonce = [0u8; NONCE_LEN];
    getrandom::getrandom(&mut salt).map_err(|e| std::io::Error::other(e.to_string()))?;
    getrandom::getrandom(&mut nonce).map_err(|e| std::io::Error::other(e.to_string()))?;

    let mut header = Vec::with_capacity(HEADER_LEN);
    header.extend_from_slice(MAGIC);
    header.extend_from_slice(&salt);
    header.extend_from_slice(&nonce);

    let derived = key.derive(&salt);
    let cipher = XChaCha20Poly1305::new(&Key::from(*derived));
    let ct = cipher
        .encrypt(&XNonce::from(nonce), Payload { msg: plaintext, aad: &header })
        .map_err(|_| StateError::Authentication)?;

    let mut out = header;
    out.extend_from_slice(&ct);
    Ok(out)
}

/// Authenticate and decrypt an archive produced by [`seal`].
pub fn open(key: &StateKey, blob: &[u8]) -> Result<Zeroizing<Vec<u8>>, StateError> {
    if blob.len() < MAGIC.len() {
        return Err(StateError::Truncated);
    }
    if &blob[..MAGIC.len()] != MAGIC {
        return Err(StateError::BadMagic);
    }
    if blob.len() < HEADER_LEN + TAG_LEN {
        return Err(StateError::Truncated);
    }
    let (header, ct) = blob.split_at(HEADER_LEN);
    let salt = &header[MAGIC.len()..MAGIC.len() + SALT_LEN];
    let nonce = &header[MAGIC.len() + SALT_LEN..];

    let nonce: [u8; NONCE_LEN] = nonce.try_into().expect("header slice has nonce length");
    let derived = key.derive(salt);
    let cipher = XChaCha20Poly1305::new(&Key::from(*derived));
    cipher
        .decrypt(&XNonce::from(nonce), Payload { msg: ct, aad: header })
        .map(Zeroizing::new)
        .map_err(|_| StateError::Authentication)
}

/// Build the deterministic gzip'd tar of `files` (relative names) found in
/// `dir`. Missing files are skipped: a store that never had an event cache
/// still exports.
pub fn pack(dir: &Path, files: &[&str]) -> Result<Vec<u8>, StateError> {
    let gz = GzEncoder::new(Vec::new(), Compression::best());
    let mut tar = tar::Builder::new(gz);
    tar.mode(tar::HeaderMode::Deterministic);
    for name in files {
        let path = dir.join(name);
        let Ok(mut f) = std::fs::File::open(&path) else { continue };
        let meta = f.metadata()?;
        if !meta.is_file() {
            continue;
        }
        let mut header = tar::Header::new_gnu();
        header.set_size(meta.len());
        header.set_mode(0o600);
        header.set_mtime(0);
        header.set_uid(0);
        header.set_gid(0);
        header.set_entry_type(tar::EntryType::Regular);
        tar.append_data(&mut header, name, &mut f)?;
    }
    let gz = tar.into_inner()?;
    Ok(gz.finish()?)
}

/// Inverse of [`pack`]: write the archive's regular files into `dir`
/// (created with mode 0700 if missing). Rejects anything that is not a
/// plain relative file name so a hostile archive cannot write outside `dir`.
pub fn unpack(dir: &Path, tgz: &[u8]) -> Result<Vec<String>, StateError> {
    crate::store::ensure_private_dir(dir)?;
    let gz = GzDecoder::new(tgz);
    let mut archive = tar::Archive::new(gz.take(MAX_PLAINTEXT));
    let mut written = Vec::new();
    for entry in archive.entries()? {
        let mut entry = entry?;
        let path = entry.path()?.into_owned();
        if entry.header().entry_type() != tar::EntryType::Regular {
            return Err(StateError::NotAFile(path));
        }
        let mut comps = path.components();
        let name = match (comps.next(), comps.next()) {
            (Some(Component::Normal(n)), None) => n.to_owned(),
            _ => return Err(StateError::UnsafePath(path)),
        };
        let dest = dir.join(&name);
        let tmp = dir.join(format!(".{}.tmp", name.to_string_lossy()));
        {
            let mut f = crate::store::create_private_file(&tmp)?;
            std::io::copy(&mut entry, &mut f)?;
            f.sync_all()?;
        }
        std::fs::rename(&tmp, &dest)?;
        written.push(name.to_string_lossy().into_owned());
    }
    if archive.into_inner().limit() == 0 {
        return Err(StateError::TooLarge);
    }
    Ok(written)
}

/// Export `dir` as a base64 string ready to paste into a secret.
pub fn export(dir: &Path, key: &StateKey) -> Result<String, StateError> {
    let tgz = Zeroizing::new(pack(dir, crate::store::EXPORTED_FILES)?);
    let blob = seal(key, &tgz)?;
    Ok(base64::engine::general_purpose::STANDARD.encode(blob))
}

/// Import into `dir` from either base64 text (whitespace tolerated) or the
/// raw binary archive.
pub fn import(dir: &Path, key: &StateKey, input: &[u8]) -> Result<Vec<String>, StateError> {
    let blob = if input.starts_with(MAGIC) {
        input.to_vec()
    } else {
        let compact: Vec<u8> = input.iter().copied().filter(|b| !b.is_ascii_whitespace()).collect();
        base64::engine::general_purpose::STANDARD.decode(compact)?
    };
    let tgz = open(key, &blob)?;
    unpack(dir, &tgz)
}

/// Convenience for the CLI: write `s` to `out` (a path or `-` for stdout)
/// followed by a newline.
pub fn write_output(out: &str, s: &str) -> std::io::Result<()> {
    if out == "-" {
        let mut so = std::io::stdout().lock();
        so.write_all(s.as_bytes())?;
        so.write_all(b"\n")?;
        so.flush()
    } else {
        let mut f = crate::store::create_private_file(Path::new(out))?;
        f.write_all(s.as_bytes())?;
        f.write_all(b"\n")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key() -> StateKey {
        StateKey::from_hex(&"ab".repeat(32)).unwrap()
    }

    #[test]
    fn key_parsing() {
        assert!(StateKey::from_hex("abc").is_err());
        assert!(StateKey::from_hex(&"zz".repeat(32)).is_err());
        let k = StateKey::from_hex(&format!("  {}\n", "01".repeat(32))).unwrap();
        assert_eq!(k.to_hex().as_str(), "01".repeat(32));
        let g = StateKey::generate().unwrap();
        assert_ne!(g.to_hex().as_str(), k.to_hex().as_str());
    }

    #[test]
    fn seal_open_round_trip() {
        let blob = seal(&key(), b"hello").unwrap();
        assert_eq!(&blob[..4], MAGIC);
        assert_eq!(blob.len(), HEADER_LEN + 5 + TAG_LEN);
        assert_eq!(open(&key(), &blob).unwrap().as_slice(), b"hello");
    }

    #[test]
    fn tamper_anywhere_is_rejected() {
        let blob = seal(&key(), b"hello world").unwrap();
        for i in 0..blob.len() {
            let mut t = blob.clone();
            t[i] ^= 0x01;
            let err = open(&key(), &t).unwrap_err();
            if i < MAGIC.len() {
                assert!(matches!(err, StateError::BadMagic), "byte {i}: {err}");
            } else {
                assert!(matches!(err, StateError::Authentication), "byte {i}: {err}");
            }
        }
        let mut short = blob.clone();
        short.truncate(HEADER_LEN + 3);
        assert!(matches!(open(&key(), &short).unwrap_err(), StateError::Truncated));
    }

    #[test]
    fn wrong_key_is_rejected() {
        let blob = seal(&key(), b"hello").unwrap();
        let other = StateKey::from_hex(&"cd".repeat(32)).unwrap();
        assert!(matches!(open(&other, &blob).unwrap_err(), StateError::Authentication));
    }

    #[test]
    fn export_import_round_trip() {
        let src = tempfile::tempdir().unwrap();
        std::fs::write(src.path().join("session.json"), b"{\"a\":1}").unwrap();
        std::fs::write(src.path().join("matrix-sdk-crypto.sqlite3"), vec![7u8; 10_000]).unwrap();
        std::fs::write(src.path().join("matrix-sdk-state.sqlite3"), vec![0u8; 50_000]).unwrap();
        std::fs::write(src.path().join("matrix-sdk-event-cache.sqlite3"), b"not exported").unwrap();

        let b64 = export(src.path(), &key()).unwrap();
        assert!(b64.len() < 8_000, "zero pages must compress: {}", b64.len());

        let dst = tempfile::tempdir().unwrap();
        let written = import(dst.path(), &key(), format!("{b64}\n").as_bytes()).unwrap();
        assert_eq!(written, ["session.json", "matrix-sdk-state.sqlite3", "matrix-sdk-crypto.sqlite3"]);
        assert_eq!(std::fs::read(dst.path().join("session.json")).unwrap(), b"{\"a\":1}");
        assert_eq!(std::fs::read(dst.path().join("matrix-sdk-crypto.sqlite3")).unwrap(), vec![7u8; 10_000]);
        assert!(!dst.path().join("matrix-sdk-event-cache.sqlite3").exists());

        // Raw binary input is accepted too.
        let raw = base64::engine::general_purpose::STANDARD.decode(&b64).unwrap();
        let dst2 = tempfile::tempdir().unwrap();
        assert_eq!(import(dst2.path(), &key(), &raw).unwrap().len(), 3);

        // A flipped byte inside the base64 payload is a clean error, not a partial write.
        let mut bad = raw.clone();
        let last = bad.len() - 1;
        bad[last] ^= 0x80;
        let dst3 = tempfile::tempdir().unwrap();
        assert!(matches!(import(dst3.path(), &key(), &bad).unwrap_err(), StateError::Authentication));
        assert!(std::fs::read_dir(dst3.path()).unwrap().next().is_none());
    }

    #[test]
    fn pack_is_deterministic() {
        let src = tempfile::tempdir().unwrap();
        std::fs::write(src.path().join("session.json"), b"x").unwrap();
        let a = pack(src.path(), &["session.json"]).unwrap();
        std::thread::sleep(std::time::Duration::from_millis(20));
        std::fs::write(src.path().join("session.json"), b"x").unwrap();
        let b = pack(src.path(), &["session.json"]).unwrap();
        assert_eq!(a, b);
    }

    #[test]
    fn unpack_rejects_path_escape() {
        let mut tar = tar::Builder::new(GzEncoder::new(Vec::new(), Compression::fast()));
        let data = b"evil";
        let mut h = tar::Header::new_gnu();
        h.set_size(data.len() as u64);
        h.set_mode(0o644);
        h.set_cksum();
        tar.append_data(&mut h, "nested/escape", &data[..]).unwrap();
        let tgz = tar.into_inner().unwrap().finish().unwrap();
        let dst = tempfile::tempdir().unwrap();
        assert!(matches!(unpack(dst.path(), &tgz).unwrap_err(), StateError::UnsafePath(_)));

        let mut tar = tar::Builder::new(GzEncoder::new(Vec::new(), Compression::fast()));
        let mut h = tar::Header::new_gnu();
        h.set_size(0);
        h.set_entry_type(tar::EntryType::Symlink);
        h.set_cksum();
        tar.append_link(&mut h, "link", "/etc/passwd").unwrap();
        let tgz = tar.into_inner().unwrap().finish().unwrap();
        assert!(matches!(unpack(dst.path(), &tgz).unwrap_err(), StateError::NotAFile(_)));
    }
}
