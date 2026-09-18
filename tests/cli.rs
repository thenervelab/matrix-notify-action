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

//! Black-box tests of the binary: argument validation, state commands, and
//! the error paths a CI job hits when secrets are missing. No network.

use assert_cmd::Command;
use predicates::prelude::*;

fn bin() -> Command {
    let mut c = Command::cargo_bin("matrix-notify").unwrap();
    c.env_remove("MATRIX_NOTIFY_HOME").env_remove("MATRIX_STATE_KEY").env_remove("MATRIX_ROOM");
    c
}

fn fake_store(dir: &std::path::Path) {
    matrix_notify::store::Session {
        homeserver: "http://127.0.0.1:1".into(),
        server_name: "example.org".into(),
        user_id: "@ci:example.org".into(),
        device_id: "ABCDEFGH".into(),
        access_token: "syt_fake".into(),
        refresh_token: None,
    }
    .save(dir)
    .unwrap();
    std::fs::write(dir.join(matrix_notify::store::STATE_DB), b"").unwrap();
    // Minimal crypto-store schema so prepare_export's hygiene/slim find their tables.
    let conn = rusqlite::Connection::open(dir.join(matrix_notify::store::CRYPTO_DB)).unwrap();
    conn.execute_batch(
        r#"
        CREATE TABLE "session" ("session_id" BLOB PRIMARY KEY, "sender_key" BLOB, "data" BLOB);
        CREATE TABLE "outbound_group_session" ("room_id" BLOB PRIMARY KEY, "data" BLOB);
        CREATE TABLE "tracked_user" ("user_id" BLOB PRIMARY KEY, "data" BLOB);
        CREATE TABLE "device" ("user_id" BLOB, "device_id" BLOB, "data" BLOB, PRIMARY KEY ("user_id", "device_id"));
        CREATE TABLE "identity" ("user_id" BLOB PRIMARY KEY, "data" BLOB);
        "#,
    )
    .unwrap();
}

#[test]
fn help_and_version() {
    bin().arg("--version").assert().success().stdout(predicate::str::starts_with("matrix-notify "));
    bin()
        .arg("--help")
        .assert()
        .success()
        .stdout(predicate::str::contains("login").and(predicate::str::contains("send")));
}

#[test]
fn keygen_is_64_hex() {
    let out = bin().args(["state", "keygen"]).assert().success().get_output().stdout.clone();
    let s = String::from_utf8(out).unwrap();
    assert_eq!(s.trim().len(), 64);
    assert!(s.trim().chars().all(|c| c.is_ascii_hexdigit()));
}

#[test]
fn state_export_import_via_cli() {
    let src = tempfile::tempdir().unwrap();
    fake_store(src.path());
    let key = "0f".repeat(32);

    bin()
        .args(["--store", src.path().to_str().unwrap(), "state", "export", "--key", "abc"])
        .assert()
        .failure()
        .stderr(predicate::str::contains("64 hex characters"));

    let blob = bin()
        .args(["--store", src.path().to_str().unwrap(), "state", "export", "--key", &key])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let blob = String::from_utf8(blob).unwrap();
    assert!(!blob.contains("syt_fake"), "export must be ciphertext");

    let fp = bin()
        .args(["--store", src.path().to_str().unwrap(), "state", "fingerprint"])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();

    let dst = tempfile::tempdir().unwrap();
    bin()
        .args(["--store", dst.path().to_str().unwrap(), "state", "import", "--key", &key])
        .write_stdin(blob.clone())
        .assert()
        .success()
        .stderr(predicate::str::contains("imported 3 file(s)"));
    assert!(dst.path().join("session.json").exists());
    let fp2 = bin()
        .args(["--store", dst.path().to_str().unwrap(), "state", "fingerprint"])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    assert_eq!(fp, fp2);

    // Wrong key: clean error, nothing written.
    let dst2 = tempfile::tempdir().unwrap();
    bin()
        .env("MATRIX_STATE_KEY", "ee".repeat(32))
        .args(["--store", dst2.path().to_str().unwrap(), "state", "import"])
        .write_stdin(blob)
        .assert()
        .failure()
        .stderr(predicate::str::contains("wrong key or tampered"));
    assert!(!dst2.path().join("session.json").exists());

    // Empty secret: explicit message.
    bin()
        .args(["--store", dst2.path().to_str().unwrap(), "state", "import", "--key", &key])
        .write_stdin("\n")
        .assert()
        .failure()
        .stderr(predicate::str::contains("empty state input"));
}

#[test]
fn send_without_state_is_a_clear_error() {
    let dir = tempfile::tempdir().unwrap();
    bin()
        .args([
            "--store",
            dir.path().to_str().unwrap(),
            "send",
            "--room",
            "#ci:example.org",
            "--message",
            "hi",
        ])
        .assert()
        .failure()
        .stderr(predicate::str::contains("no session in"));
}

#[test]
fn send_argument_validation() {
    let dir = tempfile::tempdir().unwrap();
    let store = dir.path().to_str().unwrap();
    bin()
        .args(["--store", store, "send", "--room", "nonsense", "--message", "hi"])
        .assert()
        .failure()
        .stderr(predicate::str::contains("not a room alias"));
    bin()
        .args(["--store", store, "send", "--room", "#ci:example.org", "--message", "   "])
        .assert()
        .failure()
        .stderr(predicate::str::contains("empty message"));
    bin()
        .args(["--store", store, "send", "--room", "#ci:example.org", "--format", "github-run"])
        .assert()
        .failure()
        .stderr(predicate::str::contains("--status"));
    bin()
        .env_remove("GITHUB_REPOSITORY")
        .env_remove("GITHUB_RUN_ID")
        .args([
            "--store",
            store,
            "send",
            "--room",
            "#ci:example.org",
            "--format",
            "github-run",
            "--status",
            "success",
        ])
        .assert()
        .failure()
        .stderr(predicate::str::contains("GITHUB_REPOSITORY"));
    bin().args(["--store", store, "send", "--room", "#ci:example.org"]).assert().failure();
}

#[tokio::test]
async fn github_secret_via_cli() {
    use base64::Engine;
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    let server = MockServer::start().await;
    let sk = crypto_box::SecretKey::generate(&mut crypto_box::aead::OsRng);
    let pk = base64::engine::general_purpose::STANDARD.encode(sk.public_key().as_bytes());
    Mock::given(method("GET"))
        .and(path("/repos/acme/widgets/actions/secrets/public-key"))
        .respond_with(
            ResponseTemplate::new(200).set_body_json(serde_json::json!({ "key_id": "k1", "key": pk })),
        )
        .expect(1)
        .mount(&server)
        .await;
    Mock::given(method("PUT"))
        .and(path("/repos/acme/widgets/actions/secrets/MATRIX_STATE"))
        .respond_with(ResponseTemplate::new(204))
        .expect(1)
        .mount(&server)
        .await;

    let uri = server.uri();
    tokio::task::spawn_blocking(move || {
        bin()
            .env("GH_TOKEN", "ghp_test")
            .args(["github-secret", "--repo", "acme/widgets", "--api-url", &uri])
            .write_stdin("bmV3\n")
            .assert()
            .success()
            .stderr(predicate::str::contains("secret MATRIX_STATE updated"));

        // Without a token: fail before any request.
        bin()
            .env_remove("GH_TOKEN")
            .args(["github-secret", "--repo", "acme/widgets", "--api-url", "http://127.0.0.1:1"])
            .write_stdin("x")
            .assert()
            .failure()
            .stderr(predicate::str::contains("GH_TOKEN is not set"));
    })
    .await
    .unwrap();

    let put =
        server.received_requests().await.unwrap().into_iter().find(|r| r.method.as_str() == "PUT").unwrap();
    let body: serde_json::Value = serde_json::from_slice(&put.body).unwrap();
    let sealed =
        base64::engine::general_purpose::STANDARD.decode(body["encrypted_value"].as_str().unwrap()).unwrap();
    assert_eq!(sk.unseal(&sealed).unwrap(), b"bmV3");
}

#[test]
fn login_requires_a_credential_source() {
    let dir = tempfile::tempdir().unwrap();
    bin()
        .args(["--store", dir.path().to_str().unwrap(), "login", "--user", "ci"])
        .assert()
        .failure()
        .stderr(predicate::str::contains("--password-stdin"));
    fake_store(dir.path());
    bin()
        .args(["--store", dir.path().to_str().unwrap(), "login", "--user", "ci", "--password-stdin"])
        .write_stdin("pw\n")
        .assert()
        .failure()
        .stderr(predicate::str::contains("already holds a session"));
}
