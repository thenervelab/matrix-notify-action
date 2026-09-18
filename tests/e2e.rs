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

//! Live end-to-end test against a real homeserver. Compiled only with
//! `--features e2e`, and skipped unless `MATRIX_NOTIFY_E2E=1`.
//!
//! Environment:
//!   MATRIX_E2E_HOMESERVER  server name or URL (default hippius.com)
//!   MATRIX_E2E_USER        bot localpart or full id
//!   MATRIX_E2E_PASSWORD    bot password
//!   MATRIX_E2E_ROOM        alias or id the bot may join (default #ci:hippius.com)
//!   MATRIX_E2E_KEEP=1      keep the device instead of logging it out at the end
//!
//! Scenario: login into store A, export, import into store B (a "fresh
//! runner"), send from B, fetch the raw event from the server and assert it
//! is `m.room.encrypted` with no plaintext leak. Then import the *same*
//! snapshot into store C and send again: the second run must work without
//! any state written back, which is what hygiene() guarantees.

#![cfg(feature = "e2e")]

use std::time::Duration;

use matrix_notify::matrix::{self, Credentials, LoginOptions, Notifier, SendOptions};
use matrix_notify::message::Message;
use matrix_notify::state::{self, StateKey};
use matrix_notify::store::{self, Session};
use matrix_notify::target::RoomTarget;

fn env(name: &str) -> Option<String> {
    std::env::var(name).ok().filter(|v| !v.is_empty())
}

async fn raw_event(session: &Session, room_id: &str, event_id: &str) -> serde_json::Value {
    let url = format!(
        "{}/_matrix/client/v3/rooms/{}/event/{}",
        session.homeserver.trim_end_matches('/'),
        urlencoding(room_id),
        urlencoding(event_id)
    );
    let resp = reqwest::Client::new().get(url).bearer_auth(&session.access_token).send().await.unwrap();
    assert!(resp.status().is_success(), "GET event: {}", resp.status());
    resp.json().await.unwrap()
}

fn urlencoding(s: &str) -> String {
    url::form_urlencoded::byte_serialize(s.as_bytes()).collect()
}

async fn send_from_snapshot(
    blob: &str,
    key: &StateKey,
    room: &RoomTarget,
    text: &str,
) -> (Session, String, String) {
    let dir = tempfile::tempdir().unwrap();
    state::import(dir.path(), key, blob.as_bytes()).unwrap();
    let n = Notifier::open(dir.path(), false, Duration::from_secs(60)).await.unwrap();
    let report = n
        .send(
            room,
            Message::plain(text, true),
            &SendOptions {
                allow_unencrypted: false,
                strict_recipients: false,
                timeout: Duration::from_secs(60),
            },
        )
        .await
        .unwrap();
    assert!(report.encrypted, "room must be encrypted for this test to mean anything");
    let session = n.session().clone();
    n.close().await.unwrap();
    (session, report.room_id.to_string(), report.event_id)
}

#[tokio::test]
async fn login_export_import_send_is_encrypted_on_the_wire() {
    if env("MATRIX_NOTIFY_E2E").as_deref() != Some("1") {
        eprintln!("MATRIX_NOTIFY_E2E != 1: skipping live test");
        return;
    }
    let homeserver = env("MATRIX_E2E_HOMESERVER").unwrap_or_else(|| "hippius.com".into());
    let user = env("MATRIX_E2E_USER").expect("MATRIX_E2E_USER");
    let password = env("MATRIX_E2E_PASSWORD").expect("MATRIX_E2E_PASSWORD");
    let room =
        RoomTarget::parse(&env("MATRIX_E2E_ROOM").unwrap_or_else(|| "#ci:hippius.com".into())).unwrap();

    // 1. login into store A, join the room, snapshot.
    let a = tempfile::tempdir().unwrap();
    let report = matrix::login(
        a.path(),
        LoginOptions {
            homeserver,
            credentials: Credentials::Password { user, password },
            device_name: "matrix-notify (e2e test)".into(),
            reset_cross_signing: false,
            join: vec![room.clone()],
        },
    )
    .await
    .unwrap();
    eprintln!("login: {report:?}");
    store::prepare_export(a.path()).unwrap();
    let key = StateKey::generate().unwrap();
    let blob = state::export(a.path(), &key).unwrap();
    eprintln!("snapshot: {} bytes of base64", blob.len());
    assert!(blob.len() < 48 * 1024, "snapshot must fit a repository secret");

    // 2. "runner 1": import into B, send.
    let nonce =
        format!("matrix-notify e2e {}", std::time::SystemTime::UNIX_EPOCH.elapsed().unwrap().as_millis());
    let (session, room_id, event_id) = send_from_snapshot(&blob, &key, &room, &nonce).await;
    eprintln!("sent {event_id} to {room_id}");

    // 3. What the server stored must be ciphertext.
    let ev = raw_event(&session, &room_id, &event_id).await;
    assert_eq!(ev["type"], "m.room.encrypted", "{ev}");
    assert_eq!(ev["content"]["algorithm"], "m.megolm.v1.aes-sha2", "{ev}");
    assert!(!ev.to_string().contains(&nonce), "plaintext leaked to the server: {ev}");
    assert!(ev["content"]["body"].is_null(), "an encrypted event must not carry a body: {ev}");

    // 4. "runner 2": same snapshot, no write-back, must still work.
    let nonce2 = format!("{nonce} (second run)");
    let (_, _, event_id2) = send_from_snapshot(&blob, &key, &room, &nonce2).await;
    assert_ne!(event_id, event_id2);
    let ev2 = raw_event(&session, &room_id, &event_id2).await;
    assert_eq!(ev2["type"], "m.room.encrypted");
    assert_ne!(
        ev["content"]["session_id"], ev2["content"]["session_id"],
        "each run must use a fresh Megolm session (no replayed message index)"
    );

    // 5. Tidy: remove the test device unless asked to keep it.
    if env("MATRIX_E2E_KEEP").as_deref() != Some("1") {
        let n = Notifier::open(a.path(), true, Duration::from_secs(30)).await.unwrap();
        n.logout().await.unwrap();
        eprintln!("device logged out");
    }
}
