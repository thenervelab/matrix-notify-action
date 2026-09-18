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

//! A store created by the real SDK survives prepare_export -> export ->
//! import and is reopened by the SDK with the same identity. No network.

use std::path::Path;
use std::time::Duration;

use matrix_notify::state::{self, StateKey};
use matrix_notify::store::{self, Session};

/// GitHub caps a repository secret at 48 KB.
const SECRET_LIMIT: usize = 48 * 1024;

async fn open_sdk(dir: &Path) -> matrix_sdk::Client {
    let client = matrix_sdk::Client::builder()
        .homeserver_url("http://127.0.0.1:1")
        .sqlite_store(dir, None)
        .request_config(
            matrix_sdk::config::RequestConfig::new().timeout(Duration::from_millis(200)).disable_retry(),
        )
        .build()
        .await
        .unwrap();
    let session = matrix_sdk::authentication::matrix::MatrixSession {
        meta: matrix_sdk::SessionMeta {
            user_id: "@ci:example.org".parse().unwrap(),
            device_id: "ABCDEFGH".into(),
        },
        tokens: matrix_sdk::SessionTokens { access_token: "syt_test".into(), refresh_token: None },
    };
    client.restore_session(session).await.unwrap();
    client
}

async fn settle() {
    // Let the SDK's background tasks release their SQLite handles.
    tokio::time::sleep(Duration::from_millis(300)).await;
}

#[tokio::test]
async fn sdk_store_round_trips_and_fits_a_secret() {
    let src = tempfile::tempdir().unwrap();
    let client = open_sdk(src.path()).await;
    let own_ed25519 = client
        .encryption()
        .get_own_device()
        .await
        .unwrap()
        .expect("own device")
        .ed25519_key()
        .expect("ed25519")
        .to_base64();
    drop(client);
    settle().await;

    Session {
        homeserver: "http://127.0.0.1:1".into(),
        server_name: "example.org".into(),
        user_id: "@ci:example.org".into(),
        device_id: "ABCDEFGH".into(),
        access_token: "syt_test".into(),
        refresh_token: None,
    }
    .save(src.path())
    .unwrap();

    store::prepare_export(src.path()).unwrap();
    let key = StateKey::generate().unwrap();
    let blob = state::export(src.path(), &key).unwrap();
    println!("export: {} bytes of base64", blob.len());
    assert!(blob.len() < SECRET_LIMIT, "{} >= {SECRET_LIMIT}", blob.len());

    let dst = tempfile::tempdir().unwrap();
    let written = state::import(dst.path(), &key, blob.as_bytes()).unwrap();
    assert_eq!(written.len(), 3, "{written:?}");
    assert!(!dst.path().join(format!("{}-wal", store::CRYPTO_DB)).exists());

    // Hygiene must not break the store for the SDK.
    store::hygiene(dst.path()).unwrap();

    let client = open_sdk(dst.path()).await;
    let reopened = client.encryption().get_own_device().await.unwrap().expect("own device after import");
    assert_eq!(
        reopened.ed25519_key().unwrap().to_base64(),
        own_ed25519,
        "device identity must survive the round trip"
    );
    drop(client);
    settle().await;

    let s = Session::load(dst.path()).unwrap();
    assert_eq!(s.device_id, "ABCDEFGH");
}
