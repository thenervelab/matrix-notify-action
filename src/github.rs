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

//! Update a GitHub Actions repository secret.
//!
//! GitHub expects the value sealed with libsodium `crypto_box_seal` against
//! the repository's public key (`GET .../actions/secrets/public-key`), then
//! `PUT .../actions/secrets/{name}` with the ciphertext and the key id.
//! Requires a token with `secrets: write` (a fine-grained PAT with
//! "Secrets: read and write", or a GitHub App token); the default
//! `GITHUB_TOKEN` cannot write secrets.

use base64::Engine;
use crypto_box::aead::OsRng;
use crypto_box::PublicKey;
use serde::Deserialize;

const B64: base64::engine::GeneralPurpose = base64::engine::general_purpose::STANDARD;

#[derive(Debug, thiserror::Error)]
pub enum GitHubError {
    #[error("GitHub API {method} {path} returned {status}: {body}")]
    Status { method: &'static str, path: String, status: u16, body: String },
    #[error("repository public key is not a 32-byte base64 value")]
    PublicKey,
    #[error("repository must be `owner/name`, got {0:?}")]
    Repository(String),
    #[error(transparent)]
    Http(#[from] reqwest::Error),
}

#[derive(Debug, Deserialize)]
struct PublicKeyResponse {
    key_id: String,
    key: String,
}

/// Seal `plaintext` for `repo_public_key` (raw 32 bytes). Returns base64 of
/// the 48 + n byte sealed box, as the API wants it.
pub fn seal_for_github(repo_public_key: &[u8], plaintext: &[u8]) -> Result<String, GitHubError> {
    let pk: [u8; 32] = repo_public_key.try_into().map_err(|_| GitHubError::PublicKey)?;
    let pk = PublicKey::from(pk);
    let sealed = pk.seal(&mut OsRng, plaintext).map_err(|_| GitHubError::PublicKey)?;
    Ok(B64.encode(sealed))
}

pub struct SecretsClient {
    http: reqwest::Client,
    api_url: String,
    token: String,
    owner: String,
    repo: String,
}

impl SecretsClient {
    /// `api_url` is normally `https://api.github.com` (`$GITHUB_API_URL` on a
    /// runner); `repository` is `owner/name`.
    pub fn new(api_url: &str, repository: &str, token: &str) -> Result<Self, GitHubError> {
        let (owner, repo) = repository
            .split_once('/')
            .filter(|(o, r)| !o.is_empty() && !r.is_empty() && !r.contains('/'))
            .ok_or_else(|| GitHubError::Repository(repository.to_owned()))?;
        let http = reqwest::Client::builder()
            .user_agent(concat!("matrix-notify/", env!("CARGO_PKG_VERSION")))
            .build()?;
        Ok(Self {
            http,
            api_url: api_url.trim_end_matches('/').to_owned(),
            token: token.to_owned(),
            owner: owner.to_owned(),
            repo: repo.to_owned(),
        })
    }

    fn url(&self, tail: &str) -> String {
        format!("{}/repos/{}/{}/actions/secrets/{tail}", self.api_url, self.owner, self.repo)
    }

    async fn check(
        method: &'static str,
        path: String,
        resp: reqwest::Response,
    ) -> Result<reqwest::Response, GitHubError> {
        let status = resp.status();
        if status.is_success() {
            return Ok(resp);
        }
        let body = resp.text().await.unwrap_or_default();
        Err(GitHubError::Status {
            method,
            path,
            status: status.as_u16(),
            body: body.chars().take(300).collect(),
        })
    }

    async fn public_key(&self) -> Result<(String, Vec<u8>), GitHubError> {
        let url = self.url("public-key");
        let resp = self
            .http
            .get(&url)
            .bearer_auth(&self.token)
            .header("Accept", "application/vnd.github+json")
            .header("X-GitHub-Api-Version", "2022-11-28")
            .send()
            .await?;
        let resp = Self::check("GET", url, resp).await?;
        let pk: PublicKeyResponse = resp.json().await?;
        let key = B64.decode(pk.key.trim()).map_err(|_| GitHubError::PublicKey)?;
        if key.len() != 32 {
            return Err(GitHubError::PublicKey);
        }
        Ok((pk.key_id, key))
    }

    /// Create or update `name` with `value`.
    pub async fn put_secret(&self, name: &str, value: &str) -> Result<(), GitHubError> {
        let (key_id, key) = self.public_key().await?;
        let encrypted_value = seal_for_github(&key, value.as_bytes())?;
        let url = self.url(name);
        let resp = self
            .http
            .put(&url)
            .bearer_auth(&self.token)
            .header("Accept", "application/vnd.github+json")
            .header("X-GitHub-Api-Version", "2022-11-28")
            .json(&serde_json::json!({ "encrypted_value": encrypted_value, "key_id": key_id }))
            .send()
            .await?;
        Self::check("PUT", url, resp).await?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crypto_box::SecretKey;
    use wiremock::matchers::{body_partial_json, header, method, path};
    use wiremock::{Mock, MockServer, Request, ResponseTemplate};

    #[test]
    fn seal_round_trips_with_libsodium_layout() {
        let sk = SecretKey::generate(&mut OsRng);
        let b64 = seal_for_github(sk.public_key().as_bytes(), b"payload").unwrap();
        let sealed = B64.decode(b64).unwrap();
        // ephemeral pk (32) + tag (16) + plaintext
        assert_eq!(sealed.len(), 32 + 16 + 7);
        assert_eq!(sk.unseal(&sealed).unwrap(), b"payload");
        assert!(seal_for_github(&[0u8; 31], b"x").is_err());
    }

    #[test]
    fn repository_validation() {
        assert!(SecretsClient::new("https://api.github.com", "owner", "t").is_err());
        assert!(SecretsClient::new("https://api.github.com", "/name", "t").is_err());
        assert!(SecretsClient::new("https://api.github.com", "a/b/c", "t").is_err());
        assert!(SecretsClient::new("https://api.github.com", "a/b", "t").is_ok());
    }

    #[tokio::test]
    async fn put_secret_fetches_key_then_puts_sealed_value() {
        let server = MockServer::start().await;
        let sk = SecretKey::generate(&mut OsRng);
        let pk_b64 = B64.encode(sk.public_key().as_bytes());

        Mock::given(method("GET"))
            .and(path("/repos/acme/widgets/actions/secrets/public-key"))
            .and(header("authorization", "Bearer ghp_test"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_json(serde_json::json!({ "key_id": "568250167242549743", "key": pk_b64 })),
            )
            .expect(1)
            .mount(&server)
            .await;
        Mock::given(method("PUT"))
            .and(path("/repos/acme/widgets/actions/secrets/MATRIX_STATE"))
            .and(header("authorization", "Bearer ghp_test"))
            .and(body_partial_json(serde_json::json!({ "key_id": "568250167242549743" })))
            .respond_with(ResponseTemplate::new(201))
            .expect(1)
            .mount(&server)
            .await;

        let c = SecretsClient::new(&format!("{}/", server.uri()), "acme/widgets", "ghp_test").unwrap();
        c.put_secret("MATRIX_STATE", "bmV3LXN0YXRl").await.unwrap();

        let reqs: Vec<Request> = server.received_requests().await.unwrap();
        let put = reqs.iter().find(|r| r.method.as_str() == "PUT").unwrap();
        let body: serde_json::Value = serde_json::from_slice(&put.body).unwrap();
        let sealed = B64.decode(body["encrypted_value"].as_str().unwrap()).unwrap();
        assert_eq!(sk.unseal(&sealed).unwrap(), b"bmV3LXN0YXRl");
    }

    #[tokio::test]
    async fn put_secret_surfaces_api_errors() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/repos/acme/widgets/actions/secrets/public-key"))
            .respond_with(
                ResponseTemplate::new(403)
                    .set_body_string(r#"{"message":"Resource not accessible by integration"}"#),
            )
            .mount(&server)
            .await;
        let c = SecretsClient::new(&server.uri(), "acme/widgets", "ghp_test").unwrap();
        let err = c.put_secret("MATRIX_STATE", "x").await.unwrap_err().to_string();
        assert!(err.contains("403"), "{err}");
        assert!(err.contains("Resource not accessible"), "{err}");
    }
}
