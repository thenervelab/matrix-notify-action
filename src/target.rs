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

//! Parsing of the `--room` argument: a room alias (`#ci:example.org`), a
//! room id (`!abc:example.org`), or either of those wrapped in a
//! `https://matrix.to/#/...` permalink.

use matrix_sdk::ruma::{OwnedRoomAliasId, OwnedRoomId, OwnedServerName};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RoomTarget {
    Alias(OwnedRoomAliasId),
    Id { room_id: OwnedRoomId, via: Vec<OwnedServerName> },
}

#[derive(Debug, thiserror::Error)]
#[error("{0:?} is not a room alias (#name:server) or room id (!id:server)")]
pub struct TargetError(String);

impl RoomTarget {
    pub fn parse(input: &str) -> Result<Self, TargetError> {
        let raw = input.trim();
        let (body, query) = strip_permalink(raw);
        let via = query_via(query);

        if body.len() < 2 {
            return Err(TargetError(input.to_owned()));
        }
        if body.starts_with('#') {
            let alias: OwnedRoomAliasId = body.parse().map_err(|_| TargetError(input.to_owned()))?;
            return Ok(Self::Alias(alias));
        }
        if body.starts_with('!') {
            let room_id: OwnedRoomId = body.parse().map_err(|_| TargetError(input.to_owned()))?;
            return Ok(Self::Id { room_id, via });
        }
        Err(TargetError(input.to_owned()))
    }

    pub fn describe(&self) -> String {
        match self {
            Self::Alias(a) => a.to_string(),
            Self::Id { room_id, .. } => room_id.to_string(),
        }
    }
}

/// Peel `https://matrix.to/#/<target>?via=..` (percent-encoded `#` as `%23`
/// included). Returns `(target, query)`.
fn strip_permalink(raw: &str) -> (String, Option<&str>) {
    let Some(rest) = raw.strip_prefix("https://matrix.to/#/").or_else(|| raw.strip_prefix("matrix.to/#/"))
    else {
        return (raw.to_owned(), None);
    };
    let (target, query) = match rest.split_once('?') {
        Some((t, q)) => (t, Some(q)),
        None => (rest, None),
    };
    let target = percent_encoding::percent_decode_str(target).decode_utf8_lossy().into_owned();
    (target, query)
}

fn query_via(query: Option<&str>) -> Vec<OwnedServerName> {
    query
        .unwrap_or("")
        .split('&')
        .filter_map(|kv| kv.strip_prefix("via="))
        .filter_map(|v| percent_encoding::percent_decode_str(v).decode_utf8_lossy().parse().ok())
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn alias() {
        let t = RoomTarget::parse(" #ci:hippius.com\n").unwrap();
        assert_eq!(t, RoomTarget::Alias("#ci:hippius.com".parse().unwrap()));
        assert_eq!(t.describe(), "#ci:hippius.com");
    }

    #[test]
    fn room_id() {
        let t = RoomTarget::parse("!abcDEF:hippius.com").unwrap();
        assert!(
            matches!(t, RoomTarget::Id { ref room_id, ref via } if room_id == "!abcDEF:hippius.com" && via.is_empty())
        );
    }

    #[test]
    fn permalinks() {
        let t = RoomTarget::parse("https://matrix.to/#/%23ci%3Ahippius.com").unwrap();
        assert_eq!(t.describe(), "#ci:hippius.com");
        let t = RoomTarget::parse("https://matrix.to/#/%23ci%3ahippius.com?via=hippius%2Ecom").unwrap();
        assert_eq!(t.describe(), "#ci:hippius.com");
        let t =
            RoomTarget::parse("https://matrix.to/#/!abc:hippius.com?via=hippius.com&via=matrix.org").unwrap();
        match t {
            RoomTarget::Id { room_id, via } => {
                assert_eq!(room_id, "!abc:hippius.com");
                assert_eq!(
                    via.iter().map(ToString::to_string).collect::<Vec<_>>(),
                    ["hippius.com", "matrix.org"]
                );
            }
            _ => panic!(),
        }
    }

    #[test]
    fn garbage() {
        for bad in ["", "ci", "@user:hippius.com", "#no-server", "!", "https://example.org"] {
            assert!(RoomTarget::parse(bad).is_err(), "{bad:?} should fail");
        }
    }
}
