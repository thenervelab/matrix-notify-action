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

//! `matrix-notify`: post end-to-end encrypted messages to a Matrix room from
//! CI, with a device identity that survives across ephemeral runners.
//!
//! The crate is split so that everything that does not need a homeserver
//! (archive format, message formatting, room-target parsing, GitHub secret
//! sealing) is unit-testable offline; only [`matrix`] talks to the network.

pub mod message;
pub mod state;
pub mod store;
pub mod target;
