#!/usr/bin/env bash
# Copyright 2026 The Nerve Lab
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

# Live end-to-end test: login -> export -> import -> send -> read the raw
# event back and assert it is m.room.encrypted. Creates one device on the
# bot account and logs it out at the end (MATRIX_E2E_KEEP=1 to keep it).
#
# Usage:
#   MATRIX_E2E_PASSWORD=... scripts/e2e.sh [user] [room] [homeserver]
#   scripts/e2e.sh                      # prompts for the password
#
# Defaults: user ci, room #ci:hippius.com, homeserver hippius.com.
set -euo pipefail

cd "$(dirname "$0")/.."

export MATRIX_E2E_USER="${1:-${MATRIX_E2E_USER:-ci}}"
export MATRIX_E2E_ROOM="${2:-${MATRIX_E2E_ROOM:-#ci:hippius.com}}"
export MATRIX_E2E_HOMESERVER="${3:-${MATRIX_E2E_HOMESERVER:-hippius.com}}"

if [ -z "${MATRIX_E2E_PASSWORD:-}" ]; then
  read -r -s -p "password for ${MATRIX_E2E_USER} on ${MATRIX_E2E_HOMESERVER}: " MATRIX_E2E_PASSWORD
  echo
  export MATRIX_E2E_PASSWORD
fi

export MATRIX_NOTIFY_E2E=1
export RUST_LOG="${RUST_LOG:-warn,matrix_notify=info}"

exec cargo test --features e2e --test e2e -- --nocapture
