# matrix-notify-action

Post end-to-end encrypted messages to a Matrix room from CI. A small
[matrix-rust-sdk](https://github.com/matrix-org/matrix-rust-sdk) CLI plus a
GitHub Action: the message is encrypted on your runner with Megolm; the
homeserver only ever stores ciphertext.

```yaml
- uses: thenervelab/matrix-notify-action@v1
  if: always()
  with:
    room: "#ci:hippius.com"
    state: ${{ secrets.MATRIX_STATE }}
    state-key: ${{ secrets.MATRIX_STATE_KEY }}
    format: github-run
```

## Setup in 60 seconds

You need a Matrix account for the bot and a room it is invited to (or that it
can join). Once, on your machine:

```sh
# 1. get the CLI (or: cargo install --git https://github.com/thenervelab/matrix-notify-action)
curl -fsSL https://github.com/thenervelab/matrix-notify-action/releases/latest/download/matrix-notify-x86_64-unknown-linux-musl.tar.gz | tar xz

# 2. log the bot in, join the room, print the two secrets
GITHUB_REPOSITORY=your-org/your-repo \
./matrix-notify --store ./bot-state login --homeserver hippius.com --user ci --password-stdin --join '#ci:hippius.com'
# MATRIX_STATE_KEY=3f9a...   (64 hex chars)
# MATRIX_STATE=TU5TMQ...     (~16 KB of base64)

# 3. store both as repository secrets, then forget the local copy
gh secret set MATRIX_STATE_KEY --body 3f9a...
gh secret set MATRIX_STATE     --body TU5TMQ...
rm -rf ./bot-state
```

Any Matrix client in the room now shows one cross-signed device named
`matrix-notify (your-org/your-repo)`. The action reuses that same device on
every run.

`login` also accepts `--token -` (an access token on stdin) for accounts on
homeservers that log in through an OIDC provider instead of a password.

## Why the state must persist

Encrypting to a room means owning a device: an Olm account, its identity keys,
cross-signing signatures, and the access token that pairs them. A stateless
job would create a new device on every run, so recipients would see a fresh
"unverified device" each time and the account would accumulate hundreds of
dead devices.

`matrix-notify` keeps the SDK's SQLite store instead and moves it through one
repository secret:

- `state export` drops everything per-conversation (Olm sessions, outbound
  Megolm sessions, device-list tracking, other users' cached devices), then
  packs `session.json` and the two SQLite files into a deterministic gzip'd
  tar, and seals it with XChaCha20-Poly1305 under a key derived (HKDF-SHA256,
  per-archive salt) from `MATRIX_STATE_KEY`. A fresh snapshot is ~16 KB of
  base64 against GitHub's 48 KB secret limit.
- `state import` authenticates the whole blob before touching the tar, refuses
  any entry that is not a plain file name, and writes a 0700 directory with
  0600 files.
- Before every `send`, the same hygiene runs on the restored store. A snapshot
  restored on every run must never replay a Megolm message index or a spent
  Olm ratchet step, so each run shares a fresh room key over fresh Olm
  sessions. This is why the state does **not** have to be written back after
  a run: the identity is constant, the conversation keys are ephemeral.

The only thing that changes the snapshot is the identity itself: user id,
device id, access token, homeserver. `state fingerprint` hashes exactly those.
The action compares it before and after `send`; when it differs (the server
rotated the token) it exports a fresh blob and either updates the secret in
place (`gh-token` with `secrets: write`) or prints a masked warning telling you
to run `login` again.

## Action inputs

| input | default | notes |
|---|---|---|
| `room` | required | `#alias:server`, `!id:server` or a matrix.to link |
| `state`, `state-key` | required | the two secrets from `login` |
| `message` | | text; with `format` it becomes the paragraph under the card. `-` is not needed, the action feeds stdin |
| `markdown` | `false` | CommonMark + tables/strikethrough/task lists into `formatted_body` |
| `format` | | `github-run`: status glyph, repo, workflow / job, branch, linked short SHA, actor, run URL |
| `status` | `job.status` | `success`, `failure`, `cancelled` |
| `notice` | `true` | `m.notice` (does not ring phones); `false` sends `m.text` |
| `allow-unencrypted` | `false` | plaintext rooms are refused unless set |
| `timeout` | `60` | seconds |
| `version` | the action ref | release tag to download (`v1` resolves to the newest `v1.x.y`), or `source` to `cargo build` |
| `gh-token` | | token with `secrets: write` to update `secret-name` when the identity changed |
| `secret-name` | `MATRIX_STATE` | |

Outputs: `event-id`, `room-id`, `encrypted`, `state-changed`.

The action runs on `ubuntu-*` (x86_64, arm64) and `macos-*` runners; the
binary is a static musl build on Linux. Release assets are checksummed
(`SHA256SUMS`) and the checksum is verified before the binary runs.

## CLI

```
matrix-notify login   --homeserver <server> --user <id> (--password-stdin | --token -)
                      [--device-name ..] [--join <room>..] [--reset-cross-signing] [--no-export]
matrix-notify send    --room <room> (--message <text|-> | --format github-run --status <s>)
                      [--markdown] [--no-notice] [--allow-unencrypted] [--sync] [--json]
matrix-notify state   keygen | export --out - | import --in - | fingerprint
matrix-notify whoami  [--json]
matrix-notify github-secret --name <NAME> --repo <owner/repo> --value-file -   # token in $GH_TOKEN
```

The store directory is `--store`, else `$MATRIX_NOTIFY_STORE`, else
`$MATRIX_NOTIFY_HOME`, else `~/.matrix-notify`. `MATRIX_STATE_KEY` is read
from the environment; it is never accepted on the command line by the action.

## Security notes

- Everything sent is `m.room.encrypted` / `m.megolm.v1.aes-sha2`. The room's
  encryption state is checked on the server before sending; a plaintext room
  is an error unless `--allow-unencrypted`.
- The bot device signs itself with cross-signing at `login`. If the account
  already has a cross-signing identity from another session it is reported,
  not replaced, unless `--reset-cross-signing`.
- No refresh tokens are requested, so the token in the snapshot keeps working
  across runs without the state having to be written back. If your homeserver
  forces short-lived tokens, give the action `gh-token` and it will keep the
  secret current.
- The snapshot is decrypted into `$RUNNER_TEMP` and deleted in an `always()`
  step. Tokens never appear on stdout, in logs, or on the command line.
- Anyone holding both secrets *is* the bot device: they can read what the room
  sends it and post as it. Scope the secrets to the environments that need
  them and rotate by running `login` again (the old device can be removed
  from any Matrix client).
- The snapshot does not include the SDK event cache or media, and other users'
  device lists are re-fetched on each run.

## Development

```sh
cargo test                       # unit + integration, no network
cargo clippy --all-targets --features e2e -- -D warnings
scripts/e2e.sh [user] [room] [homeserver]   # live: login, export, import, send, read back
```

The live test logs in, snapshots, restores into two separate stores, sends
from both, fetches the raw events with the access token and asserts they are
`m.room.encrypted` with distinct Megolm session ids and no plaintext. It logs
the test device out at the end.

## License

Apache-2.0. See `LICENSE`.
