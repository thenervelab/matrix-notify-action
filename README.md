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
./matrix-notify --store ./bot-state login ... > secrets.env      # or paste the two lines by hand
grep '^MATRIX_STATE_KEY=' secrets.env | cut -d= -f2- | gh secret set MATRIX_STATE_KEY
grep '^MATRIX_STATE='     secrets.env | cut -d= -f2- | gh secret set MATRIX_STATE
rm -rf ./bot-state secrets.env
```

Any Matrix client in the room now shows one cross-signed device named
`matrix-notify (your-org/your-repo)`. The action reuses that same device on
every run.

`login` also accepts `--token-stdin` (an access token on stdin) for accounts
on homeservers that log in through an OIDC provider instead of a password. If
`login` ends with a cross-signing warning (the server wanted interactive auth),
finish it on the same device with `matrix-notify --store ./bot-state cross-sign
--password-stdin` and export again; do not log in twice, that makes two devices.

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
- The room itself is never trusted from the snapshot: every `send` runs one
  incremental sync, re-fetches the member list from the server and queries the
  keys of every member before sharing the room key. A member who joined since
  the snapshot gets the key; one who left does not.

The only thing that changes the snapshot is the identity itself: user id,
device id, access token, homeserver. `state fingerprint` hashes exactly those.
The action compares it before and after `send`; when it differs it exports a
fresh blob and either updates the secret in place (`gh-token` with
`secrets: write`) or prints a masked warning. With the current client this
should not happen: no refresh token is requested, so the access token in the
snapshot is the one the server issued at `login` and it stays valid until you
log the device out. The check is there so a silent change can never go
unnoticed, not because rotation is expected.

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
| `strict-recipients` | `false` | fail when any member has no device; default fails only when nobody could decrypt |
| `timeout` | `60` | seconds, for the whole send (sync, members, key queries, send) |
| `version` | the action ref | release tag to download (`v1` resolves to the newest `v1.x.y`), or `source` to `cargo build` |
| `gh-token` | | token with `secrets: write` to update `secret-name` if the identity ever changes |
| `secret-name` | `MATRIX_STATE` | |

Outputs: `event-id`, `room-id`, `encrypted`, `recipients` (devices the room
key was shared with), `state-changed`.

The action runs on `ubuntu-*` (x86_64, arm64) and `macos-*` runners; the
binary is a static musl build on Linux. Release assets are checksummed
(`SHA256SUMS`) and the checksum is verified before the binary runs.

## CLI

```
matrix-notify login   --homeserver <server> --user <id> (--password-stdin | --token-stdin)
                      [--device-name ..] [--join <room>..] [--reset-cross-signing] [--no-export]
matrix-notify send    --room <room> (--message <text|-> | --format github-run --status <s>)
                      [--markdown] [--no-notice] [--allow-unencrypted] [--strict-recipients] [--json]
matrix-notify state   keygen | export --out - | import --in - | fingerprint
matrix-notify cross-sign [--password-stdin] [--reset]
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
- Before sharing the room key, every other member's devices are queried from
  the server. A room where nobody has a device (federation failure, empty
  room) is an error rather than a message no one can decrypt; members with no
  device are listed in a warning, or fail the run with `--strict-recipients`.
- The bot device signs itself with cross-signing at `login`. If the account
  already has a cross-signing identity from another session it is reported,
  not replaced, unless `--reset-cross-signing`.
- No refresh tokens are requested, so the token in the snapshot keeps working
  across runs without the state having to be written back. Homeservers that
  only issue short-lived tokens are not supported by this design.
- The snapshot is decrypted into `$RUNNER_TEMP` and deleted in an `always()`
  step. Tokens and keys travel through stdin, environment variables or 0600
  files, never argv; they do not appear on stdout or in logs.
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
