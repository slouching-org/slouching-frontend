# AGENTS.md

Slouching's product client: a native Rust/Iced desktop app for peer-first
chat, calls and screen sharing. The optional Elixir helper lives in
`slouching-backend`. The project overview, design sources, canonical protobuf
schema and cross-repository scripts live in `slouching`, which pins this
repository as the submodule `repositories/frontend`.

The README is long and parts of it lag behind the code. Where they disagree,
trust the code.

## Commands

```sh
cargo fmt --check
cargo clippy --locked --all-targets -- -D warnings
cargo test --locked
cargo run    # opens the desktop app
```

The first three are the CI gates (`.github/workflows/ci.yml`).

- `rust-toolchain.toml` pins Rust 1.99.1. Only rustup honours it; a
  distribution `cargo` uses its own version and may report other lints.
- The build needs `protoc`, clang/libclang, cmake, nasm and the development
  files for ALSA, PipeWire, EGL, GBM and XCB. The exact Ubuntu package list is
  `APT_PACKAGES` in the workflow.
- Tests use loopback sockets and temporary directories. They need no display,
  audio device or keyring, and they pass in a headless container.
- Four tests are `#[ignore]`d because they need a live Elixir helper. The
  `scripts/smoke-*.sh` scripts in `slouching` start one and run them.

## Layout

One binary crate, no library target.

| Path | Contents |
| --- | --- |
| `src/main.rs` | Iced application state and update loop, command-line flags, gateway handshake |
| `src/ui.rs` | Screens and widgets |
| `src/storage.rs` | SQLCipher profile: identity, contacts, history, OpenMLS state, outbox, saved routes |
| `src/peer.rs` | Pinned Iroh/QUIC sessions and their frame protocol |
| `src/identity.rs`, `peer_invite.rs`, `pairing_*.rs`, `verification_fingerprint.rs` | Device keys, signed QR invites, SPAKE2 pairing, fingerprints |
| `src/call_*.rs`, `sfu_call.rs`, `audio.rs`, `media.rs`, `video_transport.rs` | WebRTC calls, Opus and H.264 with SFrame, optional SFU route |
| `src/screen_capture.rs`, `wayland_capture.rs`, `camera_capture.rs` | Capture through xcap, the ScreenCast portal with PipeWire, and nokhwa |
| `src/file_transfer.rs`, `blob_store.rs`, `delivery_client.rs`, `lan_discovery.rs` | Encrypted attachments, mailbox client, mDNS |
| `tests/peer_process.rs` | Runs a listener and a sender as two processes by re-executing the test binary |
| `proto/` | Copy of the handshake schema; `build.rs` compiles it with prost |
| `assets/`, `docs/`, `prototypes/web/` | Art and fonts, fichas and runtime captures, the historical web prototype |

## Conventions

- `tests/peer_process.rs` compiles `blob_store`, `file_transfer`, `identity`,
  `media`, `peer` and `storage` a second time through `#[path]`. Those six
  modules may only depend on each other, and their unit tests run in both
  test binaries.
- Unit tests sit in a `#[cfg(test)] mod tests` at the end of each module.
- Most dependencies are pinned to exact versions (`=x.y.z`). Pin new ones the
  same way and commit `Cargo.lock`.
- `proto/slouching/v1/handshake.proto` must stay byte-identical to the
  canonical file in `slouching`. Change it there first, then copy it here and
  to `slouching-backend`.
- Interface text is mostly Brazilian Portuguese with some English; match the
  screen you are editing. Code, comments and commit messages are in English.
- The interface shows only state that the client core actually has. Do not
  add placeholder peers, messages or connection states outside the
  `--capture-*` fixtures.
- There is no `unsafe` code.
- Device seeds and the database key live in the operating system keyring.
  Never log or persist them elsewhere.
- Images under `docs/design/runtime/` are generated with the `--capture-*`
  flags described in the README.
- Commit subjects are short imperative sentences without a prefix.
- Peer session tests must drive both sides until `Disconnected` and call
  `listener.close().await` before the listener task returns. A session is a lazy
  stream: an unpolled side cannot answer CLOSE, and a dropped listener can cut
  QUIC teardown short; either way the other side waits out `CLOSE_TIMEOUT` (8 s).

## Known gaps

- There is no LICENSE file yet; the team has to choose one.
