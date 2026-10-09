# Slouching frontend

Slouching's product client is a **native Rust/Iced desktop app**. This
follows the owner's [complete architecture PDF](https://github.com/slouching-org/slouching-backend/blob/main/docs/fichas/architecture/sources/architecture-p2p-v0.1.pdf);
the current architecture keeps Elixir as the server/backend core and Rust/Iced
as the client. The Rust peer scaffold is historical work, not this client's
backend interface.

The first HTML/CSS/JavaScript screens were a rushed **visual prototype**.
They now live in [`prototypes/web/`](prototypes/web/) and are not the
product frontend. The Rust app in [`src/main.rs`](src/main.rs) is the
application entry point; [src/ui.rs](src/ui.rs) owns the native design components and screens.

## Run the native scaffold

```sh
cargo check
cargo run
```

The build uses `protoc` to generate Rust types from
[`proto/slouching/v1/handshake.proto`](proto/slouching/v1/handshake.proto),
the copied shared protocol schema.

The app makes an asynchronous development handshake to
`GET http://127.0.0.1:3707/api/status` when it opens and on **Refresh backend**.
Run the sibling Elixir backend locally to see a response; otherwise the UI
reports it as unavailable. A response must match status contract v1 and
`backend: "elixir_scaffold"`. The UI reports contract mismatches separately.
This diagnostic confirms only that the local backend process responds. It
does not authenticate peers, start messaging, or establish a secure network
connection.

The app also opens `ws://127.0.0.1:3707/ws` asynchronously, sends a binary
protobuf `ClientHello` v1, and validates one binary `ServerHello` or
`VersionError` response. A compatible development transport stays open with
WebSocket Ping/Pong heartbeats and reconnects after a disconnect. This does
not establish a peer session. The UI shows connection and protocol errors
separately. **Refresh backend** repeats both
the HTTP diagnostic and WebSocket handshake.

## Direct LAN text transport experiment

The client includes a one-message Iroh/QUIC path for testing two devices on
the same LAN. Create an Ed25519 identity on each device from the Familiar
screen, then exchange the 64-character public-key hex values out of band.
Start the receiver on device A, pinning device B's public key:

```sh
PEER_KEY='REPLACE_WITH_DEVICE_B_64_CHAR_PUBLIC_KEY_HEX'
cargo run -- --lan-listen 45873 --expect-peer "$PEER_KEY"
```

On device B, use A's LAN IPv4 address and public key:

```sh
PEER_KEY='REPLACE_WITH_DEVICE_A_64_CHAR_PUBLIC_KEY_HEX'
cargo run -- --lan-send 192.168.1.20:45873 --expect-peer "$PEER_KEY" --text 'hello from the crew'
```

The listener accepts only the pinned Iroh EndpointId, and the sender dials the
expected ID directly. The Iroh endpoint key is derived from the device's
existing Ed25519 identity; QUIC TLS encrypts and authenticates the connection.
The stream carries one versioned UTF-8 frame (up to 16 KiB), an acknowledgement,
and explicit receipt frames so both processes know the exchange completed. No
relay, address lookup, Elixir route, or database service is used. Find the
receiver's LAN IP with `ip -4 addr` and allow UDP on the chosen port in the
local firewall.

This is a direct pairwise transport check, not MLS messaging or verified
contact pairing. The user must manually pin the other device key on both ends.
There is no MLS group, message history, retry/offline delivery, relay fallback,
NAT traversal, or chat UI integration. The chat screen remains an illustrative
preview. The automated `cargo test --test peer_process` launches two separate
OS processes, checks a text exchange and acknowledgement, and confirms that a
listener rejects an unpinned device.

The native app now recreates all eleven design-board views with real Iced
widgets, original characters and scenery, extracted outline SVG icons,
Bricolage Grotesque and JetBrains Mono, translucent panels, scanlines, and
vignette. The top-right **Telas** button opens the screen gallery.

Familiar selection, invitation/draft fields, screen navigation, settings
tabs, illustrative share-source selection, and interface texture work locally.
The familiar screen saves the display name and familiar as a local profile in
SQLCipher encrypted SQLite; the database key is stored in the operating system
credential store. Saving fails closed when that store is unavailable. The
screen can also explicitly create and retain an Ed25519 device signing key in
the system credential store. It displays the public key as unverified; no
fingerprint format, contact pairing, or MLS state is implemented. The core can
sign a versioned binding from that durable device key to an MLS signing
public key, including its signature-scheme code, without returning the private
seed. This primitive is not connected to an MLS credential, key package, peer
credential, KeyPackage, or trusted contact roster; the direct-LAN CLI pins
device public keys separately. The local profile remains separate from that key.
Every view is labeled as a visual
preview: character images, messages, and comparison words are illustrative.
The chat UI does not send messages; the separate direct-LAN CLI above sends one
real pairwise text frame. No camera, microphone, or screen is captured. **Rede &
P2P** in Settings retains the real Elixir HTTP/WebSocket diagnostics and
manual refresh. On Linux, this uses Secret Service, so a desktop password
vault must be installed and available in the user session.

The encrypted local database now has an event journal schema and storage
primitives for opaque, already-encrypted inbound and outbound events. It
deduplicates identical event IDs and rejects reuse with different ciphertext
or envelope metadata. Outbound rows have local queued/held/received/expired/
failed states and bounded cursor-paginated reads; the inbox can also be read
in bounded pages. No transport or authenticated receipt feeds those states
yet. MLS, inbox/outbox UI, delivery, and transport are not connected to these
primitives; this does not enable chat.

Opening the same SQLCipher database now composes OpenMLS RustCrypto with the
SQLite storage provider and initializes its versioned schema. This is only a
persistence foundation: the app does not yet create credentials, key
packages, groups, or live MLS state. MLS remains unconnected to the event
journal and UI.
A caller can explicitly create or load a distinct MLS signing key for a
chosen OpenMLS ciphersuite. Its public key is signed by the long-term device
identity and the MLS key is stored in the encrypted database. Repeated calls
reuse the key; this still does not create a KeyPackage or authenticate a peer.
A storage test verifies the encrypted schema, repeats both migrations, and
stores then reloads an MLS signing key across database opens in a temporary
database. The test composes OpenMLS's RustCrypto and SQL storage providers;
the app does not yet create MLS credentials, KeyPackages, or groups.

![Actual refreshed 1280 × 800 native Iced familiar screen from this transport milestone; Secret Service is unavailable in this capture](docs/design/runtime/native-vhs/01-familiar.png)

![Actual native Iced home with open scenery and icon-based feature strip, without the frog mage or gnome cutouts](docs/design/runtime/native-vhs/09-home.png)

![Actual native Iced group-call preview; all media and chat content is illustrative](docs/design/runtime/native-vhs/10-call.png)

The eleven runtime captures are in [native-vhs](docs/design/runtime/native-vhs/).
These are a first implementation of the visual direction, with comparison
at 1280 × 800 and a compact 960 × 640 window. Exact visual parity,
accessibility, and live media integration remain to be completed.

## Reproduce native captures

```sh
cargo run -- --screen 09-home
SLOUCHING_WINDOW_SIZE=1280x800 cargo run -- --capture-dir /tmp/slouching-captures
SLOUCHING_WINDOW_SIZE=960x640 cargo run -- --capture-dir /tmp/slouching-captures --capture-screen 01-familiar
```

The capture command renders all eleven screens, saves screenshots through
Iced's window screenshot API, and exits. Add `--capture-screen <slug>` to
capture one view, such as the familiar screen, instead of the full gallery. A tiling compositor may override
the requested window size; float/resize that window before the capture delay.
Set `SLOUCHING_CAPTURE_DELAY_MS` to extend the default six-second delay when
needed. `SLOUCHING_WINDOW_SIZE` only requests an initial size. The normal
default is a compact 1100 × 720 window.

Assets and font license/provenance notes are in [assets/README.md](assets/README.md).

## Architecture

- **UI:** Rust 2024, Iced 0.14.0 (pinned), wgpu renderer.
- **Local client core:** Rust owns local identity, cryptography, encrypted
  storage, peer transport, and media. The encrypted display profile and
  explicit Ed25519 key storage plus initial opaque encrypted-event storage
  are implemented. A pinned-device Iroh/QUIC LAN text exchange is available as
  a one-shot CLI experiment; MLS messaging, integrated inbox/history, and media
  remain unbuilt.
- **Server/backend:** Elixir in
  [`slouching-org/slouching-backend`](https://github.com/slouching-org/slouching-backend).
- **Current boundary:** loopback HTTP status and binary protobuf WebSocket
  handshake v1 and persistent Ping/Pong for development diagnostics. Authenticated production transport
  and functional APIs remain open design work.
- **Source of truth:** implemented backend and client-core state for identity,
  delivery, connections, capture, and calls. The UI must never invent them.

Read the [technology ficha](docs/fichas/architecture/tech-stack.md),
[native-client ADR](docs/fichas/architecture/adr-0003-native-client.md),
and [current-slice ficha](docs/fichas/frontend/current-slice.md).
Original screen exports are in [`docs/design/screens/`](docs/design/screens/).

The old web preview can still be viewed for visual comparison:

```sh
cd prototypes/web
python3 -m http.server 3708 --bind 127.0.0.1
```

That server is a static prototype only. The backend's current loopback
`/api/status` route is a development diagnostic, not the planned
production UI/core API.
