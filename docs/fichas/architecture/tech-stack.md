# Frontend technology plan

**Accepted client direction:** native Rust/Iced. This comes from the
[owner's complete source PDF](https://github.com/slouching-org/slouching-backend/blob/main/docs/fichas/architecture/sources/architecture-p2p-v0.1.pdf).
Its Elixir server/backend core and Rust/Iced client direction are retained.

| Layer | Choice | Current state |
| --- | --- | --- |
| Desktop UI | Rust 2024 + pinned Iced 0.14.0 | Native state in `src/main.rs`; eleven design-board views plus an MLS group setup screen |
| Rendering | Iced/wgpu | Native views with images, SVG icons, and canvas texture; direct-LAN chat is functional, call/media screens remain previews |
| Local client core | Rust identity, cryptography, storage, transport, media | SQLCipher profile and direct-chat history; OpenMLS group setup, transactional event journal, and MLS chat over a pinned Iroh/QUIC session with durable ACK/retry are implemented; discovery, relay, offline delivery, and media remain pending |
| Server/backend | Elixir, separately versioned backend repo | Development status and protobuf handshake implemented |
| State boundary | Versioned protocol | Asynchronous loopback HTTP status and binary protobuf WebSocket handshake v1 integrated; production boundary pending |
| Browser UI | HTML/CSS/JavaScript | Historical visual prototype in `prototypes/web/`; not product runtime |
| Identity, MLS, storage, transport, calls | Client and server responsibilities per source PDF | Device-bound MLS signer, manual KeyPackage/Welcome exchange, local group persistence, designated-committer admission, authenticated application messages over the active peer session, and SQLCipher transcript/outbox; group discovery, fingerprint verification, relay, offline delivery, and calls remain unimplemented |

The frontend must render authoritative implemented state. It must not generate
security claims, route badges, presence, or capture status independently.

The frontend currently requests `GET http://127.0.0.1:3707/api/status`
as a development diagnostic. It checks status contract v1 and the Elixir
backend marker, then renders the reported capabilities. It also sends a
single binary protobuf ClientHello v1 to `/ws`, validates the response, and
keeps a development transport open with Ping/Pong heartbeats. Before a release, define an
authenticated production boundary and integration tests for identity,
routing, MLS transitions, and capture state.

Direct peer messaging uses Iroh/QUIC independently from that local server
diagnostic. MLS application messages also use the direct session once both
devices have joined the same manually provisioned group. The LAN flow uses the durable Ed25519 device key as the Iroh
EndpointId and manually pins the expected peer ID on both sides. It sends
multiple bounded UTF-8 messages over one session stream, with sequence
acknowledgements and relay mode disabled. This provides
direct pairwise transport encryption and pinned endpoint authentication only;
it does not create an MLS group or establish contact pairing. See the
[direct peer transport v4 contract](../transport/lan-peer-v4.md).

See [ADR 0003](adr-0003-native-client.md) and the
[backend stack ficha](https://github.com/slouching-org/slouching-backend/blob/main/docs/fichas/architecture/tech-stack.md).
