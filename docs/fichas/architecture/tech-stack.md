# Frontend technology plan

**Accepted client direction:** native Rust/Iced. This comes from the
[owner's complete source PDF](https://github.com/slouching-org/slouching-backend/blob/main/docs/fichas/architecture/sources/architecture-p2p-v0.1.pdf).
Its Elixir server/backend core and Rust/Iced client direction are retained.

| Layer | Choice | Current state |
| --- | --- | --- |
| Desktop UI | Rust 2024 + pinned Iced 0.14.0 | Native scaffold in `src/main.rs` |
| Rendering | Iced/wgpu | Basic image and control views; video shader path unbuilt |
| Local client core | Rust identity, cryptography, storage, transport, media | Not yet implemented |
| Server/backend | Elixir, separately versioned backend repo | Development status and protobuf handshake implemented |
| State boundary | Versioned protocol | Asynchronous loopback HTTP status and binary protobuf WebSocket handshake v1 integrated; production boundary pending |
| Browser UI | HTML/CSS/JavaScript | Historical visual prototype in `prototypes/web/`; not product runtime |
| Identity, MLS, storage, transport, calls | Client and server responsibilities per source PDF | Not implemented in frontend |

The frontend must render authoritative implemented state. It must not generate
security claims, route badges, presence, or capture status independently.

The frontend currently requests `GET http://127.0.0.1:3707/api/status`
as a development diagnostic. It checks status contract v1 and the Elixir
backend marker, then renders the reported capabilities. It also sends a
single binary protobuf ClientHello v1 to `/ws`, validates the response, and
keeps a development transport open with Ping/Pong heartbeats. Before a release, define an
authenticated production boundary and integration tests for identity,
routing, MLS transitions, and capture state.

See [ADR 0003](adr-0003-native-client.md) and the
[backend stack ficha](https://github.com/slouching-org/slouching-backend/blob/main/docs/fichas/architecture/tech-stack.md).
