# Frontend technology plan

**Accepted client direction:** native Rust/Iced. This comes from the
[owner's complete source PDF](https://github.com/slouching-org/slouching-backend/blob/main/docs/fichas/architecture/sources/architecture-p2p-v0.1.pdf).
The PDF's central Elixir/PostgreSQL server proposal was superseded by
the peer-first decision, but the client direction remains.

| Layer | Choice | Current state |
| --- | --- | --- |
| Desktop UI | Rust 2024 + pinned Iced 0.14.0 | Native scaffold in `src/main.rs` |
| Rendering | Iced/wgpu | Basic image and control views; video shader path unbuilt |
| Peer core | Rust/Tokio, separately versioned backend repo | No linked core yet |
| State boundary | Version-pinned Rust library API preferred | Contract, packaging, and cross-repo checks pending |
| Browser UI | HTML/CSS/JavaScript | Historical visual prototype in `prototypes/web/`; not product runtime |
| Identity, MLS, storage, transport, calls | Owned by peer core | Not implemented in frontend |

The frontend must render authoritative core state. It must not generate
security claims, route badges, presence, or capture status independently.
The production app should package UI and peer core on each user's device;
source repository separation is not a hosted-server requirement.

The current backend `GET /api/status` endpoint is only a local
development diagnostic. It is not a secure application IPC boundary.
Before linking the repos, define the Rust API, pin compatible commits,
and run integration tests for identity, routing, MLS transitions, and
capture state.

See [ADR 0003](adr-0003-native-client.md) and the
[backend stack ficha](https://github.com/slouching-org/slouching-backend/blob/main/docs/fichas/architecture/tech-stack.md).
