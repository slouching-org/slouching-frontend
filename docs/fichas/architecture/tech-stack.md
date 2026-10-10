# Frontend technology plan

**Accepted client direction:** native Rust/Iced, with Elixir/OTP as the
optional backend core. This follows the
[owner's architecture specification](https://github.com/slouching-org/slouching-backend/blob/main/docs/fichas/architecture/sources/architecture-p2p-v0.1.pdf)
and [ADR 0005](https://github.com/slouching-org/slouching/blob/main/docs/fichas/architecture/adr-0005-elixir-server-core.md).

| Layer | Choice | Current state |
| --- | --- | --- |
| Desktop UI | Rust 2024 + pinned Iced 0.14.0 | Twelve native design-board views with direct chat, MLS, calls, sharing, identity, and settings flows |
| Rendering | Iced/wgpu | Native images, SVG icons, canvas scenes, local capture previews, and authenticated remote video frames |
| Local media | CPAL, Opus/SFrame, WebRTC | Device selection and microphone test; direct call media is implemented, with experimental two-device SFU audio tested against the local Elixir helper |
| Local client core | Rust, Tokio, Iroh/QUIC, OpenMLS | Pinned-device direct chat, MLS groups and events, durable per-device delivery, file transfer, local route book, signed QR invites, and LAN discovery hints |
| Local persistence | SQLCipher SQLite + OS credential store | Encrypted profile, identity metadata, transcripts, MLS state, outboxes, and optional helper settings; private device keys remain in the OS credential store |
| Backend | Elixir/OTP, separately versioned repo | Optional SPAKE2 pairing, signed opaque-copy mailbox, and experimental authenticated SFU signaling; remote helper deployment remains unverified |
| Protocol boundary | Protobuf WebSocket v2 + HTTP helper APIs | Ed25519 device proof, Ping/Pong, signed SFU roster admission, pairing, and mailbox flows; device proof does not establish human trust or MLS membership |
| Historical UI | HTML/CSS/JavaScript | `prototypes/web/` is a design reference; it is not the product runtime |

Direct messaging and local state do not require a hosted server or PostgreSQL.
Members may explicitly configure Iroh relay or Elixir helper services. The SFU
settings page can test WSS, device authentication, and advertised call support;
it cannot verify UDP media reachability. Calls across physical devices or
different networks, authenticated remote contact discovery, and release
packaging remain open.

The frontend renders state reported by local transports and cryptographic
operations. It must not invent security claims, route status, presence, or
capture status. The local `/api/status` endpoint is a development diagnostic;
the authenticated WebSocket is used by experimental SFU signaling and does not
carry ordinary chat or MLS application messages.

See [ADR 0003](adr-0003-native-client.md), [the current
transport contract](../transport/lan-peer-v10.md), and the
[main project architecture](https://github.com/slouching-org/slouching/blob/main/docs/fichas/architecture/frontend-tech-stack.md).
