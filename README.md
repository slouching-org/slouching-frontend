# Slouching frontend

Slouching's product client is a **native Rust/Iced desktop app**. This
follows the owner's [complete architecture PDF](https://github.com/slouching-org/slouching-backend/blob/main/docs/fichas/architecture/sources/architecture-p2p-v0.1.pdf);
the later peer-first decision changed the mandatory server model, not the
client language or UI toolkit.

The first HTML/CSS/JavaScript screens were a rushed **visual prototype**.
They now live in [`prototypes/web/`](prototypes/web/) and are not the
product frontend. The Rust app in [`src/main.rs`](src/main.rs) is the
new starting point.

## Run the native scaffold

```sh
cargo check
cargo run
```

It opens home, familiar, and call-preview views using the supplied art.
Controls do not connect peers, create keys, capture media, or send messages.
This is a native UI scaffold; visual parity with the eleven reference
screens and integration with the peer core remain open work.

![Actual Rust/Iced home scaffold, captured at runtime; visual parity is pending](docs/design/runtime/native-home.png)

## Architecture

- **UI:** Rust 2024, Iced 0.14.0 (pinned), wgpu renderer.
- **Core:** Rust/Tokio in
  [`slouching-org/slouching-backend`](https://github.com/slouching-org/slouching-backend).
  Each installed app will run the peer core locally.
- **Preferred boundary:** a version-pinned Rust library API from the
  backend repo, pending a reviewed interface and packaging plan.
- **Source of truth:** peer core state for identity, MLS, delivery,
  connections, capture, and calls. The UI must never invent those states.

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
