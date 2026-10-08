# Current frontend slice

**Status:** native Rust/Iced scaffold; visual and functional work remains.

`src/main.rs` opens three navigable views: home, familiar selection,
and call preview. It uses supplied artwork. Invitation entry and controls
produce explicit local notices. They do not create a cryptographic identity,
connect peers, open capture devices, send messages, or join calls.

The earlier HTML/CSS/JavaScript preview is retained under
`prototypes/web/` as a **design benchmark**, not the product runtime.
Its familiar name lives in browser local storage only; that is not a
verified device identity. Its call art is illustrative, never a live
camera feed.

The [eleven source screens](../../design/screens) define the visual
target. A future native implementation must compare real Iced captures
against them and handle small windows, accessibility, permissions, and
honest connection states.

The backend Rust repository owns identity, MLS, delivery, transport,
and call state. The frontend currently has no core dependency. The
preferred future boundary is a reviewed and version-pinned Rust library
API; see the [technology plan](../architecture/tech-stack.md).
