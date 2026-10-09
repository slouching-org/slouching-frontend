# Current frontend slice

**Status:** native Rust/Iced scaffold; visual and functional work remains.

`src/main.rs` opens three navigable views: home, familiar selection,
and call preview. It uses supplied artwork. Invitation entry is a visual
preview, while call and device controls are disabled. They do not create a
cryptographic identity, connect peers, open capture devices, send messages,
or join calls.

The earlier HTML/CSS/JavaScript preview is retained under
`prototypes/web/` as a **design benchmark**, not the product runtime.
Its familiar name lives in browser local storage only; that is not a
verified device identity. Its call art is illustrative, never a live
camera feed.

The [eleven source screens](../../design/screens) define the visual
target. A future native implementation must compare real Iced captures
against them and handle small windows, accessibility, permissions, and
honest connection states.

The native UI now requests a v1 development status snapshot from the local
Elixir backend over loopback HTTP using an asynchronous Iced task. It shows
connecting, unavailable, incompatible-contract, and responding states; the
user can refresh manually. This only proves local process availability.
The response currently reports unimplemented identity, messaging, and calls
and zero peer connections. It is not an authenticated production boundary
or a live event stream. Functional client-core and server APIs remain open;
see the [technology plan](../architecture/tech-stack.md).

The UI also performs a binary protobuf WebSocket handshake at `/ws` using
the copied shared v1 schema. It validates the Elixir role and protocol
version, then keeps a development transport open with Ping/Pong heartbeats.
It reports disconnects and retries with bounded backoff. This transport has
no device authentication, application traffic, or messaging.
