# Current frontend slice

**Status:** eleven native Rust/Iced screens, including a user-facing direct-LAN
Iroh/QUIC text flow with a session-only transcript; MLS messaging and product
pairing remain open.

The frontend's `src/main.rs` owns application state and local transport;
`src/ui.rs` composes the eleven source-board views with native widgets,
original scenery, familiar portraits and cutouts, source-derived SVG icons,
embedded fonts, translucent panels, scanlines, and vignette. The **Telas**
gallery reaches every view. Home actions open the lobby preview; invitation
fields edit in-memory values. The chat screen manually pins a peer device key,
starts a one-message listener, sends text to a LAN address, and shows confirmed
sends and received messages only in the current session. Familiar selection,
settings and share-source tabs, and the interface texture toggle work locally. The
familiar screen saves only the display name and familiar in SQLCipher
encrypted SQLite; its random database key is kept in the operating system
credential store. Linux requires Secret Service in the user session. A
separate explicit action generates a local Ed25519 device signing key and
stores its seed in the system credential store; the public key is displayed
as unverified. The core can sign the MLS signing key selected for an OpenMLS
ciphersuite with this long-term device key. Fingerprint/QR derivation, contact
pairing, MLS groups, and message history remain unimplemented. If the keyring cannot be read, the screen offers
a retry that reuses an existing key rather than replacing it. The display
profile is distinct from identity.

The encrypted SQLite schema now includes an event journal for opaque inbound
and outbound ciphertext, with stable random IDs, envelope metadata, BLAKE3
ciphertext digests, and duplicate/conflict handling. These storage primitives
also retain queued, peer-held, received, expired, or failed outbox state and
load bounded cursor pages for both inbox and outbox. They are not connected to
the UI, MLS, or peer transport; only trusted protocol code may record a real
receipt.

Character scenes and call views remain visual previews. The chat screen sends
and receives actual one-shot text over pinned-device Iroh/QUIC; it does not
write to the local event journal. Camera/microphone actions explain their
unavailable state; verification controls still do not verify MLS membership.
The app does not enumerate devices, create MLS messages, join calls, or persist
local conversation history. The settings **Rede & P2P** tab exposes
real backend diagnostics separately from the illustrative call routes.

The earlier HTML/CSS/JavaScript preview is retained under
`prototypes/web/` as a **design benchmark**, not the product runtime.
Its familiar name lives in browser local storage only; that is not a
verified device identity. Its call art is illustrative, never a live
camera feed.

The [eleven source screens](../../design/screens) define the visual
target. Native captures were compared at 1280 × 800 and a compact 960 × 640
window. The first visual pass covers all eleven views; exact parity,
accessibility, and permissions still need further implementation and review.

The native UI now requests a v1 development status snapshot from the local
Elixir backend over loopback HTTP using an asynchronous Iced task in the network settings. It shows
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

The chat screen uses a direct-LAN-only Iroh/QUIC transport, separate from the
Elixir diagnostics. Both sides manually pin the other's Ed25519 device public
key; QUIC TLS authenticates and encrypts the connection. The listener accepts
one bounded UTF-8 text frame and acknowledges it. Sent and received messages
remain only in application memory. This has no relay, address lookup, NAT
traversal, MLS group, offline delivery, durable history, or trusted contact
roster. See [LAN text transport v1](../transport/lan-text-v1.md) for framing
and use. An automated test launches two separate OS processes and checks
delivery and rejection of an unpinned peer.
