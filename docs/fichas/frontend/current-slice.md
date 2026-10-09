# Current frontend slice

**Status:** eleven native Rust/Iced screens, including direct-LAN Iroh/QUIC
text with per-peer local history in SQLCipher. Core MLS membership and atomic
application-message encryption plus inbound/outbound journal processing now
work. An additional Iced screen exposes local group creation and admission;
network delivery and MLS chat presentation remain open.

The frontend's `src/main.rs` owns application state and local transport;
`src/ui.rs` composes the eleven source-board views and an MLS setup screen with native widgets,
original scenery, familiar portraits and cutouts, source-derived SVG icons,
embedded fonts, translucent panels, scanlines, and vignette. The **Telas**
gallery reaches every view. Home actions open the lobby preview; invitation
fields edit in-memory values. The chat screen manually pins a peer device key,
starts a pinned direct listener or connects to a pinned LAN address, and keeps
a bidirectional session open for multiple messages with live receive and ACK
states. Received text is saved in SQLCipher before ACK; sent text is saved
after ACK. The app reloads the newest 200 messages for the pinned peer and can
delete that peer's local history after confirmation.
Familiar selection, settings and share-source tabs, and the interface
texture toggle work locally. The familiar screen saves only the display name
and familiar in SQLCipher
encrypted SQLite; its random database key is kept in the operating system
credential store. Linux requires Secret Service in the user session. A
separate explicit action generates a local Ed25519 device signing key and
stores its seed in the system credential store; the public key is displayed
as unverified. The core can sign the MLS signing key selected for an OpenMLS
ciphersuite with this long-term device key. The core can create a one-use
OpenMLS KeyPackage whose BasicCredential embeds this binding; OpenMLS keeps its
private bundle in SQLCipher. The core creates and persists local MLS group
state and indexes its creator as designated committer. The MLS setup screen
exposes group creation and public-artifact exchange. Core APIs admit a device-bound KeyPackage,
merge its Commit into local state, return Commit/Welcome/ratchet-tree bytes, and
process a Welcome on the joining device. It can encrypt an application payload
at the current epoch and persist the serialized MLS message as a queued outbox
event in the same SQLCipher transaction as the MLS ratchet update. Inbound
processing authenticates the event AAD and sender binding, persists ciphertext
before returning plaintext, and deduplicates exact redelivery in the same
transaction as the ratchet update. Network delivery, fingerprint/QR derivation,
contact pairing, and MLS group history remain unimplemented. If the keyring cannot be read, the screen offers
a retry that reuses an existing key rather than replacing it. The display
profile is distinct from identity.

The encrypted SQLite schema now includes an event journal for opaque inbound
and outbound ciphertext, with stable random IDs, envelope metadata, BLAKE3
ciphertext digests, and duplicate/conflict handling. These storage primitives
also retain queued, peer-held, received, expired, or failed outbox state and
load bounded cursor pages for both inbox and outbox. MLS application processing
now stores ciphertext in this journal and changes OpenMLS state transactionally;
transport delivery, UI, and authenticated remote receipts remain open.

Character scenes and call views remain visual previews. The chat screen sends
and receives actual multiple-message sessions over pinned-device Iroh/QUIC and
stores its transcript in a separate per-peer table; it does not write to the
local event journal. Camera/microphone actions explain their
unavailable state; verification controls still do not verify MLS membership.
The app does not enumerate devices, expose MLS group or message flows, or join calls. The
settings **Rede & P2P** tab exposes
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
key; QUIC authenticates and encrypts the connection. One bidirectional stream
exchanges multiple bounded UTF-8 messages with sequence ACKs. The receiver
saves inbound text to SQLCipher before ACK; the sender saves after ACK. This
local transcript is per peer and is not group/MLS history or a synced inbox.
The transport has no relay, address lookup, NAT traversal, offline delivery,
or trusted contact roster. See [LAN text transport v2](../transport/lan-text-v2.md) for framing
and use. Automated tests launch separate OS processes to check multiple messages
in both directions, wrong-pin rejection, and pending-send status at disconnect.
