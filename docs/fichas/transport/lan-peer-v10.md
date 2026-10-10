# Direct peer transport v10

This client-only protocol carries direct pairwise text and opaque OpenMLS
application events between two Rust clients over a manually addressed UDP route. The Iced chat
screen exposes pin, listen, connect, send, disconnect, and session transcript
controls. The MLS screen uses the same active peer session after both devices
have joined the same group. Elixir HTTP/WebSocket diagnostics are independent
and do not carry these messages.

## Identity and channel

Each Iroh endpoint uses the local Ed25519 device identity seed. Iroh's
`SecretKey` and the device key derive the same public bytes, so the Iroh
`EndpointId` is the device public key. Both sides manually pin the expected
peer ID out of band; QUIC authenticates that endpoint and encrypts transport.
This does not establish contact trust, a verified roster, or MLS membership.
A direct UDP route is the default; the user may also configure a participant-operated Iroh Relay with HTTPS and a shared token. The relay carries the encrypted QUIC connection and is never selected silently.

## Session framing

ALPN: `org.slouching.peer/10`. One QUIC bidirectional stream stays open for a
session. Every frame has a 19-byte header followed by its payload:

| Field | Size | Encoding |
| --- | ---: | --- |
| Marker | 4 bytes | ASCII `SLCH` |
| Version | 2 bytes | Unsigned big-endian integer, `10` |
| Kind | 1 byte | DATA=1, ACK=2, CLOSE=3, CLOSE_ACK=4, MLS_EVENT=5, MLS_COMMIT=6, REJECT=7, MLS_COMMIT_REQUEST=8, MLS_PROPOSAL=9, MLS_KEY_PACKAGE=10, MLS_WELCOME=11, MLS_DELEGATED_COPY=12, MLS_COPY_FETCH=13, CALL_SIGNAL=14 |
| Sequence | 8 bytes | Unsigned big-endian; application frames advance monotonically, control requests use zero |
| Payload length | 4 bytes | Unsigned big-endian byte count |

DATA carries 1–16,384 bytes of valid UTF-8. MLS_EVENT carries a bounded
`SLME` version 1 envelope with event ID (16 bytes), author device key (32),
group ID (16), epoch (u64), expiry timestamp (i64), optional checkpoint (up to
16 KiB), and nonempty serialized MLS ciphertext. The envelope is length
checked and capped at 64 KiB. The MLS ciphertext is already protected by MLS;
QUIC also encrypts the transport connection.

MLS_PROPOSAL carries a `SLMP` version 1 envelope: event ID (16 bytes), author
device key (32), group ID (16), current epoch (u64), and nonempty serialized
proposal. Its payload is capped at 64 KiB. The event ID is the first 16 bytes
of BLAKE3 over the proposal bytes. OpenMLS verifies the proposal's member
credential before storage; the authenticated QUIC session protects it in
transit.

The receiver accepts only the next sequence and keeps at most 16 unacknowledged
inbound deliveries. The application must persist an inbound text message or
validate and persist an MLS event before sending ACK. For MLS, the client
updates its ratchet and local transcript in one SQLCipher transaction before
it ACKs. Exact event redelivery is deduplicated and ACKed without advancing the
ratchet a second time. A sender marks an MLS outbox item held by the peer after
that ACK; it does not mean a person read the message. On disconnect, pending
sends have unknown delivery. Queued MLS outbox events can be explicitly
retried from the group screen after reconnecting.

The MLS screen can send a freshly generated self-update proposal to the
designated committer over the same pinned session. The receiver checks that
the envelope author matches the pinned Iroh device, then OpenMLS verifies the
member credential, group, epoch, and self-update proposal before saving it in
the encrypted local database. Only after that storage operation succeeds does
the client ACK. Exact redelivery is deduplicated. If the connection closes
before ACK, delivery is unknown and the member can resend the same proposal;
the receiver's event ID makes that retry idempotent. This path supports
self-update proposals only; proposal approval and other proposal types remain
unimplemented.

MLS_KEY_PACKAGE carries a `SLKP` version 1 envelope: event ID (16 bytes),
invitee device key (32), group ID (16), and public KeyPackage bytes. The event
ID is the first 16 bytes of BLAKE3 over the package. Payloads are capped at
64 KiB. The receiving UI requires the envelope's invitee key to equal the
authenticated pinned peer and requires the same group to be selected. It
holds the frame until the designated committer approves **Validar e admitir
membro**. The ACK follows the transaction that saves the membership Commit
and Welcome locally. It then sends the Welcome and ratchet tree in an
MLS_WELCOME frame. The invitee checks the target device and group, validates
the MLS Welcome against its local KeyPackage and the pinned committer identity,
persists the group, and only then ACKs. The committer keeps the Welcome in its
encrypted retry outbox until ACK and can resend it after reconnect; the invitee
records the event and purpose together so an exact retry is idempotent and a
purpose change is rejected.

MLS_WELCOME carries an `SLMW` version 2 envelope: event ID (16), invitee
device key (32), group ID (16), purpose byte (`0` for conversation, `1` for
call), Welcome length and bytes, then ratchet-tree length and bytes. The purpose
is stored with the joined group and immutable Welcome receipt. Call-media key
export rejects conversation and quarantined groups; the UI does not yet create
call groups or connect this exporter to media. The content ID is the first 16 BLAKE3 bytes over both
length-prefixed artifacts. The payload is bounded to 256 KiB. The receiver
requires the local device and pending group to match the envelope, then
OpenMLS verifies the Welcome against the local KeyPackage. The sender's
device-bound MLS credential must match the pinned Iroh peer before the joined
group can commit to SQLCipher.

MLS_DELEGATED_COPY carries an `SLDG` version 1 signed author grant, the
recipient device key, expiry, event metadata, BLAKE3 ciphertext digest, and the
bounded `SLME` event. The peer transport checks that the grant metadata and
ciphertext digest match the event. A helper additionally requires the QUIC
peer to equal the signed author and its local storage opt-in to be enabled;
the SQLCipher holder quota and expiry checks run before ACK. The recipient
checks the signed grant targets its own device, verifies the signature and
digest, then applies the MLS event and persists the transcript before ACK. A
helper deletes its ciphertext only after that recipient ACK. The copy frame is
capped at 96 KiB; the persisted ciphertext item limit remains 32 KiB.

MLS_COPY_FETCH is a zero-sequence, empty control frame. A peer sends it once
when a direct session connects. The holder returns at most 16 authorized
queued copies addressed to that authenticated device. Copies beyond the first
batch remain queued for a later session. The MLS fan-out action tries a
reachable routed group member as a helper when a recipient cannot be reached;
the author sends signed grants and the helper's storage ACK is reported
separately from recipient delivery. The author's recipient outbox stays queued
until the recipient itself ACKs. A holder only promises the copies it retains
within its local quota and retention window, so this remains best-effort
delivery rather than an availability guarantee.

## WebRTC call signaling frame

`CALL_SIGNAL` is a sequenced application frame carried only over a pinned
QUIC session. Its payload is an `SLCS` version 1 envelope: group ID (16 bytes),
call MLS epoch (u64), kind (OFFER=1, ANSWER=2, ICE_CANDIDATE=3, END=4),
payload length (u32), and opaque payload (up to 128 KiB). The fixed envelope
header is 35 bytes. The group ID cannot be zero, the epoch must fit the local
MLS storage range, and END must have an empty payload; the other kinds require
a nonempty payload. Offer, answer, and candidate payloads carry serialized
WebRTC signaling data. The transport does not authenticate MLS membership or
interpret SDP: the application must match the pinned device to a current member
of the indicated call group and epoch before accepting the signal.

The normal per-session sequence and ACK/REJECT behavior applies. ACK confirms
that the receiving client accepted the signaling frame into its application
flow; it does not mean ICE connected or media started. The current client
exposes this transport primitive, but its UI rejects incoming signaling until
the WebRTC call controller is implemented.

## Using the Iced app on a reachable route

Create an identity on each device and exchange the displayed public keys out
of band. Linux needs Secret Service available in the user session. Start both
apps and pin the other device's key. One device chooses a UDP port and clicks
**Aguardar peer**; choose and copy the announced interface address that the
other device can reach. It may be a LAN or VPN address; allow UDP on the
selected port. The other enters that address and connects. Either side can
then send pairwise text in the **Texto direto · LAN/VPN** view. A VPN can
provide the route when it carries UDP, but this has not been validated between
machines yet.

To use MLS, create a group on one device. Generate a KeyPackage on the other,
select the same group ID, and connect directly to the designated committer.
Click **Enviar KeyPackage ao committer conectado**. The committer reviews the
incoming peer-bound package and admits it with **Validar e admitir membro**.
After storing the membership Commit and Welcome, it ACKs the KeyPackage and
sends the Welcome plus ratchet tree through the same pinned session. The new
member clicks **Validar Welcome e entrar**; it saves the group before ACKing the
Welcome. The copy/paste fields remain available if the direct Welcome delivery
is unknown. Both devices open **Grupo MLS**
and select the same group ID. Establish the pinned direct session in
**Texto direto · LAN/VPN**, then return to the group screen to send or retry
messages. Messages are retained in each device's local SQLCipher database.
When adding later members, the MLS screen can send the pending Commit over the
active pinned session to one device in the predecessor-epoch member snapshot.
The Iroh peer key must match the snapshotted device key, so a newly invited
member never receives the older Commit and a removed member can receive its
removal Commit. On peer connection, the client checks whether that pinned
device has eligible pending Commits and starts the chain automatically. The
receiver validates the Commit signature, designated committer, group and next
epoch, persists the state, then ACKs. The sender persists that ACK per recipient
and the MLS screen shows which devices have adopted the Commit; redelivery is
idempotent. Each next Commit waits for the previous persisted ACK. The same
chain can also be started manually from the MLS screen. The new member joins
with the matching Welcome and ratchet tree. Connecting to every member still
requires a separate peer session; simultaneous multi-peer fan-out and helper
delivery are not implemented. To update a member's credential, select that
group on the member device, generate a self-update proposal, connect directly
to the designated committer, and use **Enviar proposta ao committer conectado**.
After the committer reports that it stored the proposal, it can create and
deliver the resulting Commit through the existing member flow.

Allow the selected UDP port through each device's firewall. Wildcard addresses
such as `0.0.0.0` cannot be shared. If no direct address is announced, inspect the
machine's network interfaces.

An MLS_COMMIT_REQUEST is a control frame with sequence zero and a fixed 24-byte
payload: group ID (16 bytes) followed by the missing predecessor epoch (u64).
It does not consume the data sequence. The receiver answers only when its local
Commit outbox contains that epoch and the requesting pinned device appears in
the Commit's predecessor-epoch recipient snapshot. An existing recipient may
recover a Commit already marked delivered; a newly invited or unrelated device
cannot fetch it. Requests are limited to 16 per session.

## Automated checks

`cargo test --test peer_process` launches separate operating system processes.
It exchanges text, opaque MLS events, MLS Commit frames, predecessor requests,
proposals, KeyPackages, and Welcome bundles; checks
positive ACK, explicit rejection, and wrong-pin rejection; then disconnects with pending text,
event, Commit, and proposal sends to verify delivery is reported unknown. Storage
coverage verifies that a recipient can recover a previously ACKed Commit after
database reopen, while a device absent from its recipient snapshot receives no
data. Codec tests cover proposal and call-signaling envelope bounds. A direct pinned-session test exchanges a call offer and verifies its transport ACK.

## Limits

The current client supports manually addressed UDP routes and an explicitly
configured participant-operated Iroh Relay. It has no address discovery, NAT
traversal, offline delivery, group event distribution service, automatic
multi-member Commit fan-out, or cross-device history sync. Group creation and admission
require explicit user actions. Welcome and ratchet-tree transfer use the
direct pinned session after admission, with copy/paste retained as a fallback.
Existing members can receive and atomically apply a Commit over the direct
session. The protocol v10 ALPN and frame version are not compatible with v9 or
older peers. The older command-line
helpers are diagnostic; the supported user-facing flow is in Iced.
