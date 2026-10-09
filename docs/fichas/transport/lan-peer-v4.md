# Direct peer transport v3

This client-only protocol carries direct pairwise text and opaque OpenMLS
application events between two Rust clients on a reachable LAN. The Iced chat
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
Relay mode is disabled and callers supply direct socket addresses.

## Session framing

ALPN: `org.slouching.peer/4`. One QUIC bidirectional stream stays open for a
session. Every frame has a 19-byte header followed by its payload:

| Field | Size | Encoding |
| --- | ---: | --- |
| Marker | 4 bytes | ASCII `SLCH` |
| Version | 2 bytes | Unsigned big-endian integer, `4` |
| Kind | 1 byte | DATA=1, ACK=2, CLOSE=3, CLOSE_ACK=4, MLS_EVENT=5, MLS_COMMIT=6, REJECT=7, MLS_COMMIT_REQUEST=8 |
| Sequence | 8 bytes | Unsigned big-endian; application frames advance monotonically, control requests use zero |
| Payload length | 4 bytes | Unsigned big-endian byte count |

DATA carries 1–16,384 bytes of valid UTF-8. MLS_EVENT carries a bounded
`SLME` version 1 envelope with event ID (16 bytes), author device key (32),
group ID (16), epoch (u64), expiry timestamp (i64), optional checkpoint (up to
16 KiB), and nonempty serialized MLS ciphertext. The envelope is length
checked and capped at 64 KiB. The MLS ciphertext is already protected by MLS;
QUIC also encrypts the transport connection.

The receiver accepts only the next sequence and keeps at most 16 unacknowledged
inbound deliveries. The application must persist an inbound text message or
validate and persist an MLS event before sending ACK. For MLS, the client
updates its ratchet and local transcript in one SQLCipher transaction before
it ACKs. Exact event redelivery is deduplicated and ACKed without advancing the
ratchet a second time. A sender marks an MLS outbox item held by the peer after
that ACK; it does not mean a person read the message. On disconnect, pending
sends have unknown delivery. Queued MLS outbox events can be explicitly
retried from the group screen after reconnecting.

## Using the Iced app on a LAN

Create an identity on each device and exchange the displayed public keys out
of band. Linux needs Secret Service available in the user session. Start both
apps and pin the other device's key. One device chooses a UDP port and clicks
**Aguardar peer**; share its announced LAN address and port. The other enters
that address and connects. Either side can then send pairwise text in the
**Texto direto · LAN** view.

To use MLS, create a group on one device. Generate a KeyPackage on the other,
exchange it over a separately trusted channel, admit it, then return the
Welcome and ratchet tree to the joining client. Both devices open **Grupo MLS**
and select the same group ID. Establish the pinned direct LAN session in
**Texto direto · LAN**, then return to the group screen to send or retry
messages. Messages are retained in each device's local SQLCipher database.
When adding later members, the MLS screen can send the pending Commit over the
active pinned session to one device in the predecessor-epoch member snapshot.
The Iroh peer key must match the snapshotted device key, so a newly invited
member never receives the older Commit and a removed member can receive its
removal Commit. The receiver
validates the Commit signature, designated committer, group and next epoch,
persists the state, then ACKs. The sender persists that ACK per recipient and
the MLS screen shows which devices have adopted the Commit; redelivery is
idempotent. The new member joins with the matching Welcome and
ratchet tree. Automatic multi-member fan-out and helper delivery are not
implemented. One click drains that member's eligible Commit chain in epoch
order and waits for each persisted ACK before sending the next.

Allow the selected UDP port through each device's firewall. Wildcard addresses
such as `0.0.0.0` cannot be shared. If no LAN address is announced, inspect the
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
It exchanges text, opaque MLS events, MLS Commit frames, and predecessor
requests between separate processes; checks positive ACK, explicit rejection,
and wrong-pin rejection; then disconnects with pending sends to verify that
delivery remains unknown. Storage coverage verifies that a recipient can
recover a previously ACKed Commit after database reopen, while a device absent
from its recipient snapshot receives no data.

## Limits

This is direct-LAN-only. It has no relay, address discovery, NAT traversal,
offline delivery, group event distribution service, automatic multi-member
Commit fan-out, or cross-device history sync. MLS group setup and new-member
Welcome exchange remain manual. Existing members can receive and atomically
apply a Commit over the direct session; new members join through the matching
Welcome/ratchet tree. The protocol v4 ALPN and frame version are not compatible
with v3 peers. The older command-line
helpers are diagnostic; the supported user-facing flow is in Iced.
