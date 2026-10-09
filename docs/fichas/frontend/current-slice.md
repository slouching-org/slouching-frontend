# Current frontend slice

**Status:** eleven design-board screens plus a native MLS group screen. Direct
LAN chat uses pinned Ed25519 device identities and persistent Iroh/QUIC
sessions. MLS group setup supports manual KeyPackage, Welcome, and ratchet-tree
exchange over a trusted channel. For an already joined group, MLS application
messages are encrypted with OpenMLS and sent over the active direct session.
The receiver validates the sender binding and event metadata, advances the
ratchet, stores ciphertext and the local transcript in SQLCipher, then ACKs.
The sender marks the outbox event held by the peer after receiving that ACK.
Queued application events can be retried from the MLS screen after reconnecting. Membership Commit bytes and the predecessor-epoch member roster are saved atomically with the merged group state. The MLS screen drains pending Commits in epoch order over the active pinned QUIC session, sending only to devices in each Commit's predecessor-epoch recipient snapshot. It waits for each durable ACK before advancing. If a device receives a later Commit before its expected predecessor, it requests that epoch over the pinned session; the committer can return an already-ACKed Commit only to a device in its original recipient snapshot. Newly invited members are excluded; a removed device can receive the Commit that removes it. The receiver validates envelope metadata, MLS signature, group, predecessor epoch, designated committer, and device-bound credentials before atomically persisting the Commit and journal record; transport ACK follows persistence and is durably recorded per recipient on the sender. The UI shows each eligible device's saved adoption ACK. Exact redelivery is idempotent. Repeat after connecting to each other member; multi-peer fan-out, offline delivery, and concurrent proposal handling remain open.

`src/main.rs` owns application and transport state; `src/ui.rs` composes the
native Iced views, original art, icons, embedded fonts, and texture effects.
The **Telas** gallery reaches each screen. The MLS view creates groups,
prepares and admits device-bound KeyPackages, processes Welcome and ratchet
tree data, loads a bounded local transcript, sends application messages, and
retries queued outbox events for the selected group. Group invitations still
require a separately trusted channel. Both devices must have joined the same
group, select its ID, and establish a direct LAN session to exchange messages.

The direct-LAN text screen manually pins the peer's Ed25519 device key. One
side listens and shares its announced LAN address; the other connects to that
address. Both can send multiple messages. The receiver stores inbound text
before ACK; the sender stores sent text after ACK. It reloads the newest 200
messages for the peer and supports confirmed history deletion. This pairwise
text path is separate from MLS. Neither path provides relay, address discovery,
NAT traversal, or offline delivery. The MLS ACK confirms durable local
acceptance by the other client, not that a person read the message.

The familiar screen stores the display name and familiar in encrypted SQLite;
the database key and Ed25519 device seed use the operating system credential
store. The public device key is shown as unverified. A device-signed binding
connects that identity to the MLS signing key and is carried in KeyPackages.
This does not establish contact trust or pairing. Linux needs Secret Service
available in the user session. The settings **Rede & P2P** screen separately
shows local Elixir HTTP/WebSocket diagnostics; it does not carry chat traffic.

Character scenes and call views remain visual previews. Camera, microphone,
screen capture, contact discovery, verified pairing, group event distribution,
relay, and offline delivery are not implemented. The older web UI under
`prototypes/web/` is a design benchmark, not the product runtime.

See [direct peer transport v4](../transport/lan-peer-v4.md) for the direct session
contract and [the Iced design plan](iced-design.md) for visual references.
