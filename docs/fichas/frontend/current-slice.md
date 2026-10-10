# Current frontend slice

**Status:** eleven design-board screens plus a native MLS group screen. Direct
chat uses pinned Ed25519 device identities and persistent Iroh/QUIC sessions.
Successful connections save the pinned device key and a direct or configured
relay route in the encrypted local route book. The MLS screen can reuse saved
routes for sequential multi-member Commit fan-out. MLS group setup can send a device-bound KeyPackage over the active
pinned session; the committer reviews and admits it after matching the package
identity to the transport peer. Admission stores the exact Welcome and ratchet
tree in the encrypted outbox with the membership Commit. The committer sends
the bundle over the pinned session and marks it delivered after ACK. The
invitee validates the target device, group, local KeyPackage and pinned
committer, saves the joined group and content-bound Welcome receipt atomically,
then ACKs. Reconnecting retries queued Welcomes, and a duplicate after a lost
ACK returns the already joined group. Copy/paste remains available when direct
delivery is unavailable. For an already joined group, MLS application
messages are encrypted with OpenMLS and sent over the active direct session.
The receiver validates the sender binding and event metadata, advances the
ratchet, stores ciphertext and the local transcript in SQLCipher, then ACKs.
Each application event atomically snapshots the current peer devices with its ciphertext and ratchet update. Per-device ACKs keep other recipients queued; the global outbox entry closes only after all snapshot members ACK. Direct send checks that the pinned peer is in this snapshot, and queued events can be retried for that peer after reconnecting. The fan-out control sends messages through saved routes in order, after that member's pending Commit chain is clear. An unreachable peer remains queued while other members continue. Membership Commit bytes and the predecessor-epoch member roster are saved atomically with the merged group state. The MLS screen drains pending Commits in epoch order over the active pinned QUIC session, sending only to devices in each Commit's predecessor-epoch recipient snapshot. It waits for each durable ACK before advancing. If a device receives a later Commit before its expected predecessor, it requests that epoch over the pinned session; the committer can return an already-ACKed Commit only to a device in its original recipient snapshot. Newly invited members are excluded; a removed device can receive the Commit that removes it. The receiver validates envelope metadata, MLS signature, group, predecessor epoch, designated committer, and device-bound credentials before atomically persisting the Commit and journal record; transport ACK follows persistence and is durably recorded per recipient on the sender. The UI shows each eligible device's saved adoption ACK. Exact redelivery is idempotent. The fan-out control visits recipients with queued Commits and saved routes in turn, sends bounded ordered batches, and persists each ACK before continuing. An unavailable peer does not stop the others; its Commits remain queued for retry. Routes can be stale and are learned from successful outbound pinned connections. Offline delivery and concurrent proposal handling remain open.

The encrypted local profile has a disabled-by-default delegated MLS-copy
store. It accepts ciphertext only with an Ed25519 grant from the authenticated
author device, bound to one recipient and one event digest. It enforces a 64
MiB / 4,096-event holder quota, a 32 KiB item limit, and a 30-day maximum TTL;
it retains bounded deduplication receipts and removes ciphertext after ACK or
expiry. Disabling consent erases all queued ciphertext immediately and retains
only bounded deduplication tombstones. Network & P2P settings expose the
persisted opt-in and bounded policy.
The control is unavailable while the OS credential store cannot unlock the
local encrypted profile. Peer transport and recipient fetch are now present in
QUIC v8. On connect, the client requests up to 16
copies addressed to its device; the holder requires its opt-in and ACKs only
after durable storage, while the recipient verifies the author's grant and
persists the MLS event before ACK. The helper deletes its copy after that ACK.
The MLS fan-out action tries a reachable routed group peer to retain copies
when a recipient route cannot be reached. Helper ACKs remain separate from
recipient delivery; the author's outbox stays queued until the target device
accepts the event. Fetch is limited to 16 copies per connection, and helper
retention is best-effort rather than an availability guarantee.
An opted-in listener accepts the author and a later recipient in distinct
authenticated sessions, one at a time. Other application frames remain bound
to the manually pinned peer. This store-and-forward path requires a reachable
route to the helper for each connection. A configured participant Iroh Relay
can carry that route, but the helper flow has not been separately tested over
a remote relay. This does not provide address discovery or hole-punching.

Before applying a next-epoch Commit, the client stores the prior OpenMLS group
state in the encrypted profile database. If a different Commit later arrives
for an already accepted predecessor epoch, the client restores that snapshot
inside a rolled-back verification transaction and checks the MLS signature,
group, epoch, designated committer, and device binding. A second valid Commit
from the same committer is recorded as equivocation and permanently quarantines
that group on this device. The accepted epoch stays intact; MLS sends, retries,
and Commit distribution are blocked, and the security alert returns when the
group is reopened. The UI disables member admission, Commit distribution and
manual application along with message sends and retries. Invalid or differently
authored conflicts do not trigger quarantine. Recovery or rekey after
quarantine is not implemented.

`src/main.rs` owns application and transport state; `src/ui.rs` composes the
native Iced views, original art, icons, embedded fonts, and texture effects.
The **Telas** gallery reaches each screen. The MLS view creates groups,
prepares and admits device-bound KeyPackages, processes Welcome and ratchet
tree data, loads a bounded local transcript, sends application messages, and
retries queued outbox events for the selected group unless it is quarantined. Group invitations require a separately trusted device-key pin and an explicit
committer admission. Both devices must have joined the same
group, select its ID, and establish a direct session over a reachable route.
Groups saved on this device appear with their current epoch and quarantine
status; selecting one reloads its local transcript and security state.
Members can send signed self-update proposals to the designated committer over
the active pinned session, or exchange their bytes through a separately
trusted channel. The committer checks the MLS author against the pinned peer,
authenticates and stores the proposal before ACK, and deduplicates exact
redelivery. The committer UI lists each current-epoch proposal's member key
prefix and proposal ID before enabling Commit creation. The button commits all
proposals shown in the review list; selecting or rejecting proposals
individually and handling other proposal types are not implemented.

The direct-text screen manually pins the peer's Ed25519 device key. One side
listens and shares a reachable interface address; the other connects to that
address. A VPN may provide a direct route if it carries UDP, but that path is
not yet verified between machines. Both can send multiple messages. A member
may configure an HTTPS/token Iroh Relay for fallback or relay-only connections;
the local test exercises pinned text and opaque MLS event delivery through it.
The receiver stores inbound text
before ACK; the sender stores sent text after ACK. It reloads the newest 200
messages for the peer and supports confirmed history deletion. This pairwise
text path is separate from MLS. Neither path provides address discovery,
hole-punching, or guaranteed offline delivery. Remote relay and VPN behavior
remain unverified. The MLS ACK confirms durable local
acceptance by the other client, not that a person read the message.

The familiar screen stores the display name and familiar in encrypted SQLite;
the database key and Ed25519 device seed use the operating system credential
store. The public device key is shown as unverified. A device-signed binding
connects that identity to the MLS signing key and is carried in KeyPackages.
This does not establish contact trust or pairing. Linux needs Secret Service
available in the user session. The settings **Rede & P2P** screen separately
shows local Elixir HTTP/WebSocket diagnostics; it does not carry chat traffic.

Character scenes and call views remain visual previews. Camera, microphone,
screen capture, contact discovery, verified pairing, and guaranteed offline
delivery are not implemented. The older web UI under
`prototypes/web/` is a design benchmark, not the product runtime.

See [direct peer transport v8](../transport/lan-peer-v8.md) for the direct session
contract and [the Iced design plan](iced-design.md) for visual references.
