# Slouching frontend

Slouching's product client is a **native Rust/Iced desktop app**. This
follows the owner's [complete architecture PDF](https://github.com/slouching-org/slouching-backend/blob/main/docs/fichas/architecture/sources/architecture-p2p-v0.1.pdf);
the current architecture keeps Elixir as the server/backend core and Rust/Iced
as the client. The Rust peer scaffold is historical work, not this client's
backend interface.

The first HTML/CSS/JavaScript screens were a rushed **visual prototype**.
They now live in [`prototypes/web/`](prototypes/web/) and are not the
product frontend. The Rust app in [`src/main.rs`](src/main.rs) is the
application entry point; [src/ui.rs](src/ui.rs) owns the native design components and screens.

## Run the native scaffold

```sh
cargo check
cargo run
```

The build uses `protoc` to generate Rust types from
[`proto/slouching/v1/handshake.proto`](proto/slouching/v1/handshake.proto),
the copied shared protocol schema.

The app makes an asynchronous development handshake to
`GET http://127.0.0.1:3707/api/status` when it opens and on **Refresh backend**.
Run the sibling Elixir backend locally to see a response; otherwise the UI
reports it as unavailable. A response must match status contract v1 and
`backend: "elixir_scaffold"`. The UI reports contract mismatches separately.
This diagnostic confirms only that the local backend process responds. It
does not authenticate peers, start messaging, or establish a secure network
connection.

The app also opens `ws://127.0.0.1:3707/ws` asynchronously, sends a binary
protobuf `ClientHello` v1, and validates one binary `ServerHello` or
`VersionError` response. A compatible development transport stays open with
WebSocket Ping/Pong heartbeats and reconnects after a disconnect. This does
not establish a peer session. The UI shows connection and protocol errors
separately. **Refresh backend** repeats both
the HTTP diagnostic and WebSocket handshake.

## Direct LAN messages

The **chat** button in the Iced app opens a persistent direct-text screen. This
path sends real text over Iroh/QUIC between devices on a reachable LAN; it is
separate from the Elixir diagnostics and has no hosted service in the data
path.

1. Start the app on both devices. Create a device identity if needed, open the
   chat screen, and use **Copiar minha chave pública** to exchange the two 64-character
   Ed25519 public keys out of band. On Linux, the system Secret Service must
   be available to create or load this identity.
2. On both devices, paste the other device's public key into **Chave pública do
   peer · pin manual**. This manually pins the peer for both sending and receiving.
3. On the receiving device, choose a UDP port (for example `45873`) and click
   **Aguardar peer**. Use **Copiar endereço LAN** to copy the announced socket
   address and share it with the sender. If the app lists several addresses,
   the button prefers a private IPv4 address. Wildcard addresses such as
   `0.0.0.0` cannot be shared; if no LAN address is announced, check the
   device's network interfaces.
4. On the sending device, enter the receiver's LAN address and port, type a
   message, and click **Conectar e enviar**. After connection, either device
   can send multiple messages over the same session. Sent text appears only
   after an ACK; received text appears live after the pinned identity check.

A successful outbound connection saves the pinned device key and socket address
in the encrypted local route book. The chat screen lists these routes, and the
MLS screen can use them to distribute pending Commits to current group members.
LAN addresses can become stale; peers without a saved route remain pending. The listener stays
available through the session. Either side can use **Desconectar sessão** to
close it; start a new session to reconnect. The
receiver saves an inbound message to its encrypted local history before ACK;
the sender saves an outbound message after receiving ACK. ACK confirms
acceptance into the receiver's local transcript, not that the user read it.
History stays on each device and is scoped to the pinned peer key; it is not
synchronized. **Apagar histórico local deste peer** removes only that peer's
rows after an explicit confirmation. This is pairwise QUIC channel encryption
and pinned device identity, not MLS messaging or contact verification. There
is no address discovery, relay, cross-NAT support, retry/offline delivery, or
media. Allow the chosen UDP port through each device's local firewall. The automated
`cargo test --test peer_process` launches separate OS processes, exchanges
multiple messages in both directions over one connection, checks wrong-pin
rejection, and verifies a pending send is reported as unknown on disconnect.

The native app now recreates all eleven design-board views with real Iced
widgets, original characters and scenery, extracted outline SVG icons,
Bricolage Grotesque and JetBrains Mono, translucent panels, scanlines, and
vignette. The top-right **Telas** button opens the screen gallery.

An additional **Grupo MLS** screen supports two-device group setup. Create the
group on one device and share its ID. The invitee can send its public KeyPackage
over the active pinned session, or copy it through a trusted channel. The
committer reviews and admits the package; the receiver checks that its device
key matches the pinned peer before saving the Commit. After admission, the committer sends the Welcome and ratchet tree through the
same pinned session. The committer saves the exact Welcome bundle in its
encrypted outbox with the membership Commit. The invitee validates it and
stores the group before ACK; the same content-bound event is recorded in that
transaction, so a retry after a lost ACK safely returns the existing group.
After an unknown delivery or app restart, reconnect to the pinned invitee to
retry the queued bundle. Copy/paste fields remain available if direct delivery
is unavailable. After both devices join, open
**Texto direto · LAN** and connect them using the usual
pinned-key and LAN-address flow. In **Grupo MLS**, select the same group ID on
both devices; MLS messages are encrypted and sent over that active direct
Iroh/QUIC session. The receiver validates the MLS event and stores its
ciphertext, ratchet update, and plaintext transcript in SQLCipher before
sending the transport ACK. Each message atomically snapshots this epoch's peer
devices with the ciphertext and ratchet update. The sender records ACKs per
device and leaves other recipients queued; the outbox event closes only after
all snapshot members confirm. Direct send checks that the pinned peer belongs
to the snapshot. The MLS screen can retry messages for the connected peer or
distribute them to all peers with saved routes. A peer with pending Commits is
skipped until its group epoch is current; unavailable peers remain queued. New
MLS chat events expire after 30 days. Expired events leave the retry queue,
recipients reject new expired events before changing their MLS ratchet, and
fan-out status reports the number that expired during the run.
Membership Commits are also saved atomically with the
group epoch in a separate local outbox; the latest pending Commit is restored
from SQLCipher and can be sent from the MLS screen over an active direct
session. The sender matches the pinned peer key to the device snapshot taken
at the Commit's predecessor epoch; a newly invited device is not sent that
older Commit, while a removed device can still receive its removal Commit.
The recipient validates it and persists the new
epoch before ACK, and the sender stores that ACK per recipient. Exact redelivery
is harmless. When a pinned peer connects, the client checks for that device's
eligible Commit chain and starts delivery automatically; each next Commit waits
for the preceding durable ACK. The manual **Enviar Commits pendentes** control
remains available for the connected peer. **Distribuir a todos os peers salvos**
walks the queued recipient ledger, connects to each peer's saved route in turn,
and sends its eligible Commits in bounded batches. Each Commit waits for its
durable ACK before the next is sent; one unavailable peer does not stop delivery
to the others. Stop the current listener/session before starting the fan-out.
Stale or missing routes are reported and can be retried after reconnecting.
Offline delivery remains in progress. If a recipient is behind, it requests the missing predecessor over
the pinned session; the committer serves it only when that device was in the
Commit's predecessor snapshot, including Commits already marked delivered.
The MLS screen
shows each eligible device's persisted adoption ACK. Storage regression tests
build a two-Commit chain, verify epoch order, and confirm that the next Commit
remains queued after the first recipient ACK and a database reopen. New members join with the matching Welcome and ratchet tree delivered over the
pinned session after the committer admits their KeyPackage. The transcript reloads locally, and **Reenviar pendentes**
sends queued events for the selected group after reconnecting.

### Testar fan-out MLS com três dispositivos

Use três máquinas na mesma LAN (A, B e C). Em cada uma, crie uma identidade e
troque as chaves públicas por um canal confiável. Libere no firewall UDP para a
porta escolhida em cada máquina.

1. Em A, crie um grupo MLS. Em B, conecte a A usando o endereço LAN anunciado e
   envie o KeyPackage público. Em A, admita B e envie o Welcome. Confirme que B
   abriu o mesmo grupo.
2. Repita com C. C recebe o Welcome no epoch atual; B precisa aplicar o Commit
   que adicionou C.
3. Faça A conectar uma vez a B e uma vez a C usando as chaves pinadas e os
   endereços LAN deles. Isso salva as duas rotas no dispositivo A. Encerre a
   sessão/listener e, em A, clique em **Distribuir a todos os peers salvos**
   para entregar a B os Commits pendentes.
4. Confirme que os três dispositivos mostram o mesmo grupo e epoch. Em A,
   envie uma mensagem MLS e clique em **Distribuir mensagens MLS aos peers
   salvos**. B e C devem mostrar a mensagem recebida. Em A, o status deve
   confirmar ACK de ambos e a outbox só deve fechar depois dos dois ACKs.
5. Para conferir a retomada, feche ou desconecte C antes do próximo fan-out.
   B deve receber e confirmar a mensagem; C deve continuar pendente. Reconecte
   A a C para atualizar a rota, feche a sessão e repita o fan-out. C deve
   receber o mesmo evento, sem duplicar a mensagem em B.

Esse fluxo exercita rotas diretas salvas e ACK por membro; não usa Postgres nem
helper. Uma rota inacessível fica pendente, e o ACK confirma persistência no
cliente remoto, não leitura humana.

The MLS screen lists groups saved in the local SQLCipher database with their
current epoch and quarantine state. **Abrir** restores a group's ID, bounded
transcript, pending Commits, and security alert, so reopening the app does not
depend on remembering the group ID.

A member can create a signed MLS self-update proposal and send it to the
designated committer over the active pinned peer session, or copy its public
bytes for a separately trusted channel. The committer checks that the MLS
author is the same device as the pinned transport peer, authenticates the
member's device-bound MLS credential, stores the proposal in the encrypted
OpenMLS state, and deduplicates exact redelivery. The sender receives an ACK
only after the proposal is stored. Only the designated committer can turn
accepted proposals into a Commit. That operation saves the new epoch, Commit
outbox, and predecessor-member recipient ledger atomically; the existing
direct-session Commit delivery flow distributes it. This proposal path accepts
self-updates only. Before Commit creation, the committer screen lists each
authenticated proposal's epoch, member key prefix, and proposal ID prefix. The
button commits every proposal shown for the current epoch; individual approval
and rejection controls and other proposal types are not implemented.

For this flow, both members join the same group. The member opens it, clicks
**Criar proposta para atualizar minha chave**, connects directly to the
designated committer, and clicks **Enviar proposta ao committer conectado**.
The copy/paste controls remain available when the devices cannot connect. The
committer then clicks **Criar Commit das propostas pendentes** and distributes
it over the active pinned peer session.

Before applying a Commit, each device saves the prior OpenMLS epoch state in
its encrypted profile database. If it later receives a different, valid Commit
from the designated committer for an already accepted predecessor epoch, it
verifies that Commit against the saved state, records both signed Commit values,
and quarantines the group locally. The accepted epoch remains unchanged, and
the UI shows a persistent security alert while blocking MLS sends, retries,
and further Commit distribution for that group. Invalid Commit bytes do not
quarantine the group. This client currently has no automated recovery or rekey
flow for a quarantined group.

Familiar selection, invitation/draft fields, screen navigation, settings
tabs, illustrative share-source selection, and interface texture work locally.
The familiar screen saves the display name and familiar as a local profile in
SQLCipher encrypted SQLite; the database key is stored in the operating system
credential store. Saving fails closed when that store is unavailable. The
screen can also explicitly create and retain an Ed25519 device signing key in
the system credential store. It displays the public key as unverified; no
fingerprint format or contact pairing is implemented. OpenMLS credentials
include a versioned binding signed by the durable device key. One-use
KeyPackages and private MLS state are stored in SQLCipher. The direct-LAN
screen separately pins device public keys. Character scenes and call views
remain visual previews. No camera, microphone, or screen is captured. **Rede &
P2P** in Settings retains the Elixir HTTP/WebSocket diagnostics and manual
refresh. On Linux, this uses Secret Service, so a desktop password vault must
be installed and available in the user session.

![Actual refreshed 1280 × 800 native Iced familiar screen from this transport milestone; Secret Service is unavailable in this capture](docs/design/runtime/native-vhs/01-familiar.png)

![Actual 1884 × 1000 native Iced chat showing the pinned-route area; Secret Service is unavailable in this capture, so identity-gated controls are disabled.](docs/design/runtime/native-vhs/06-chat.png)

![Actual native Iced home with open scenery and icon-based feature strip, without the frog mage or gnome cutouts](docs/design/runtime/native-vhs/09-home.png)

![Actual native Iced group-call preview; media and sample messages are illustrative](docs/design/runtime/native-vhs/10-call.png)

![Actual 1884 × 1000 native Iced MLS screen describing the direct KeyPackage and Welcome session flow](docs/design/runtime/native-vhs/11-mls.png)

The MLS screen now detects authenticated committer equivocation. It verifies a
conflicting historical Commit against a saved OpenMLS epoch snapshot, stores
both Commit values in the encrypted database, and quarantines that group on
the device. Its accepted epoch remains intact, and reopening the group restores
the visible security alert. MLS message creation, event retries, member admission,
and Commit delivery or manual application are blocked until a recovery or rekey
flow is implemented. Regression coverage runs an exact redelivery and valid
conflict simultaneously through two independent SQLite connections; the group
ends quarantined at its accepted epoch without a transient lock failure.

The eleven design-board views and additional MLS screen are captured in [native-vhs](docs/design/runtime/native-vhs/).
These are a first implementation of the visual direction, with comparison
at 1280 × 800 and a compact 960 × 640 window. Exact visual parity,
accessibility, and live media integration remain to be completed.
The current direct transport and MLS recovery frames are specified in the
[v7 peer protocol](docs/fichas/transport/lan-peer-v7.md).

## Reproduce native captures

```sh
cargo run -- --screen 09-home
SLOUCHING_WINDOW_SIZE=1280x800 cargo run -- --capture-dir /tmp/slouching-captures
SLOUCHING_WINDOW_SIZE=960x640 cargo run -- --capture-dir /tmp/slouching-captures --capture-screen 01-familiar
```

The capture command renders all twelve screens, saves screenshots through
Iced's window screenshot API, and exits. Add `--capture-screen <slug>` to
capture one view, such as the familiar screen, instead of the full gallery. A tiling compositor may override
the requested window size; float/resize that window before the capture delay.
Set `SLOUCHING_CAPTURE_DELAY_MS` to extend the default six-second delay when
needed. `SLOUCHING_WINDOW_SIZE` only requests an initial size. The normal
default is a compact 1100 × 720 window.

Assets and font license/provenance notes are in [assets/README.md](assets/README.md).

## Architecture

- **UI:** Rust 2024, Iced 0.14.0 (pinned), wgpu renderer.
- **Local client core:** Rust owns local identity, cryptography, encrypted
  storage, peer transport, and media. The encrypted display profile and
  explicit Ed25519 key storage plus initial opaque encrypted-event storage
  are implemented. A pinned-device Iroh/QUIC LAN text exchange is available
  from the Iced UI with a persistent bidirectional session and per-peer history
  in SQLCipher. MLS application messages use the direct pinned Iroh/QUIC session with a
  local SQLCipher transcript, predecessor-epoch recipient snapshot, per-device
  ACK ledger, and retryable outbox. Membership Commit bytes are
  atomically journaled with group state; ordered direct delivery, per-device
  ACKs, predecessor recovery, and sequential multi-member fan-out over saved
  pinned routes are available. Helper delivery, offline delivery, and media
  remain in progress.
- **Server/backend:** Elixir in
  [`slouching-org/slouching-backend`](https://github.com/slouching-org/slouching-backend).
- **Current boundary:** loopback HTTP status and binary protobuf WebSocket
  handshake v1 and persistent Ping/Pong for development diagnostics. Authenticated production transport
  and functional APIs remain open design work.
- **Source of truth:** implemented backend and client-core state for identity,
  delivery, connections, capture, and calls. The UI must never invent them.

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
