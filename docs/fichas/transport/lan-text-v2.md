# Direct LAN text transport v2

This client-only flow provides a persistent direct text session between two
Rust clients on a reachable LAN. The Iced chat screen exposes pin, listen,
connect, send, disconnect, and session transcript controls. Elixir HTTP and
WebSocket diagnostics and their protobuf handshake are not involved.

## Identity and channel

Each Iroh endpoint uses the existing local Ed25519 device identity seed. Iroh's
`SecretKey` and the device key derive the same public bytes, so the Iroh
`EndpointId` is the device public key. The dialing side supplies the expected
`EndpointId`; the listener checks the authenticated incoming `remote_id` before
opening the application stream. Both devices pin the other's public key out of
band.

Iroh QUIC provides encrypted transport and endpoint-key authentication. This is
pairwise transport authentication based on manually supplied keys; it does not
establish contact trust, a verified roster, or MLS membership. Relay mode is
disabled and callers supply direct socket addresses.

## Session framing

ALPN: `org.slouching.text/2`. One QUIC bidirectional stream remains open for the
session. Each frame has a 19-byte header followed by a payload when present:

| Field | Size | Encoding |
| --- | ---: | --- |
| Marker | 4 bytes | ASCII `SLCH` |
| Version | 2 bytes | Unsigned big-endian integer, `2` |
| Kind | 1 byte | DATA=1, ACK=2, CLOSE=3, CLOSE_ACK=4 |
| Sequence | 8 bytes | Unsigned big-endian, monotonic per direction |
| Payload length | 4 bytes | Unsigned big-endian byte count |
| DATA payload | 1–16,384 bytes | Valid UTF-8 |

Empty and oversized DATA, invalid UTF-8, unknown types or versions, invalid
sequence order, nonempty ACK bodies, and unsolicited ACKs terminate the session.
ACK carries the DATA sequence and no payload. A receiver sends ACK after adding
the message to its in-memory transcript. ACK confirms acceptance into memory,
not that the user read it. Each direction allows at most 16 pending messages;
writes are serialized. CLOSE and CLOSE_ACK provide explicit shutdown. Pending
sends without ACK at disconnect have unknown delivery status and are never
replayed automatically.

## Using the Iced app on a LAN

Create an identity on each device and exchange the displayed public keys out of
band. Linux needs an available Secret Service for the device identity. Start
the app on both devices and pin the other device's key on both.

On the receiving device, choose a UDP port and click **Aguardar peer**. Share a
displayed LAN endpoint address and port. On the sending device, enter that
address, type the first message, and click **Conectar e enviar**. After the
session connects, either side can send more messages over the same connection;
incoming messages appear live. **Desconectar sessão** ends it. A new session can
be started by either side. The transcript is session-only and is cleared when
the app closes.

Allow the selected UDP port through each device's local firewall. Wildcard
addresses such as `0.0.0.0` cannot be shared. If no LAN address is announced,
inspect the machine's network interfaces.

## Automated checks

`cargo test --test peer_process` launches separate operating system processes.
It exchanges multiple messages in both directions on one connection, checks
wrong-pin rejection before accepting application text, and disconnects while a
send is pending to verify the delivery status remains unknown.

## Limits

This does not create MLS credentials, KeyPackages, groups, or product messaging.
It does not persist messages, retry delivery, support offline peers, discover
addresses, traverse NAT, or fall back to a relay. It is direct-LAN-only pinned
device transport, not trusted contact pairing or cross-NAT messaging.

The older `--lan-listen` and `--lan-send` command-line smoke helpers remain
available for diagnostics. The supported user-facing flow is in the Iced app.
