# Direct LAN text transport v1

This is a bounded client-only experiment for exchanging one text frame between
two manually paired Rust clients on a reachable LAN. The Elixir HTTP/WebSocket
diagnostics and their protobuf handshake are not involved.

## Identity and channel

Each Iroh endpoint uses the existing local Ed25519 device identity seed. Iroh's
`SecretKey` and the device key derive the same public bytes, so the Iroh
`EndpointId` is the device public key. The sender supplies the expected
`EndpointId` when dialing. The listener checks the authenticated incoming
`remote_id` against its configured expected device before opening a data stream.
Both devices therefore need the other's public key pinned out of band.

Iroh QUIC uses TLS channel encryption and authenticates the endpoint key. This
is pairwise transport authentication based on manually supplied public keys;
it does not establish contact trust, a verified roster, or an MLS membership.
The endpoint is configured with Iroh's minimal crypto preset and relay mode
disabled. A caller supplies a direct socket address; there is no relay or
address lookup in this slice.

## Stream framing

ALPN: `org.slouching.text/1`.

Each QUIC bidirectional stream carries one frame:

| Field | Size | Encoding |
| --- | ---: | --- |
| Marker | 4 bytes | ASCII `SLTX` |
| Version | 2 bytes | Unsigned big-endian integer, currently `1` |
| Text length | 4 bytes | Unsigned big-endian UTF-8 byte count |
| Text | 1–16,384 bytes | Valid UTF-8 |

The receiver returns one frame on the same stream containing an acknowledgement
with the received UTF-8 byte count. The sender confirms that receipt on a
versioned `SLAR` uni stream; the receiver then sends a versioned `SLAF` final
acknowledgement on a second uni stream. Both sides validate these control
frames before reporting success. Unknown versions, malformed UTF-8, empty text,
and lengths above 16 KiB are rejected. The listener accepts one connection and
one text frame, then exits.

## Running the two-client check

Create an identity on each device in the Familiar screen and exchange the
displayed public-key hex values out of band. On device A:

```sh
cargo run -- --lan-listen 45873 --expect-peer <DEVICE_B_PUBLIC_KEY_HEX>
```

Find A's LAN IPv4 address with `ip -4 addr`. On device B:

```sh
cargo run -- --lan-send 192.168.1.20:45873 --expect-peer <DEVICE_A_PUBLIC_KEY_HEX> --text 'hello from the crew'
```

Both machines need to allow the selected UDP port on their local networks. The
automated `cargo test --test peer_process` test launches separate operating
system processes, performs a successful exchange, and checks rejection when
the listener pins another device key.

## Limits

This does not create an MLS credential, KeyPackage, or group. It does not use
the MLS binding primitive, create a durable peer roster, persist the delivered
text, update the illustrative chat UI, retry delivery, work for offline peers,
discover addresses, traverse NAT, or fall back to a relay. It must not be
described as cross-NAT ready or as product MLS messaging.
