# Actual Iced runtime captures

Captured from the native Rust/Iced window with its
window screenshot API. Every numbered image corresponds to the supplied
design-board view. These are rendered widgets and source assets, not screen
PNGs pasted into an app. `compact/` keeps representative 960 × 640 captures.

The window gallery, familiar selection, preview fields, tabs, texture
control, and local MLS group invitation flow work locally. The familiar screen now persists the display name and
familiar using SQLCipher encrypted SQLite with a key in the system credential
store. A missing credential store appears as an unavailable state; no
plaintext fallback is used. A separate explicit action creates and stores an
Ed25519 device signing seed in the credential store and displays its public
key as unverified. Fingerprint derivation and contact pairing are not
implemented. When the keyring cannot be read, the screen explains the failure
and offers a safe retry that does not replace an existing key. All scenes,
messages, and comparison words are marked as illustrative. No peer route,
media capture, messaging, or call is established by these images.
Exact parity and accessibility remain open.

The MLS screen lets two devices manually exchange a public KeyPackage,
Welcome, and ratchet tree through a separately trusted channel. Joined devices
send encrypted MLS messages over their active pinned Iroh/QUIC session. The
receiver persists the ratchet update and transcript before ACK. The group view
lists locally saved group IDs, epochs, and quarantine state so a group and its
transcript can be reopened from SQLCipher. It displays a persistent security
banner when authenticated committer
equivocation has quarantined a group; MLS sends, retries, and Commit delivery
are disabled for that group.

The screen also supports signed member self-update proposals sent to the
designated committer over the active pinned peer session. The committer checks
the MLS author against the transport peer, authenticates and stores the
proposal before ACK, then creates a Commit for the existing per-member
delivery flow. Copy/paste over a separately trusted channel remains available.
This path currently handles self-updates only; other proposal types and
approval controls are not implemented.

Opening the encrypted database composes OpenMLS RustCrypto with its versioned
SQLite storage schema through the same SQLCipher connection. The Rust core
persists MLS signing keys and groups, creates device-bound KeyPackages, admits
members, processes Welcome messages, and encrypts/decrypts events transactionally
with the journal. The group setup flow is now exposed as an additional native
screen; the original eleven design-board views remain available.

Storage tests use temporary SQLCipher databases to check OpenMLS migrations,
device-bound group admission, encrypted messaging, signed self-update proposal
authentication and deduplication, transactional proposal Commits, ordered
Commit recovery, and authenticated conflicting Commits. The equivocation test confirms that the
valid conflicting Commit is verified against a saved historical epoch, evidence
and quarantine persist, the accepted epoch is unchanged, and outbound MLS
messages are blocked. It also races an exact redelivery against that conflict
through independent database connections and verifies the same durable result.

The familiar-screen capture was refreshed after adding the core's signed
device-to-MLS key binding primitive. The chat capture now shows the per-peer
SQLCipher history UI. The capture's Secret Service is unavailable, so the
identity action is shown and sending/listening are gated; no conversation data
is present. The UI also offers confirmed deletion of one peer's local history.
The key binding primitive does not verify contacts or provide pairing.

The home view keeps the supplied night scenery and call controls, with an
icon-based feature strip. Its frog mage and gnome foreground cutouts have been
removed to keep the scene open.

Reproduce with `cargo run -- --capture-dir /tmp/slouching-captures`.
Request a size with `SLOUCHING_WINDOW_SIZE=1280x800`; a tiling compositor may
need this window floated and resized before the six-second capture delay;
`SLOUCHING_CAPTURE_DELAY_MS` can extend the delay.
The command visits all twelve views and exits after saving them.
Use `cargo run -- --capture-dir /tmp/slouching-captures --capture-screen 01-familiar` to capture one view at the requested size.
