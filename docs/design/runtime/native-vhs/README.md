# Actual Iced runtime captures

Captured from the native Rust/Iced window at 1280 × 800 pixels with its
window screenshot API. Every numbered image corresponds to the supplied
design-board view. These are rendered widgets and source assets, not screen
PNGs pasted into an app. `compact/` keeps representative 960 × 640 captures.

The window gallery, familiar selection, preview fields, tabs, and texture
control work locally. The familiar screen now persists the display name and
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

These captures show only the native UI. The separate encrypted event-journal
storage primitives are not connected to the screens, MLS, or delivery and do
not enable chat.

Opening the encrypted database composes OpenMLS RustCrypto with its versioned
SQLite storage schema through the same SQLCipher connection. No MLS client
state, credentials, key packages, or groups are created yet.

The storage test uses a temporary SQLCipher database, confirms that opening it
twice preserves the OpenMLS schema, and composes the RustCrypto and SQL
providers to save and reload an MLS signature key. It creates no product MLS
credential or group.

The familiar-screen capture was refreshed after adding the core's signed
device-to-MLS key binding primitive. The chat capture was refreshed with the
persistent direct-LAN session UI. This capture's system Secret Service is
unavailable, so the identity action is shown and sending/listening are gated.
The key binding primitive is not connected to MLS credentials or peer
verification.

The home view keeps the supplied night scenery and call controls, with an
icon-based feature strip. Its frog mage and gnome foreground cutouts have been
removed to keep the scene open.

Reproduce with `cargo run -- --capture-dir /tmp/slouching-captures`.
Request a size with `SLOUCHING_WINDOW_SIZE=1280x800`; a tiling compositor may
need this window floated and resized before the six-second capture delay;
`SLOUCHING_CAPTURE_DELAY_MS` can extend the delay.
The command visits all eleven views and exits after saving them.
Use `cargo run -- --capture-dir /tmp/slouching-captures --capture-screen 01-familiar` to capture one view at the requested size.
