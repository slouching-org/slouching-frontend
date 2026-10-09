# Actual Iced runtime captures

Captured from the native Rust/Iced window at 1280 × 800 pixels with its
window screenshot API. Every numbered image corresponds to the supplied
design-board view. These are rendered widgets and source assets, not screen
PNGs pasted into an app. `compact/` keeps representative 960 × 640 captures.

The window gallery, familiar selection, preview fields, tabs, and texture
control work locally. All scenes, messages, and comparison words are marked
as illustrative. No identity, peer route, capture, messaging, or call is
established by these images. Exact parity and accessibility remain open.

Reproduce with `cargo run -- --capture-dir /tmp/slouching-captures`.
Request a size with `SLOUCHING_WINDOW_SIZE=1280x800`; a tiling compositor may
need this window floated and resized before the six-second capture delay.
The command visits all eleven views and exits after saving them.
