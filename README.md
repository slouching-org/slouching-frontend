# Slouching frontend

This repository contains the first standalone visual slice of Slouching.
It has three navigable screens: home, familiar selection, and a clearly
labeled call layout preview. The original scene and avatar artwork is served
locally with the page. The eleven supplied screen exports are preserved in
[docs/design/screens](docs/design/screens).

**Current status:** static preview. It does not connect to peers, create keys,
send messages, or start a call. The separate Rust core scaffold is in
[`slouching-org/slouching-backend`](https://github.com/slouching-org/slouching-backend).
This static server does not proxy `GET /api/status` to the core, so the UI
shows it as unavailable even if the backend is running on its own port.

## Run

```sh
python3 -m http.server 3708 --bind 127.0.0.1
# open http://127.0.0.1:3708
```

The interface has no build step or third-party runtime dependency. It uses
local assets in `art/`, `avatars/`, and `brand/`. All documentation lives
under [docs/fichas](docs/fichas/README.md).
