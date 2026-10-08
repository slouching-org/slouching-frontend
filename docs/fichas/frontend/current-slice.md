# Current frontend slice

**Status:** local visual preview.

The home, familiar-selection, and call-layout screens use the owner's
nighttime fantasy assets. The walking pair of wizards is the primary
pictorial logo; the hat is only a small icon/placeholder. The current UI
stores a preview display name and familiar in browser local storage. It
does not create a cryptographic identity.

The call screen displays illustrative scenes with a visible
`SEM CONEXÃO · PRÉVIA` badge. Its buttons change visual state only.
No camera, microphone, messaging, peer transport, or MLS is implemented
in this repository. The `/api/status` integration point reports a local
core if one is present; otherwise the footer says it is unavailable.

The [eleven source screens](../../design/screens) define the broader
frontend target. Future functionality must use authoritative state from
the peer core and preserve the explicit failure/permission states.
