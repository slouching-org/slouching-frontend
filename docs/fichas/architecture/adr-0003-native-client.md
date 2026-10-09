# ADR 0003 — Rust/Iced is the product client

**Status:** accepted; reflects the owner's original architecture
document and current correction.

## Context

The complete architecture PDF specifies Rust/Iced for the client,
Rust for its local core, and Elixir for the server/backend. The first frontend repository instead placed
a JavaScript visual preview at the root without saying it was a
temporary prototype.

## Decision

Build the product desktop frontend in Rust/Iced. Keep the JavaScript
screens only under `prototypes/web/` as visual reference. The native
UI must read real identity, membership, delivery, network, and media state
from their implementing components through reviewed contracts. Its present
Elixir loopback HTTP status call is only a development diagnostic.

## Consequences

Recreate and validate the supplied eleven screens in Iced. Plan
video rendering with wgpu, accessibility, device permissions, and
native packaging. The web prototype can guide visual comparison but
cannot be used to claim working encryption, P2P, or calls.
