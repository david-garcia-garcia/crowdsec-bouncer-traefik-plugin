# Delivery

## Motivation

Every Traefik CrowdSec middleware constructor used to open LAPI and AppSec and bounce the same router. Sharing one LAPI stream meant every bouncing router duplicated LAPI and AppSec YAML, and implicit reclaim identity tied `createdBy` to the Traefik middleware name rather than an operator-chosen instance. Operators running several routers against one CrowdSec stream could not designate one opener with secrets and have the rest subscribe by name without copying keys or racing constructor order.

Priority: P2 — real operator pain reconfiguring shared clients; no data loss but heavy YAML duplication and fragile startup order.

## Implementation

Public config is split into `lapi*`, `appsec*`, and `bouncer*` domains with enable flags and instance names. `plugin.New` Opens and publishes into `pkg/instance` when secrets are present, subscribes by name when enabled without secrets, or skips legs when disabled. `bouncerHold` returns a 503 holder without bouncing. The bouncer resolves clients per request via Peek (with construct fallback for openers), applies failure actions on miss, and keeps scope registration on the LAPI opener only.

## What this changes
**Operators.** Must migrate YAML to new key names (`lapiKey`, `bouncerEnabled`, `lapiInstance`, etc.); may use one opener plus named subscribers or optional hold routers instead of duplicating LAPI/AppSec secrets on every bouncing middleware.

**Admin users.** None.

**Developers.** Traefik plugin config JSON tags and semantics are breaking (beta); named-instance Peek/publish contract and removed `appsec` `lapiMode` are the main integration surface.

**End users.** None unless operators misconfigure subscribe/hold (requests may passthrough or 503 on hold routers).

## Stored data model
None.

## Findings
[P2] Breaking YAML rename is intentional beta; upgrade requires rewriting middleware blocks, not aliases.
