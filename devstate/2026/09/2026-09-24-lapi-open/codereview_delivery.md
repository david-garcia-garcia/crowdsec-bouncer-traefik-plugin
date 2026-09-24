# Delivery

## Motivation

The Traefik constructor already owns which legs Open. AppSec and captcha each expose a single `Open`. LAPI still exposes two reclaim entry points, and the constructor is the one that picks.

`openOwnedLeg` branches `LapiMode`: stream or alone calls `OpenStream`, otherwise `OpenLive`. Both already do the same reclaim Open — DecisionStore, `OwnershipKey`, `New`, hooks, `bindIdentity`. The only extra line on `OpenStream` is `noteStreamOwner`, and that helper already returns unless mode is stream or alone. `LapiMode` is already on the `Config` that `New` reads for the stream ticker, live lookup, and metrics.

Leaving the split means every production and test caller must choose an entry point that is not a consumer concern. The live catalog still names the pair as the current contract. Stream, live, none, and alone keep working; the leftover axis is a wrong constructor contract, not a runtime failure.

Priority: P3 — internal clarity with no current user or operator harm

## Implementation

One exported `lapi.Open` with the same signature as `appsec.Open` and `captcha.Open`. Its body is the former shared reclaim Open plus `noteStreamOwner` on every mode (still a no-op for live and none). `OpenStream` and `OpenLive` are removed; no aliases. The LAPI own-axis in the constructor is that one call and no longer reads `LapiMode` to pick an entry point. In-package tests retarget to `Open`; function names that still say OpenStream or OpenLive stay as scenario labels. The live LAPI connection and DecisionStore store leaves now promise `Open`. A debt note records an unrelated Windows range-index classification that already failed on dest.

## What this changes
**Operators.** None.
**Admin users.** None.
**Developers.** Callers and the live catalog must use one `lapi.Open`; `OpenStream` and `OpenLive` are gone.
**End users.** None.
