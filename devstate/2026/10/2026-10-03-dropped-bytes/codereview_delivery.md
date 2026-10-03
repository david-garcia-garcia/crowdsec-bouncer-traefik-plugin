# Delivery

## Motivation

This plugin already posts `dropped` / `request` to CrowdSec LAPI usage-metrics on each remediating drop. Official firewall bouncers also post a `dropped` item whose unit is `byte`. Operators who run `cscli metrics show bouncers` compare those tables.

A ban, unsolved captcha, or AppSec envelope only increments the request series (origin, `ip_type`, remediation). The window never carries a `dropped` / `byte` item, so this plugin reports how many requests it remediates and not how much inbound request weight those drops represent.

Left alone, request counts stay correct, but the table stays incomparable with firewall bouncers that already report bytes. Operators have no signal for remediating request weight from this plugin.

Priority: P2 — real operator pain, with a workaround or limited blast radius

## Implementation

At drop time, `recordDropped` takes the inbound request and increments both series: existing `IncDropped` (unit `request`, may label `remediation`) then `IncDroppedBytes` with `EstimatedSize()` (unit `byte`, labels `origin` + `ip_type` only).

`EstimatedSize` sums the live request-target, the server-lifted Host field, each Header map key once plus each value, and declared `ContentLength` when `>= 0` capped at 50 MiB (`50 * 1024 * 1024`). It does not read `Body` and does not reconstruct a wire image. `ContentLength == -1` adds nothing for the body.

Byte window keys share the same counters map; `unit` distinguishes the item. Adds and failed-POST restore saturate at MaxInt64; a zero delta does not create a byte key. Request `+=` and processed atomics stay wrapping.

## What this changes
**Operators.** `cscli metrics show bouncers` now shows a second `dropped` row with unit `byte` (`origin` + `ip_type`) beside the existing request row; no new deploy key.
**Admin users.** None.
**Developers.** Remediating drops must also increment `IncDroppedBytes` from `EstimatedSize()`; the byte item omits `remediation`; those window keys saturate at MaxInt64.
**End users.** None.
