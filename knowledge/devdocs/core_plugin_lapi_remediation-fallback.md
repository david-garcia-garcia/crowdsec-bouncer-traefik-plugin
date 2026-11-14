# LAPI remediation fallback

## Language

**Remediation fallback**:
The store letter (`lapiRemediationFallback`: ban, captcha, or not stored under ignore) the LAPI connection gives a decision type that is neither `ban` nor `captcha`.
_Avoid_: passthrough, whitelist, allow, failure action

## Overview

One opener knob on `lapi.Client` decides what LAPI ingest does with a type that is not `ban` or `captcha` (for example `throttle`), on stream New and Deleted (Ip, header-mapped scopes, Range) and on the live/none strongest pick. Spec: `core_plugin_lapi_remediation-fallback`. `ban` and `captcha` types never read it.

## How to use

- Read the value once in `lapi.New` from the opener config through `configuration.EffectiveLapiRemediationFallback` (empty is `ban`). Do not read it from a Bouncer or a subscriber.
- Map every LAPI type to a store letter with `ingestRemediationKind`. Treat an empty kind as not stored: skip the Put, the Range upsert, and the live pick.
- Gate every stream Deleted row with `deletedTypeClearsStore(type)`, Ip/header (`streamDeleteItem`) and Range alike. Under `ignore` an unknown-type delete is a no-op; under `ban` / `captcha` it clears the whole slot or CIDR.
- Rank live decisions with `strongestLiveDecision`: first ban by ingest kind, else first captcha. Under `ignore` an IP whose only rows are unknown types gets `NoBannedValue`.
- Keep the knob on both identities through `nonDefaultRemediationFallback` (`core_plugin_lapi_reclaim-key.md`). The default `ban` encodes as empty so pre-knob SessionHex and Redis keys survive an upgrade.
- Add a new value in three places together: the `LapiRemediationFallback*` constant, the `validateParamsRequired` enum, and the `ingestRemediationKind` / `deletedTypeClearsStore` switches.

## Pattern snippet

```go
kind := c.ingestRemediationKind(item.Type) // "t", "c", or "" under ignore
if kind == "" {
	return decisionstore.Decision{}, false // not stored
}
// Deleted path
if !c.deletedTypeClearsStore(item.Type) {
	return decisionstore.Decision{}, false // ignore: unknown-type delete is a no-op
}
```

## Key files

- `pkg/lapi/client_decisions.go` (`ingestRemediationKind`, `deletedTypeClearsStore`, `strongestLiveDecision`)
- `pkg/lapi/client_stream.go` (Range New and Deleted branches)
- `pkg/lapi/identity.go`, `pkg/lapi/session.go` (`nonDefaultRemediationFallback`)
- `pkg/configuration/configuration.go` (constants, default, enum)

## Gotchas

- Do not special-case a type name. `whitelist` and `allow` are not valid CrowdSec decision types and are an inadequate way to manage whitelists: the LAPI stream says WHAT TO BLOCK, not WHAT TO ALLOW. They follow the fallback like any unknown type and never lift a ban. Allowing traffic belongs to parser whitelists and LAPI allowlists (`cscli allowlists`), which stop or expire decisions at the source (`knowledge/research/ext_crowdsec_allowlists/`).
- It is not `bouncerLapiFailureAction` (LAPI unreachable). A live query failure still applies the failure action under any fallback.
- `captcha` needs no captcha instance. A stored captcha on a router without captcha WARNs and serves the ban page, like any LAPI captcha.
- Origin remap runs on the stored letter: an unknown type stored as captcha follows `captcha` edges (`core_plugin_lapi_origin-based-decision-remap.md`).
- The TRACE stem stays `handleStreamCache:unknownType`, with `type` and `fallback` attributes, also under `ignore`. Do not add an Info or Debug line.
- Vendor behavior (bouncer spec `remediation_fallback`, lua and firewall bouncers) is in `knowledge/research/ext_crowdsec_bouncers_remediation-fallback/`.
