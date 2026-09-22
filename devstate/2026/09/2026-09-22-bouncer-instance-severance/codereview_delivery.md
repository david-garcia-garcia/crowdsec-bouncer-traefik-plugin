# Delivery

## Motivation
Each Traefik CrowdSec middleware `New` does three jobs at once: open a LAPI client (stream / live / none / alone), open an AppSec client when `crowdsecAppsecEnabled` is true, and bounce that router’s requests with those clients. Sharing already exists, but only as an identity hash (LAPI URL+key; AppSec listener+key+bodyLimit). There is no operator-chosen name.

Every bouncing router must copy the full LAPI/AppSec YAML. Create-time knobs are first-wins. `decisionScopeHeaders` unions into stream `scopes=` from whoever constructed first. Traefik does not guarantee constructor order, so a bouncing router can `New` before the middleware that opens the shared clients.

Left alone, operators cannot keep per-route bounce policy (remediation header, failure action, captcha, trusted IPs) while sharing one named LAPI/AppSec pair. They keep duplicating secrets and fetch knobs, and they cannot attach a subscriber-only route without also owning a backend.

Priority: P2 — real operator pain with a workaround (copy the full YAML on every router)

## Implementation
`plugin.go` severs the three jobs on one middleware: `crowdsecLapiEnabled` / `crowdsecAppsecEnabled` own a client (`Open` then `instance.PublishAll`); `enabled` plus a set instance name subscribes. `pkg/instance` holds two process-wide slot tables (LAPI vs AppSec). Publish fans out into Yaegi-safe `atomic.Value`s; Subscribe never waits. The bouncer `ServeHTTP` only Loads those fields. Ownership Open is the middleware name plus that client’s knobs (`lapi.OwnershipKey`, AppSec `Key(cfg, name)`); DecisionStore stays `SessionHex`. `streamStartupBlock` is a request-path published check, not a wait in `New` or `startStream`. A taken name rejects under one mutex and rolls back any slot that attempt already wrote; subscribers do not Bind reclaim.

## What this changes
**Operators.** Existing installs must set `crowdsecLapiEnabled: true` on every middleware that opens LAPI (default is false, so an unchanged YAML stops owning LAPI). `crowdsecMode: appsec` is rejected; AppSec-only is `crowdsecLapiEnabled: false` plus `crowdsecAppsecEnabled: true`. They can publish and subscribe with `crowdsecLapiInstanceName` / `crowdsecAppsecInstanceName`, set opener-only `crowdsecLapiStreamScopes`, and optionally `reclaimGraceSeconds`. `streamStartupBlock: true` now returns 503 until subscribed clients are published, not until the first stream poll. Watch `crowdsec instance name taken`, `crowdsec lapi stream collision`, `crowdsec bouncer backend missing`, and lifecycle `crowdsec lapi/appsec instance started|sleeping|waking|closed` plus `crowdsec bouncer bound|unbound`.
**Admin users.** None.
**Developers.** Public config adds `crowdsecLapiEnabled`, instance names, `crowdsecLapiStreamScopes`, and `reclaimGraceSeconds`; drop `AppsecMode`. `bouncer.New` no longer takes `*lapi.Client` / `*appsec.Client` — clients arrive via `LAPIBinding` / `AppSecBinding`. LAPI Open uses `OwnershipKey`; AppSec Open key includes the middleware name. Stream `scopes=` is the opener list, not a live header-map union. Two middleware names on the same `SessionHex` may share a DecisionStore and are two Clients. A second stream owner on the same host+key logs WARN and still succeeds `New`.
**End users.** None.

## Stored data model
**Changed**
- DecisionStore `SessionHex` field `defaultDecisionSeconds` (int64): sample `60` → `5` forks the store (I2). Upgrade: old keys not rewritten; next Open uses the new hash.
- DecisionStore `SessionHex` field `streamScopes` (string list, stream mode only): omitted/empty both hash as `ip,range`; extras such as `country` change the hex. Upgrade: old keys not rewritten; new store sends `startup=true`.
- DecisionStore `SessionHex` field `redis` (object: `host`, sorted `readHosts`, `password`, `database`): hashed only when `redisCacheEnabled` is true. Sample when false: leftover host `redis:6379` and password `secret` keep the same hex (S1). Sample when true: host `redis-a:6379` → `redis-b:6379` is a new store (S3). Upgrade: old keys not rewritten; leftover Redis fields no longer fork a disabled cache.

## Findings
None.
