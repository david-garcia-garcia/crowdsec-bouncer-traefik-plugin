# Explore
IssueKey: 2026-09-05-add-fail-mode

Measured: `go test ./pkg/crowdsecconnection/` passed (0.854s). No unit test asserts `UpdateMaxFailure` or stream-unhealthy ServeHTTP. Current fail-closed behavior is from reading `handleStreamTicker`, `queryLiveDecisions`, `AppsecQuery`, and `Bouncer.ServeHTTP` on dest `master` (4c07224). Not a reproduced product bug — a config-shape fight.

## Concepts

CrowdSec's remediation spec names one fallback enum per backend: `lapi_failure_action` and `appsec_failure_action`, values `passthrough` | `ban` | `captcha`, **default passthrough**. Sources: `knowledge/research/ext_crowdsec_bouncers_failure-action/` and `ext_crowdsec_appsec_protocol/`. This plugin does not expose those fields. It fail-closes with other knobs, and the defaults are the opposite of the spec.

```
Request
  │
  ├─ trusted IP / disabled → next (no LAPI, no AppSec)
  ├─ cache hit ban/captcha → remediate (even if stream later unhealthy)
  ├─ cache hit allow        → pass path (AppSec if enabled)
  └─ cache miss
        │
        ├─ stream/alone + StreamHealthy → pass path (unknown IP is allowed)
        ├─ stream/alone + unhealthy     → ban ReasonTECH (unknown IP fail-closed)
        └─ live/none LiveLookup error   → BannedValue → remediate (per request)
              │
              pass path
                └─ AppSec enabled
                      ├─ unreachable (dial / 502 / 503 / 504) → UnreachableBlock?
                      ├─ HTTP 500                              → FailureBlock?
                      ├─ unreadable HTTP/2 body                → UnreadableBodyBlock?
                      └─ any other non-200 (incl. protocol 403) → always ban
```

`UpdateMaxFailure` is a **stream poll counter**, not a fail-open/fail-closed enum. Default `0` marks unhealthy on the first failed poll (`updateFailure >= 0`). `-1` never marks unhealthy. When unhealthy, **cached bans and cached allows still apply**; only a cache miss fail-closes.

`StreamStartupBlock` is a **startup race** (serve before the first snapshot), not LAPI-down.

AppSec bools live on **Bouncer** (per router). `UpdateMaxFailure` lives on **CrowdsecConnection** identity (shared backend).

Official AppSec `500`/`401`/timeout share **one** `appsec_failure_action`. This plugin splits 500 vs unreachable vs unreadable-body, defaults all to block, and treats protocol `403` as a hard ban without reading the JSON `action` (out of scope for this ticket).

## Decisions

- Stop after this file. Caller: do not propose or implement until the fights below are named.
- Do not flip this plugin's fail-closed defaults to CrowdSec's passthrough without an explicit human yes.
- Do not parse AppSec `403` JSON in this change.
- Do not retarget `RedisCacheUnreachableBlock` unless the human expands scope.

## Open questions

- Q: Does `LapiFailMode` replace `UpdateMaxFailure`, or only name the action after the counter trips?
  Decision: assumed — wrap, do not delete. Keep `UpdateMaxFailure` as the stream/alone unhealthy counter. `LapiFailMode` is the ServeHTTP action on cache miss when unhealthy, and the LiveLookup error action. `-1` still means never unhealthy.
  By: explore

- Q: What happens in live mode, which has no counter and already returns `BannedValue` on any LAPI error?
  Decision: assumed — live uses `LapiFailMode` per request (no new counter). `passthrough` → treat the error as allow; `ban` → current `BannedValue`; `captcha` only if a captcha provider is configured, else validate as ban.
  By: explore

- Q: Does one `AppsecFailMode` replace `CrowdsecAppsecFailureBlock` + `CrowdsecAppsecUnreachableBlock`?
  Decision: assumed — replace those two booleans with one enum aligned to CrowdSec `appsec_failure_action` (`passthrough` | `ban` | `captcha`). Same action for HTTP 500 and unreachable. Keep `CrowdsecAppsecUnreadableBodyBlock` (different job: cannot buffer the body).
  By: explore

- Q: Which JSON key names and which enum strings?
  Decision: assumed — public keys `lapiFailMode` and `appsecFailMode` (caller `LapiFailMode` / `AppsecFailMode`). Values `passthrough` | `ban` | `captcha` to match CrowdSec, not a custom fail-open/fail-closed pair. Defaults stay this plugin's fail-closed: `ban` (not spec passthrough).
  By: explore

- Q: When stream is unhealthy, should `passthrough` skip AppSec too, or still call AppSec on the pass path?
  Decision: assumed — `LapiFailMode=passthrough` uses the existing pass path (`handleNextServeHTTP`), so AppSec still runs if enabled. AppSec has its own mode.
  By: explore

- Q: Who owns the new keys on reclaim — CrowdsecConnection identity vs per-router Bouncer?
  Decision: assumed — `LapiFailMode` on CrowdsecConnection identity (with `UpdateMaxFailure`). `AppsecFailMode` on Bouncer / `AppsecPolicy` (with the current AppSec booleans), not in identity, so two routers can disagree on AppSec fallback against one LAPI.
  By: explore
