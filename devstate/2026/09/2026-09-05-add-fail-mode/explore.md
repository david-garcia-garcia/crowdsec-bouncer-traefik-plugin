# Explore
IssueKey: 2026-09-05-add-fail-mode

Measured: `go test ./pkg/crowdsecconnection/` passed (0.854s). No unit test asserts `UpdateMaxFailure` or stream-unhealthy ServeHTTP. Current fail-closed behavior is from reading `handleStreamTicker`, `queryLiveDecisions`, `AppsecQuery`, and `Bouncer.ServeHTTP` on dest `master` (4c07224). Not a reproduced product bug — a config-shape fight.

Human (2026-09-05): public concepts are `LapiFailureAction` and `AppsecFailureAction`. The AppSec action converges/replaces the three AppSec block knobs.

## Concepts

CrowdSec's remediation spec names one fallback enum per backend: `lapi_failure_action` and `appsec_failure_action`, values `passthrough` | `ban` | `captcha`, **default passthrough**. This plugin's matching public keys are `LapiFailureAction` / `AppsecFailureAction`. Sources: `knowledge/research/ext_crowdsec_bouncers_failure-action/` and `ext_crowdsec_appsec_protocol/`.

```
                    ┌─────────────────────┐     ┌──────────────────────┐
                    │ LapiFailureAction   │     │ AppsecFailureAction  │
                    │ passthrough|ban|    │     │ passthrough|ban|     │
                    │ captcha             │     │ captcha              │
                    └──────────┬──────────┘     └──────────┬───────────┘
                               │                           │
         live LAPI error       │                           │  HTTP 500
         stream unhealthy miss │                           │  dial / 502 / 503 / 504
                               │                           │  unreadable HTTP/2 body
                               ▼                           ▼
                      apply that action              apply that action
                               │                           │
                               │                           │  not this enum:
                               │                           │  AppSec 200 allow
                               │                           │  AppSec 403 verdict (still out of scope)
                               │                           │  RedisCacheUnreachableBlock
                               │                           │  StreamStartupBlock
                    ┌──────────┴──────────┐
                    │ UpdateMaxFailure    │  still the stream *when*
                    │ (counter, not the   │  -1 never unhealthy
                    │  action)            │  0 = first failed poll
                    └─────────────────────┘
```

`AppsecFailureAction` replaces `CrowdsecAppsecFailureBlock`, `CrowdsecAppsecUnreachableBlock`, and `CrowdsecAppsecUnreadableBodyBlock`. Unreadable body is still "AppSec did not get a usable body," so it uses the same action: `ban`/`captcha` drop now; `passthrough` keeps today's headers-only GET.

`UpdateMaxFailure` stays a **stream poll counter**. `LapiFailureAction` is what happens after live error or stream-unhealthy cache miss. Cached bans/allows still apply when the stream is unhealthy.

`StreamStartupBlock` and `RedisCacheUnreachableBlock` stay out.

## Decisions

- Stop after explore until the remaining assumed rows are accepted.
- Public names: `LapiFailureAction` and `AppsecFailureAction` (human).
- `AppsecFailureAction` replaces all three AppSec block booleans (human).
- Do not flip this plugin's fail-closed defaults to CrowdSec's passthrough without an explicit human yes.
- Do not parse AppSec `403` JSON in this change.
- Do not retarget `RedisCacheUnreachableBlock` unless the human expands scope.

## Open questions

- Q: Does `LapiFailureAction` replace `UpdateMaxFailure`, or only name the action after the counter trips?
  Decision: assumed — wrap, do not delete. Keep `UpdateMaxFailure` as the stream/alone unhealthy counter. `LapiFailureAction` is the ServeHTTP action on cache miss when unhealthy, and the LiveLookup error action. `-1` still means never unhealthy.
  By: explore

- Q: What happens in live mode, which has no counter and already returns `BannedValue` on any LAPI error?
  Decision: assumed — live uses `LapiFailureAction` per request (no new counter). `passthrough` → treat the error as allow; `ban` → current `BannedValue`; `captcha` only if a captcha provider is configured, else validate as ban.
  By: explore

- Q: Does `AppsecFailureAction` replace the three AppSec block booleans?
  Decision: resolved — yes. `CrowdsecAppsecFailureBlock`, `CrowdsecAppsecUnreachableBlock`, and `CrowdsecAppsecUnreadableBodyBlock` go. One enum for 500, unreachable, and unreadable body.
  By: explore

- Q: Which JSON key names and which enum strings?
  Decision: resolved — keys `lapiFailureAction` and `appsecFailureAction` (Go `LapiFailureAction`, `AppsecFailureAction`). Values `passthrough` | `ban` | `captcha`.
  By: explore

- Q: Default value — this plugin's fail-closed `ban`, or CrowdSec spec `passthrough`?
  Decision: assumed — `ban` so dest `master` does not silently flip to fail-open.
  By: explore

- Q: When stream is unhealthy, should `passthrough` skip AppSec too, or still call AppSec on the pass path?
  Decision: assumed — `LapiFailureAction=passthrough` uses the existing pass path (`handleNextServeHTTP`), so AppSec still runs if enabled.
  By: explore

- Q: Who owns the new keys on reclaim — CrowdsecConnection identity vs per-router Bouncer?
  Decision: assumed — `LapiFailureAction` on CrowdsecConnection identity (with `UpdateMaxFailure`). `AppsecFailureAction` on Bouncer / `AppsecPolicy`, not in identity.
  By: explore
