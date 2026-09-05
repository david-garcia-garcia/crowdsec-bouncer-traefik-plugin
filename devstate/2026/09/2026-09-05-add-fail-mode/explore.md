# Explore
IssueKey: 2026-09-05-add-fail-mode

Measured: `go test ./pkg/crowdsecconnection/` passed (0.854s). No unit test asserts `UpdateMaxFailure` or stream-unhealthy ServeHTTP. Current fail-closed behavior is from reading `handleStreamTicker`, `queryLiveDecisions`, `AppsecQuery`, and `Bouncer.ServeHTTP` on dest `master` (4c07224). Not a reproduced product bug — a config-shape fight.

Human (2026-09-05): public concepts are `CrowdsecLapiFailureAction` and `CrowdsecAppsecFailureAction` (Crowdsec prefix, same as the rest of Config). The AppSec action converges/replaces the three AppSec block knobs.

## Concepts

CrowdSec's remediation spec names one fallback enum per backend: `lapi_failure_action` and `appsec_failure_action`, values `passthrough` | `ban` | `captcha`, **default passthrough**. This plugin's matching public keys are `CrowdsecLapiFailureAction` / `CrowdsecAppsecFailureAction`. Sources: `knowledge/research/ext_crowdsec_bouncers_failure-action/` and `ext_crowdsec_appsec_protocol/`.

```
                    ┌─────────────────────┐     ┌──────────────────────┐
                    │ CrowdsecLapi        │     │ CrowdsecAppsec       │
                    │ FailureAction       │     │ FailureAction        │
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

`CrowdsecAppsecFailureAction` replaces `CrowdsecAppsecFailureBlock`, `CrowdsecAppsecUnreachableBlock`, and `CrowdsecAppsecUnreadableBodyBlock`. Unreadable body is still "AppSec did not get a usable body," so it uses the same action: `ban`/`captcha` drop now; `passthrough` keeps today's headers-only GET.

`UpdateMaxFailure` stays a **stream poll counter**. `CrowdsecLapiFailureAction` is what happens after live error or stream-unhealthy cache miss. Cached bans/allows still apply when the stream is unhealthy.

`StreamStartupBlock` and `RedisCacheUnreachableBlock` stay out.

## Decisions

- Human accepted the sketch (2026-09-05). Remaining wrap/default/ownership rows are resolved.
- Public names: `CrowdsecLapiFailureAction` and `CrowdsecAppsecFailureAction` (human; Crowdsec prefix).
- `CrowdsecAppsecFailureAction` replaces all three AppSec block booleans (human).
- Do not flip this plugin's fail-closed defaults to CrowdSec's passthrough without an explicit human yes.
- Do not parse AppSec `403` JSON in this change.
- Do not retarget `RedisCacheUnreachableBlock` unless the human expands scope.

## Open questions

- Q: Does `LapiFailureAction` replace `UpdateMaxFailure`, or only name the action after the counter trips?
  Decision: resolved — wrap, do not delete. Keep `UpdateMaxFailure` as the stream/alone unhealthy counter. `CrowdsecLapiFailureAction` is the ServeHTTP action on cache miss when unhealthy, and the LiveLookup error action. `-1` still means never unhealthy.
  By: explore

- Q: What happens in live mode, which has no counter and already returns `BannedValue` on any LAPI error?
  Decision: resolved — live uses `CrowdsecLapiFailureAction` per request (no new counter). `passthrough` → treat the error as allow; `ban` → current `BannedValue`; `captcha` only if a captcha provider is configured, else validate as ban.
  By: explore

- Q: Does `CrowdsecAppsecFailureAction` replace the three AppSec block booleans?
  Decision: resolved — yes. `CrowdsecAppsecFailureBlock`, `CrowdsecAppsecUnreachableBlock`, and `CrowdsecAppsecUnreadableBodyBlock` go. One enum for 500, unreachable, and unreadable body.
  By: explore

- Q: Which JSON key names and which enum strings?
  Decision: resolved — keys `crowdsecLapiFailureAction` and `crowdsecAppsecFailureAction` (Go `CrowdsecLapiFailureAction`, `CrowdsecAppsecFailureAction`). Values `passthrough` | `ban` | `captcha`.
  By: human (2026-09-05) — Crowdsec prefix to match the rest of Config.

- Q: Default value — this plugin's fail-closed `ban`, or CrowdSec spec `passthrough`?
  Decision: resolved — `ban` so dest `master` does not silently flip to fail-open.
  By: explore

- Q: When stream is unhealthy, should `passthrough` skip AppSec too, or still call AppSec on the pass path?
  Decision: resolved — `CrowdsecLapiFailureAction=passthrough` uses the existing pass path (`handleNextServeHTTP`), so AppSec still runs if enabled.
  By: explore

- Q: Who owns the new keys on reclaim — CrowdsecConnection identity vs per-router Bouncer?
  Decision: resolved — `CrowdsecLapiFailureAction` on CrowdsecConnection identity (with `UpdateMaxFailure`). `CrowdsecAppsecFailureAction` on Bouncer / `AppsecPolicy`, not in identity.
  By: explore
