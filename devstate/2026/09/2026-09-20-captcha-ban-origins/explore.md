# Explore
IssueKey: 2026-09-20-captcha-ban-origins

## Concepts

**CaptchaBanOrigins**:
Public Traefik Config `[]string` (`json:"captchaBanOrigins"`). Empty default is a no-op. A LAPI `ban` whose metrics origin matches an entry is stored as captcha kind `c` instead of ban `t`.
_Avoid_: remapping at ServeHTTP, matching raw LAPI `origin` without `MetricsOrigin`, putting this list on the reclaim Open key

**Metrics origin (match key)**:
The string `MetricsOrigin(decision.Origin, decision.Scenario)` already used for Store origin and usage-metrics. CrowdSec `lists` plus scenario becomes `lists:<scenario>`. That is the string operators type in the list. Owner: `pkg/lapi.MetricsOrigin` (`pkg/lapi/client_metrics.go`).
_Avoid_: matching `decision.Origin` alone (upstream #369), reconstructing origin at lookup from scenario, a second rewrite

**lists prefix match**:
Config entry `lists` matches metrics origin `lists` and any `lists:<name>`. Entry `lists:<name>` matches only that list. Other entries (`CAPI`, `crowdsec`, `cscli`) are exact equality on the metrics origin.
_Avoid_: treating `lists:foo` as a prefix of other lists, a regex, a second origin vocabulary

**Remediation kind for a decision**:
One Client helper used by stream Ip/header (`streamPutItem`), stream Range (`client_stream.go` upsert), and live/none (`queryLiveDecisions` + `strongestLiveDecision`). Ban + match → `CaptchaValue`; ban + no match → `BannedValue`; captcha type stays captcha; unknown type stays empty (skip store).
_Avoid_: three copy-pasted switches, mapping in `pkg/bouncer`, changing `decisionscope.RemediationValue` globally

**Live strongest pick after remap**:
`strongestLiveDecision` today returns the first LAPI `Type=="ban"`. After remap, a listed-origin ban is captcha, so pick must use the remapped kind: first still-ban wins, else first captcha (same as upstream #369 `handleNoStreamCache` loop on `remediationForDecision == BannedValue`).
_Avoid_: remap after picking Type==ban (a CAPI ban would hide a later local `crowdsec` ban)

**First-create residue**:
`CaptchaBanOrigins` is copied onto `lapi.Client` at `New`. It MUST NOT join `SessionKey` / live `Key` (that would split the stream poller). A second router on the same cursor keeps the first Client's list, same class as `updateMaxFailure` / CAPI scenarios (`core_plugin_lapi_reclaim-key`).
_Avoid_: per-router ServeHTTP remap to dodge sharing, hashing the list into the Open key

Upstream: https://github.com/maxlerebourg/crowdsec-bouncer-traefik-plugin/pull/369 — `CaptchaBanOrigins` on Config, `remediationForDecision` on Bouncer, exact `decision.Origin` match, live + stream, empty default, unknown type stays empty. This fork cannot copy `bouncer.go` paths; apply lives in `pkg/lapi`. Per-list matching is the intentional delta.

```
LAPI decision (type, origin, scenario)
        │
        ▼
 MetricsOrigin(origin, scenario)     ← owner of lists:name
        │
        ▼
 kindForDecision(type, metricsOrigin, captchaBanOrigins)
        │
        ├── stream Put / Range upsert / live memo  → store letter t|c + origin
        └── live strongest pick                    → prefer still-t over remapped-c
```

## Decisions

- Dest is `origin/master` (fork `pkg/lapi` + `MetricsOrigin`), not `origin/main` (upstream layout). Prepare had dest `main`; explore retargeted.
- Helper on `lapi.Client`, not Bouncer. Config field on `configuration.Config` + `Client` field set in `New`.
- Match after `MetricsOrigin`. Do not match raw `decision.Origin`.
- Live/none remap the same helper; change `strongestLiveDecision` to remapped kind.
- No ValidateParams enum of origin names. Trim entries; drop blanks. Do not require `captchaProvider` (existing captcha→ban fallback).
- Do not put the list on the reclaim key.
- AppSec / failure-action captcha / ticker-stop remain out of scope.
- Mock e2e: add origin on mock LAPI (default `crowdsec`) and a `captcha-ban-origins` scenario including `lists:<name>` — this fork already has `tests/e2e/mock/`.

## Open questions

- Q: Who already owns the origin string used to decide captcha vs ban?
  Decision: resolved — `MetricsOrigin(decision.Origin, decision.Scenario)` at stream apply and live query (`pkg/lapi/client_metrics.go`, callers in `client_decisions.go` / `client_stream.go`). Remap uses that output. Do not re-derive from raw origin+scenario at lookup or ServeHTTP.
  By: explore

- Q: Must live/none remap ban→captcha the same way as stream?
  Decision: resolved — yes. Upstream #369 remaps in `handleNoStreamCache` and changes the live prefer-ban loop to the remapped kind. This fork's `queryLiveDecisions` / `strongestLiveDecision` / `memoLive` are the matching sites. Ticket stream wording does not exclude live; CAPI bans exist on live GET too.
  By: explore

- Q: Should ValidateParams reject unknown origin tokens?
  Decision: assumed — no. Upstream accepts any string. CrowdSec can add origins. Trim and ignore empty entries only.
  By: explore

- Q: Exact vs case-fold match for `CAPI` / `lists`?
  Decision: assumed — exact equality on the metrics origin (upstream `origin == decision.Origin`). The `lists` entry also matches a `lists:` prefix. `MetricsOrigin` already uses EqualFold only when rewriting the LAPI origin `lists`.
  By: explore

- Q: Can two routers sharing one Client have different CaptchaBanOrigins?
  Decision: assumed — no; first `New` wins (silent residue). Do not add the list to the Open key (would duplicate the stream ticker). Operators who need different maps need different LAPI sessions.
  By: explore

- Q: Does `lists` as a config entry match a decision whose MetricsOrigin stayed `lists` (empty scenario)?
  Decision: assumed — yes (`lists` equals `lists`, and also any `lists:` prefix).
  By: explore
