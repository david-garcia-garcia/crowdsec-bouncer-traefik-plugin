# Explore

Problem this run covers: when `bouncerRemediationHeadersCustomName` is set, Traefik JSON access logs (`downstream_<Name>`) only see a kind token (`ban`, `captcha`, `solved-captcha`, `error:client-disconnected`, or a raw AppSec `action`). Desired: structured `kind:reason` / `kind:reason:origin` from the closed vocabulary in `requirement.md` Desired. Pass/bypass/trusted/passthrough/503 stay absent. No new config key. Header still off when the name is empty.

## Concepts

Units this change would touch:

- `Bouncer.handleBanServeHTTP` — `pkg/bouncer/bouncer.go` — one writer for every operator ban page. Today `Header().Set(..., "ban")` whenever `remediationCustomHeader` is non-empty. `reason` is the ban-template `RemediationReason`; `origin` feeds `recordDropped` only. Desired splits this writer into `ban:decision-header` / `ban:lapi` / `ban:lapi:<origin>` / `ban:lapi-failure` / `ban:stream-unhealthy` / `ban:cache-fail` / `ban:unparseable-request` / `ban:appsec` / `ban:appsec-challenge-empty` / `ban:appsec-failure` / `ban:captcha-downgrade`.
- `Bouncer.handleRemediationServeHTTP` — `pkg/bouncer/bouncer.go` — captcha kind: unsubscribed / unpublished / `!Valid` fall through to `handleBanServeHTTP` (today still `"ban"`; Desired `ban:captcha-downgrade`). Usable client: `ServeHTTP` / `WriteSolvedRedirect` with this router's header **name**. Widget-asset and valid-cookie origin: `handleNextServeHTTP` (no header; Out of scope).
- `Bouncer.handleAppsecResponseServeHTTP` — `pkg/bouncer/bouncer.go` — copies `decision.Action` as the header (`captcha`, `challenge`, or any other non-allow that reached relay). Desired `captcha:appsec` / `captcha:challenge` / unknown → see Open questions.
- `Bouncer.handleClientDisconnectedServeHTTP` — `pkg/bouncer/bouncer.go` — const `error:client-disconnected`. Desired keeps that exact string.
- `Bouncer.applyAppsecServeHTTP` / `applyLapiFailureAction` / `banOrWarnForcedCaptcha` / `forcedDecisionKind` — pick kind + metrics origin, then call the writers above. Plugin origins already exist (`pkg/lapi/client_metrics.go` `OriginPlugin*`).
- `captcha.Client.ServeHTTP` / `WriteSolvedRedirect` / `writeRemediationHeader` — `pkg/captcha/captcha.go` — challenge page hardcodes `"captcha"`; Pass 302 and second-tab 302 hardcode `"solved-captcha"`. Client does not store the header name (already on the Bouncer call site).
- `configuration.Config.BouncerRemediationHeadersCustomName` — `pkg/configuration/configuration.go` — string; default `""` disables. No other public key names this response header. Out of scope: new keys.
- `lapi.MetricsOrigin` / `resolveDroppedOrigin` — third field owner for LAPI hits. CrowdSec `lists` + scenario is already `lists:<scenario>` on the metrics label; header rewrite is `lists:` → `lists_` only. Intern overflow / letter-only Range yield empty origin (`ban:lapi` / `captcha:lapi`).
- README “See the verdict in access logs” + `BouncerRemediationHeadersCustomName` — old tokens. Live specs name `solved-captcha` and `error:client-disconnected`. Tests pin the old strings (list under Decisions / Open questions).

```
ServeHTTP
  ├── disabled / trusted / startup 503 / bypass / remap-to-pass / widget / gate-cookie GET
  │         └── next  (no remediation header)     ← Out of scope
  ├── GetRemoteIP err / ipAddr nil
  │         └── handleBanServeHTTP                ← ban:unparseable-request
  ├── forced header b
  │         └── handleRemediationServeHTTP ban    ← ban:decision-header
  ├── LAPI lookup / live
  │         ├── ban  → handleBanServeHTTP         ← ban:lapi[:origin]
  │         └── captcha → handleRemediationServeHTTP
  ├── LAPI unpublished / live fail
  │         └── applyLapiFailureAction            ← ban|captcha :lapi-failure
  ├── stream miss + unhealthy
  │         └── applyLapiFailureAction            ← ban|captcha :stream-unhealthy
  ├── cache fail-closed
  │         └── handleBanServeHTTP                ← ban:cache-fail
  └── handleNextServeHTTP → AppSec
            ├── unpublished / Query err / ErrFailureCaptcha
            │     └── ban|captcha :appsec-failure
            ├── ErrClientDisconnected             ← error:client-disconnected
            ├── action ban                        ← ban:appsec
            ├── action challenge + empty body     ← ban:appsec-challenge-empty
            ├── action challenge + body           ← captcha:challenge (relay)
            └── action captcha                    ← captcha:appsec (relay)

handleRemediationServeHTTP (captcha kind)
  ├── !subscribeCaptcha / client nil / !Valid     ← ban:captcha-downgrade
  ├── custom resource / Check-true GET            ← next (no header)
  ├── Check-true form POST                        ← captcha:solved (WriteSolvedRedirect)
  └── ServeHTTP challenge / Pass 302              ← captcha:<reason>[:origin] / captcha:solved
```

Call sites that matter (roots searched: worktree `pkg/**/*.go`, `zzz_*.go`, `tests/e2e/**`, `openspec/specs/**`, `README.md`):

- `handleBanServeHTTP(`: **1** definition; **9** production calls in `pkg/bouncer/bouncer.go` (lines 390, 462, 467, 653, 658, 705, 723, 731, 735); **5** direct test calls (`pkg/bouncer/zzz_bouncer_test.go` ×3, `pkg/bouncer/zzz_ban_template_test.go` ×2). All inherit one `Header().Set`.
- `captcha.Client.ServeHTTP(`: **1** production caller (`handleRemediationServeHTTP`); **10** test callers in `pkg/captcha/zzz_*.go` (most pass empty header name).
- `WriteSolvedRedirect(`: **1** production caller; **1** test (`pkg/captcha/zzz_routing_test.go`).
- `handleAppsecResponseServeHTTP` `decision.Action` header: **1** Set.
- `handleClientDisconnectedServeHTTP`: **1** Set of the existing const.

Identity: this header does not emit client address, user, tenant, Host, or trust hop. Ban-template `ClientIP` stays `req.remoteIP` from `pkg/ip.GetRemoteIP`. AppSec `Query` already takes that same owner output. Third field is `MetricsOrigin` / `resolveDroppedOrigin`, not a reconstructed identity.

Reproduce (existing tests on this worktree, dest behavior):

1. Ban page header is the token `ban` — **pass**. `go test ./pkg/bouncer/ -count=1 -run TestHandleBanServeHTTPWithDifferentMethods` (asserts `X-Test-Remediation == "ban"`).
2. AppSec relay copies raw `action` (`challenge`, `captcha`) — **pass**. `TestHandleNextServeHTTPRelaysStructuredAppsecChallenge` / `RelaysStructuredAppsecCaptcha`.
3. AppSec `action: ban` and empty-challenge fail-closed still write `ban` — **pass**. `TestHandleNextServeHTTPStructuredBanKeepsBanTemplate` / `EmptyChallengeBodyBansWithBanPage`.
4. Disconnect keeps `error:client-disconnected` — **pass**. `TestHandleNextServeHTTP_clientDisconnected`.
5. Solved 302 is `solved-captcha` — **pass**. `go test ./pkg/captcha/ -count=1 -run Test_WriteSolvedRedirect_noCookieRemint`.
6. Traefik `downstream_<Name>` JSON field — **not reproduced** in this phase (needs the real e2e stack). In-tree proof is `tests/e2e/real/simple-bouncer.Tests.ps1` / `captcha.Tests.ps1` matching `downstream_X-Crowdsec-Remediation` to `"ban"` / `"captcha"`.

Outside facts used: `knowledge/research/ext_crowdsec_appsec_protocol/` (403 JSON actions `ban` / `captcha` / `challenge`; any other action is still applied); `knowledge/research/ext_crowdsec_lapi_usage-metrics/` (official origins include `lists:XXX`; plugin must not persist scenario except that rewrite). Usage: `knowledge/devdocs/core_plugin_middleware.md`, `core_plugin_middleware_ban-page.md`, `core_plugin_appsec.md`, `core_plugin_middleware_captcha-routing.md`, `core_plugin_middleware_captcha-widget.md`, `core_plugin_middleware_forced-decision.md`, `core_plugin_lapi_usage-metrics.md`, `std_go_test_zzz-prefix.md`. No `priority: always` packets. `openspec list --json`: no active change.

## Decisions

- Chosen seam: unexported formatter in `pkg/bouncer` (new file `remediation_header.go`) that builds `kind:reason` / `kind:reason:origin`. Ban / AppSec / disconnect / captcha-downgrade call it at the existing writers. Captcha stays a dumb setter: `ServeHTTP` takes the already-formatted challenge-page **value** plus the header **name**; Pass 302 and `WriteSolvedRedirect` write the constant `captcha:solved` inside `pkg/captcha`.
- Chosen mapping: plugin `OriginPlugin*` and AppSec specials are **reason tokens**, never a third field. LAPI hits use reason `lapi` and encode `MetricsOrigin` (strip CR/LF/TAB; prefix `lists:` → `lists_`; empty origin omits the third field). `handleBanServeHTTP` cannot infer `captcha-downgrade` vs `appsec` vs `appsec-challenge-empty` from origin alone — each of the 9 production call sites passes an explicit reason token.
- Chosen captcha challenge write: add a challenge-value argument to `ServeHTTP` (1 production caller). Do not teach `pkg/captcha` plugin origins or the closed reason table. Do not store the header on `captcha.Client`.
- Chosen unknown AppSec relay action: `formatRemediationHeader(sanitizedAction, "appsec", "")` → `{action}:appsec`. Sanitize the action token (trim; strip CR/LF/TAB; replace `:` with `_` so kind stays one field). Official `captcha` / `challenge` stay on the closed rows (`captcha:appsec`, `captcha:challenge`).
- Chosen tests: update every existing assertion that pins an old token; add `pkg/bouncer/zzz_remediation_header_test.go` for the formatter (origin encode, plugin origins, empty origin, unknown AppSec). Do not add a public config key. Do not persist scenario.
- Chosen specs: fold into live contracts (no new family). Vocabulary table + emit rules on `core_plugin_middleware_bouncer`. MODIFIED string on `core_plugin_middleware_captcha-widget` and `core_plugin_middleware_captcha-routing` (`solved-captcha` → `captcha:solved`). MODIFIED AppSec header SHALL on `core_plugin_appsec_bot-detection` (raw action → structured). Keep `error:client-disconnected` exact on the bouncer spec.
- Chosen e2e strings: real Pester uses `cscli decisions add` (origin `cscli`) → `ban:lapi:cscli` / `captcha:lapi:cscli`. Captcha fallback on a router without captcha is `ban:captcha-downgrade`. Mock `lapi_add_decision` defaults origin `crowdsec` → `ban:lapi:crowdsec` on `tests/e2e/mock/scenarios/custom-ban-page/run.sh`.
- Rejected: a shared `pkg/remediationheader` (only bouncer owns mapping; captcha does not).
- Rejected: inferring header reason from `recordDropped` origin alone (AppSec `action: ban` and empty-challenge share origin `appsec`; captcha-downgrade keeps the captcha metrics origin).
- Rejected: putting `plugin:…` origins in the third field, globally replacing every `:`, storing `Decision.Scenario`, emitting `allow: pass`, writing the header on next/503, a new Traefik Config key.
- Rejected: changing `MetricsOrigin` or DecisionStore packing so the header can skip `lists_` encode.
- Live contract: `openspec/specs/core_plugin_middleware_bouncer/spec.md` (header name on Bouncer; `error:client-disconnected` SHALL — keep exact). `openspec/specs/core_plugin_middleware_captcha-widget/spec.md` (`solved-captcha` on Pass). `openspec/specs/core_plugin_middleware_captcha-routing/spec.md` (`solved-captcha` on Check-true form POST; “captcha remediation header” on challenge). `openspec/specs/core_plugin_appsec_bot-detection/spec.md` (custom header SHALL be the AppSec `action`). Propose MODIFIED those four. `core_plugin_appsec_client` points serving the disconnect header at the bouncer spec — no value change.

## Open questions

- Q: Structured grammar `kind:reason` / `kind:reason:origin`, no space after `:`?
  Rank: additive asked — Desired Closed vocabulary and “No space after `:`”
  Decision: resolved — yes; `:` is the field separator; split at most three fields
  By: explore

- Q: Closed vocabulary table (decision-header, lapi, lapi-failure, stream-unhealthy, cache-fail, unparseable-request, appsec, appsec-challenge-empty, appsec-failure, captcha-downgrade, captcha:*, error:client-disconnected)?
  Rank: additive asked — Desired Closed vocabulary table
  Decision: resolved — emit only those rows (plus unknown AppSec `{action}:appsec` below); closed reasons never take a third field
  By: explore

- Q: LAPI third field encoding?
  Rank: additive asked — Desired Origin encoding
  Decision: resolved — third field is header-safe `MetricsOrigin`; prefix `lists:` → `lists_` only; empty origin omits the third field; strip CR/LF/TAB; do not change `MetricsOrigin` or DecisionStore packing
  By: explore

- Q: Header on pass / bypass / trusted / passthrough / remap-to-pass / widget / gate-cookie / disabled / startup 503?
  Rank: additive asked — Out of scope names those paths
  Decision: resolved — no header; do not add `allow: pass`
  By: explore

- Q: Persist CrowdSec `Decision.Scenario` on DecisionStore, or add a public config key, or emit when the header name is empty?
  Rank: additive asked — Out of scope names all three
  Decision: resolved — no persist except the existing lists rewrite; no new key; empty name still disables
  By: explore

- Q: Keep `error:client-disconnected` exact despite Breaking listing it among values that change?
  Rank: additive asked — Desired row `error:client-disconnected`; Tensions already notes the query split
  Decision: resolved — keep the exact string (`kind` `error`, `reason` `client-disconnected`); operators matching the full string do not change queries
  By: explore

- Q: Where should the emit helper live?
  Rank: additive asked — Unknowns names helper location; Desired requires structured values at the existing writers
  Decision: assumed — unexported `formatRemediationHeader` in `pkg/bouncer/remediation_header.go`; `handleBanServeHTTP` / AppSec / disconnect call it; captcha does not import the table
  By: explore

- Q: Does `captcha.Client` learn the closed vocabulary, or only set a value the bouncer already formatted?
  Rank: bounded incidental — `ServeHTTP` already has callers; 1 production + 10 tests enumerated under Concepts; Unknowns names helper location, not a captcha API
  Decision: assumed — bouncer passes the formatted challenge-page value into `ServeHTTP`; Pass 302 and `WriteSolvedRedirect` write `captcha:solved` inside captcha (constant, no origin). Do not put `OriginPlugin*` on the captcha Client
  By: explore

- Q: What header value for AppSec JSON `action` other than `ban` / `captcha` / `challenge`?
  Rank: additive asked — Unknowns names unknown AppSec actions; protocol allows “any other action”
  Decision: assumed — `{sanitized-action}:appsec` after trim, CR/LF/TAB strip, and `:` → `_` in the action token; `allow` / empty never reach relay
  By: explore

- Q: How often does a live stream Range hit still have empty origin?
  Rank: additive asked — Unknowns names letter-only vs `KindOriginString`; Desired already specifies `ban:lapi` / `captcha:lapi` when empty
  Decision: assumed — new stream Range upserts use `KindOriginString` with `MetricsOrigin` (`pkg/lapi/client_stream.go`); empty origin remains intern overflow (`originID == 0`) and letter-only Range blobs (`TestLookupHitsRangeLetterOnlyStillBans`). Header omits the third field. Do not persist scenario to close the gap
  By: explore

- Q: Who already owns client address and the header’s third field?
  Rank: additive asked — commandment One job, one owner; header third field is origin, not a new identity
  Decision: resolved — client address owner is `pkg/ip.GetRemoteIP` on `clientRequest.remoteIP` (reuse; do not parse `RemoteAddr`). Third field owner is `LookupRemediation` / `LiveLookup` `MetricsOrigin` plus `resolveDroppedOrigin` on drop. Forced / fail-closed reasons use `OriginPlugin*` as the **reason**, not as a third field
  By: explore

- Q: Which tests, README, live specs, and e2e assertions pin the old strings, and what do they become?
  Rank: bounded asked — Desired Breaking plus Ground names the files; call sites enumerated under Concepts
  Decision: assumed — update those files in place (no new e2e suite). Real Pester `cscli` origin becomes `ban:lapi:cscli` / `captcha:lapi:cscli`; captcha fallback without a client is `ban:captcha-downgrade`; mock custom-ban-page default origin becomes `ban:lapi:crowdsec`; AppSec relay becomes `captcha:challenge` / `captcha:appsec`; disconnect stays `error:client-disconnected`; `solved-captcha` becomes `captcha:solved`. File list is under Decisions.
  By: explore

- Q: New spec family for the vocabulary, or fold into the four live contracts?
  Rank: additive asked — live specs already SHALL the old values; librarian Live catalog is fold for remaining behavior
  Decision: assumed — fold; no new `openspec/specs/` folder
  By: explore

- Q: Own test file for the formatter, or only extend existing header tests?
  Rank: additive asked — Ground/Unknowns name blast radius; new helper is a unit this change creates
  Decision: assumed — both: `pkg/bouncer/zzz_remediation_header_test.go` (`std_go_test_zzz-prefix`) for encode/classify, and migrate the assertion files above
  By: explore

- Q: If a non-lists `MetricsOrigin` still contains `:`, rewrite remaining colons?
  Rank: additive asked — Desired says rewrite only the `lists:` prefix, do not globally replace
  Decision: assumed — follow the letter: only `lists:` → `lists_`. Consumers split at most three fields, so a leftover colon stays inside origin. Official origins besides lists do not use `:` (`ext_crowdsec_lapi_usage-metrics`)
  By: explore

- Q: Must operators who panel on `error:client-disconnected` change queries?
  Rank: additive asked — Unknowns / Tensions
  Decision: resolved — no; the full string is unchanged. Operators matching single-token `ban` / `captcha` / `solved-captcha` / raw AppSec `action` must update
  By: explore

- Q: Should `captcha:solved` carry a third-field origin from the captcha that was just solved?
  Rank: additive incidental — Desired row is `captcha:solved` with no third field
  Decision: assumed — no third field
  By: explore

- Q: LAPI decision type `throttle` (cscli) on the header?
  Rank: additive incidental — `decisionscope.RemediationValue` returns empty for non-ban/non-captcha; Out of scope does not name throttle; no header today
  Decision: assumed — leave; still no remediation header
  By: explore
