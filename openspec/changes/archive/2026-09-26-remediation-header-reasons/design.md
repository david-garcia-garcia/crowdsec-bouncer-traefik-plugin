## Context

See proposal.md Why. Dest `handleBanServeHTTP` always `Header().Set(..., "ban")`. Dest `handleAppsecResponseServeHTTP` copies `decision.Action`. Dest captcha `ServeHTTP` / `WriteSolvedRedirect` hard-code `captcha` / `solved-captcha`. Dest `handleClientDisconnectedServeHTTP` already writes const `error:client-disconnected`. Metrics origins (`OriginPlugin*` and `MetricsOrigin`) already exist for `recordDropped`; they are not on the header. Explore Decisions are accepted: unexported formatter in `pkg/bouncer/remediation_header.go`; captcha stays a dumb setter; unknown AppSec is `{action}:appsec`; `lists:` → `lists_` only; no new config key.

## Goals / Non-Goals

**Goals:**

- One formatter for `kind:reason` / `kind:reason:origin`.
- Explicit header-reason tokens at ban writers that share a metrics origin (`appsec`, captcha-downgrade).
- Captcha `ServeHTTP` takes the formatted challenge-page value; Pass / `WriteSolvedRedirect` write `captcha:solved`.
- Formatter unit tests plus migrate existing token assertions and e2e strings.

**Non-Goals:**

- Header on pass / next / 503.
- Changing `MetricsOrigin`, DecisionStore packing, or usage-metrics labels.
- Incoming `bouncerDecisionHeader` matching.
- A shared `pkg/remediationheader` or a Traefik Config key.
- Writing `knowledge/devdocs` this phase.
- Persisting CrowdSec `Decision.Scenario` except the existing lists rewrite.

## Decisions

| Topic | Choice | Rationale |
| ----- | ------ | --------- |
| Seam | Unexported `formatRemediationHeader(kind, reason, origin string) string` in `pkg/bouncer/remediation_header.go` | Only bouncer owns the closed table. Captcha does not import it. |
| Ban writer | `handleBanServeHTTP` takes an extra `headerReason` next to template `reason` and metrics `origin`. Formatter appends origin only when `headerReason` is `lapi`. | Template `RemediationReason` is not the header reason. AppSec `ban` and empty-challenge share origin `appsec`; captcha-downgrade keeps the captcha metrics origin. |
| Plugin / LAPI map | Helper maps `OriginPlugin*` → closed reason (`decision-header`, `lapi-failure`, `stream-unhealthy`, `cache-fail`, `unparseable-request`, `appsec-failure`) and anything else → `lapi` plus encoded origin. `handleRemediationServeHTTP` uses it for ban kind and for the captcha challenge-page value. Captcha-downgrade / `appsec` / `appsec-challenge-empty` stay explicit at those call sites. | Forced, fail-closed, and LAPI hits already pass distinct origins into the remediating handlers. |
| Captcha API | Add a challenge-value argument to `ServeHTTP` (1 production caller). Pass 302 and `WriteSolvedRedirect` write constant `captcha:solved`. Do not store the header on `captcha.Client`. | Explore: captcha is a dumb setter. Tests that pass empty name still no-op the header. |
| Unknown AppSec | `formatRemediationHeader(sanitizedAction, "appsec", "")`. Sanitize: trim; strip CR/LF/TAB; `:` → `_`. Official `captcha` / `challenge` stay on closed rows. | Protocol allows any other action. Kind must stay one field. |
| Origin encode | Strip CR/LF/TAB; prefix `lists:` → `lists_` only; empty omits third field. | Desired letter. Consumers split at most three fields. |
| Tests | New `pkg/bouncer/zzz_remediation_header_test.go` (`std_go_test_zzz-prefix`) for encode/classify. Migrate existing header assertions in place. No new e2e suite. | Explore blast-radius list. |
| Catalog | Fold the four live leaves. No new family. | Live specs already SHALL the old tokens. |

**Alternatives rejected:** shared `pkg/remediationheader`; inferring header reason from `recordDropped` origin alone; putting `plugin:…` in the third field; globally replacing every `:`; emitting `allow: pass`; a new Config key; changing packing so the header can skip `lists_`.

## Risks / Trade-offs

- **BREAKING for operators who panel on `ban` / `captcha` / `solved-captcha` / raw AppSec action** → Document in README. Header still off by default. `error:client-disconnected` stays exact.
- **A leftover colon inside a non-lists MetricsOrigin stays in the third field** → Accepted. Official origins besides `lists` do not use a colon.
- **Captcha `ServeHTTP` signature grows one argument** → One production caller plus test call sites that already pass an empty header name; pass `""` for the value there unless the test asserts the header.
- **e2e `cscli decisions add` origin is `cscli`** → Assert `ban:lapi:cscli` / `captcha:lapi:cscli`, not a bare kind.

## Migration Plan

- Deploy. Operators who match old single-token values update Traefik/log queries. Rollback is revert of the PR. No config rewrite. Empty name still disables.

## Open Questions

None. Explore rows stay as explore wrote them.
