## Why

Two gaps in `bouncerActionRules`, found while reviewing upstream PR https://github.com/maxlerebourg/crowdsec-bouncer-traefik-plugin/pull/413 (issue https://github.com/maxlerebourg/crowdsec-bouncer-traefik-plugin/issues/393). Fork review `upstream-review-2026-11-14.md`, problems 7 and 8.

1. **A bypass rule breaks the bot-detection challenge.** A `bypass` / `bypassAppsec` row that also matches `/crowdsec-internal/challenge/*` (for example a static-asset rule `\.js$`) sends the challenge scripts and submit to origin without AppSec. The visitor cannot solve the challenge. Reproduced on Traefik v3.7.11: `fpscanner.js` and `custom.js` reached `whoami`. Upstream never lets its exclusions cover that prefix.
2. **A bypass rule matches paths the backend reads differently.** The path regex runs on the decoded `req.URL.Path`. Traefik v3.7.11 cleans `..`, `%2e%2e`, `//`, `./` and redirects `%2F..%2F`, but forwards `/healthz/..;/admin`, `/healthz/%2E%2E;/admin` (decoded to `..;`), `/healthz/..%5Cadmin`, `/healthz%2Fadmin` and `/healthz/%252e%252e/admin` unchanged. With an anchored `^/healthz(/|$)` `bypassAppsec` rule AppSec was skipped for all of them. A Java servlet backend reads `..;` as `..`, so `/healthz/..;/admin` is `/admin` without the WAF (and, with `bypass` / `bypassLapi`, without LAPI bans). Anchoring does not help. Upstream only lets an exclusion match a path with one reading.

## What Changes

- No action rule skips AppSec under `/crowdsec-internal/challenge/`. LAPI skips from the same rows stay. This reverses the PR 196 explore decision "SkipAppsec is not AppSec in use; still next".
- A row with a `path` predicate contributes no skip when the request path has more than one reading (percent-encoding, a byte outside unreserved / sub-delims minus `;` and `*`, an empty / `.` / `..` / dots-only segment). Its `captcha` token still applies. Rows without `path` and `ban` rows are unchanged.
- TRACE logs name the rule whose skips were dropped.
- **Not BREAKING** for config. Behaviour change: a bypass path rule now lets AppSec / LAPI inspect requests whose path is percent-encoded (for example `%20`) or carries `;`.

## Capabilities

### Modified Capabilities

- `core_plugin_appsec_bot-detection`: the challenge-prefix 404 no longer depends on SkipAppsec; new requirement "Action rules cannot skip AppSec on the challenge prefix".
- `core_plugin_middleware_bouncer`: new requirement "Action-rule skips need a single-reading path"; the fold bullet names both exceptions.

## Impact

- `pkg/httprule/path.go` (`SingleReadingPath`), `pkg/httprule/action.go` (`Fold`, `ActionMatch.AmbiguousPathName`), `pkg/httprule/set.go` (`hasPath`)
- `pkg/bouncer/bouncer.go` (`foldActionRules`)
- Tests: `pkg/httprule/zzz_httprule_test.go`, `pkg/bouncer/zzz_action_rules_paths_test.go`, `pkg/bouncer/zzz_bouncer_test.go` (subtest "appsec bypass rule custom.js" flips to 404), mock e2e `request-bypass-rules`
- README `BouncerActionRules`, devdocs `core_plugin_httprule.md`, `core_plugin_middleware_action-rules.md`, `core_plugin_appsec.md`
