# Requirement
IssueKey: 2026-11-20-action-rule-bypass-captcha

## Problem

A request that cannot solve a captcha (a machine-to-machine API call) gets the captcha HTML page with HTTP 200 whenever a captcha applies to it, for example a CrowdSec `captcha` decision scoped to a whole AS. The operator has no way to say "on these requests, never serve a captcha, but keep the bans". The caller asks for a new `bouncerActionRules` action, `bypassCaptcha`, that lets the request through where a captcha would be served, a PR to `master`, and a README that says in which cases it works and in which it does not (`ticket/source.md`).

## Current (code)

- `pkg/httprule/action.go:12-18` — the action tokens are `ban`, `bypass`, `bypassAppsec`, `bypassLapi`, `captcha`. No token weakens only the captcha.
- `pkg/httprule/action.go:191-226` — `compileActionTokens`: rejects empty, unknown, and duplicate tokens, and `ban` mixed with any other token. `captcha` may share a rule with any `bypass*` token.
- `pkg/httprule/action.go:96-129` — `Fold`: every matching row applies. A row with a `path` predicate contributes no skip when `SingleReadingPath` is false; its `captcha` token still applies.
- `pkg/httprule/path.go:18-43` — `SingleReadingPath`: false on any percent-encoding, on a byte outside the allowed set (`;`, `\`, `%`, `*`, space...), and on empty, `.` or `..` segments.
- `pkg/httprule/set.go:193-202` — a rule's `path` regex is matched against `http.Request.URL.Path` (the decoded path).
- `pkg/bouncer/bouncer.go:176-189` — `ServeHTTP`: a rule ban first, then the LAPI leg, then the AppSec leg.
- `pkg/bouncer/bouncer_serve_lapi.go:43-47` and `:71-76` — a LAPI decision is remapped per origin (`appliedLAPIRemediation`) and then remediated; a `captcha` kind serves the captcha gate.
- `pkg/bouncer/bouncer_serve_lapi.go:84-94` — LAPI failure action `captcha` serves the captcha gate.
- `pkg/bouncer/origin_based_decision_remap.go:56-72` — `applyOriginBasedDecisionRemap`: one hop on the stored kind; `ban` can become `captcha` or pass, `captcha` can become pass.
- `pkg/bouncer/bouncer_serve_appsec_verdict.go:25-30` — an AppSec `captcha` verdict serves this router's captcha gate unless a captcha rule matched.
- `pkg/bouncer/bouncer_serve_appsec.go:74-84`, `:98-99`, `:109-111` — AppSec failure action `captcha` serves the captcha gate.
- `pkg/bouncer/bouncer_serve_appsec.go:41-54` — a matching `captcha` rule serves the captcha gate (`applyCaptchaRuleServeHTTP`); a captcha form POST that AppSec let through goes to the gate.
- `pkg/bouncer/bouncer_serve_captcha.go:53-83` — `handleCaptchaKindServeHTTP`: the one place that writes a captcha challenge, a solved-form redirect, or a downgrade ban. Every captcha source above ends here.
- `README.md:723-729` — `BouncerActionRules` reference: conditions, actions, and the single-reading path rule for `bypass*`.
- `openspec/specs/core_plugin_middleware_bouncer/spec.md:308` ("Action rules fold every matching row") and `:480` ("Action-rule skips need a single-reading path"); `openspec/specs/core_plugin_middleware_config-validation/spec.md:308-311` ("Invalid action rules fail ValidateParams").
- `knowledge/devdocs/core_plugin_middleware_action-rules.md`, `knowledge/devdocs/core_plugin_httprule.md` — usage docs of the action rules and of `httprule`.

## Desired

- A `bypassCaptcha` action token in `bouncerActionRules`. On a matching request the plugin lets the request continue where it would have served a captcha. Bans keep applying.
- The behaviour per captcha source agreed in chat (`ticket/source.md` table): CrowdSec `captcha` decision, AppSec `captcha` verdict, and LAPI or AppSec failure action `captcha` pass; a ban softened to a captcha by `bouncerOriginBasedDecisionRemap` stays a ban; `captcha` with `bypassCaptcha` in one rule is rejected at validation; against a `captcha` token of another matching rule, `bypassCaptcha` wins; the AppSec bot-detection `challenge` is not covered.
- A `bypassCaptcha` rule with a `path` applies its regex as written. It does not use the single-reading path guard that `bypass`, `bypassLapi` and `bypassAppsec` use.
- The README documents in which cases `bypassCaptcha` works and in which it does not.
- A PR to `master`.

## Affected

- `pkg/httprule` (token, validation, fold).
- `pkg/bouncer` (LAPI leg, AppSec leg, captcha gate, origin remap apply).
- `openspec/specs/core_plugin_middleware_bouncer`, `openspec/specs/core_plugin_middleware_config-validation`, possibly `openspec/specs/core_plugin_lapi_origin-based-decision-remap`.
- `knowledge/devdocs/core_plugin_middleware_action-rules.md`, `knowledge/devdocs/core_plugin_httprule.md`, `README.md`.

## Out of scope

- A token that answers an API request with an explicit error (403 or 429) instead of a captcha. Discussed in chat as a possible second token; not asked.
- An IP or network condition on action rules.
- Relaxing `SingleReadingPath` for the existing `bypass*` tokens.
- Changing the HTTP status of the captcha page (200 today).
- Exempting an address from decisions of a given scope.

## Unknowns

- Which path a Traefik middleware receives for `..`, `%2e%2e`, `..%2F`, `%5C` and `;` requests. Read from the Traefik documentation in chat, inferred from the documented order, not measured against a running Traefik.
- Whether Traefik's default configuration leaves any path form for which the `path` regex of a `bypassCaptcha` rule matches while the backend serves a different resource (the `..%2F` case raised in chat).
- Which Traefik versions the README may assume for that protection (the plugin's minimum supported Traefik version was not looked up).
- Where the captcha bypass is decided so that all five captcha sources behave the same (one place or one per leg).

## Tensions

- The caller's reason for dropping the path guard is "Traefik already protects against path traversal in the URL". The documentation read in chat supports this for `.`/`..` segments and `%2e`, and says encoded reserved characters such as `%2F` are allowed by default. The decision is the caller's and stands; what the README says about the remaining cases depends on the measurement in Unknowns.
- The same repository guards `bypass`, `bypassLapi` and `bypassAppsec` with `SingleReadingPath` for the same class of request. After this change two sibling tokens treat a path regex differently, on purpose: `bypassCaptcha` weakens a captcha only, the others skip a whole leg.
- "A remapped ban stays a ban" is an exception to "wherever a captcha would be served, the request passes". It was proposed in chat and not objected to; it is not in the caller's last message word for word.
