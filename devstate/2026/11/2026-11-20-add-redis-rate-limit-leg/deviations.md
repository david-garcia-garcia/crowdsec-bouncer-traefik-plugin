# Deviations

- [x] taken  bucket predicates sit flat on the bucket instead of under a nested `match:` object
  Asked: each bucket carries `match: {method, path, host, headers, cookies}`.
  Instead: the same `httprule.Rule` predicates are squashed onto the bucket row (`name`, `path`, `host`, …, `key`, `requests`, `window`, `action`), exactly as a `bouncerActionRules` row carries them. `match` and `key` stay separate concepts; only the nesting goes.
  Owner: `pkg/httprule/action.go` (`ActionRule` embeds `Rule` with `mapstructure:",squash"`)
  Why: one authoring shape for "which requests" across the plugin, and one less nesting level in Traefik plugin config, where only list → object → list depth is proven by the existing e2e.
  By: explore
  Requester: not asked
- [x] taken  verdict header is `ban:ratelimit:<bucket>` instead of `ratelimit:<bucket>`
  Asked: verdict header `ratelimit:<bucket>` on a 429 (and `captcha:ratelimit:<bucket>` for a captcha action).
  Instead: kind stays in the closed set (`ban`), reason is the new closed token `ratelimit`, and the bucket name rides in the third field, the way `ban:lapi:<origin>` carries an origin. Failure action gives `ban:ratelimit-failure` / `captcha:ratelimit-failure`.
  Owner: `pkg/bouncer/remediation_header.go` (`formatRemediationHeader`, closed `headerKind*` / `headerReason*` tokens)
  Why: a new kind would break consumers that split on the documented closed `kind` set; the bucket name is still in the header.
  By: explore
  Requester: not asked
- [x] taken  `rateLimitFailureAction` uses the plugin's failure-action words instead of `allow | deny`
  Asked: `rateLimitFailureAction: allow | deny`, default `allow`.
  Instead: `passthrough | ban | captcha`, validated by the existing `validateFailureAction`, default `passthrough` for this leg (fail open, as asked).
  Owner: `pkg/configuration/configuration.go` (`FailureActionPassthrough` / `FailureActionBan` / `FailureActionCaptcha`, `validateFailureAction`)
  Why: the LAPI and AppSec legs already name the same choice with these three words; a second vocabulary for "backend unusable" would be a parallel enum.
  By: explore
  Requester: not asked
- [x] taken  no startup check for captcha in the rate-limit policy
  Asked: round-2 requirement `## Out of scope` keeps `rateLimitFailureAction: captcha` failing at startup on a router without a captcha instance name ("Changing `rateLimitFailureAction: captcha` … not asked").
  Instead: no startup check for either captcha use of the leg (failure action `captcha`, `action: captcha` buckets). A subscriber that binds a policy needing a captcha without a captcha subscription logs one ERROR on that bind; at request time the failure action downgrades to the existing `ban:captcha-downgrade` and a captcha bucket to its `ratelimit` answer, with DEBUG per request and no per-request WARN.
  Owner: `pkg/bouncer/bouncer_serve_captcha.go` (`usableCaptcha`, the request-time owner of "this router has a usable captcha")
  Why: addendum B puts the policy on the owner and the captcha on the subscriber, so a startup check runs on the router that does not serve the captcha (an owner with `bouncerEnabled: false` needs none) and the subscriber learns the policy only at publish; decision 3 already chose a runtime downgrade with an ERROR over a startup failure for buckets.
  By: propose
  Requester: confirmed (chat 2026-11-21, explore open question "Where is captcha readiness of the rate-limit policy checked", answer "OK CON TUS PROPUESTAS, IMPLEMENTA")
- [x] taken  a `captcha` bucket without a usable captcha answers as `ratelimit`, not with the existing captcha downgrade
  Asked: decision 3, "Downgrade at request time using the existing downgrade path (`ban:captcha-downgrade` style — serve the ban/429 instead)".
  Instead: the bucket's own `ratelimit` answer: `rateLimitStatusCode` (429), `Retry-After`, `ban:ratelimit:<bucket>`, drop `ban` under `plugin:ratelimit:<bucket>` — the same answer decision 2 gives `bypassCaptcha`.
  Owner: `pkg/bouncer/bouncer_serve_ratelimit.go` (`denyRateLimit`, the leg's existing over-limit writer)
  Why: the existing downgrade (`handleBanServeHTTP`) answers `bouncerRemediationStatusCode` (403) with no `Retry-After` and no bucket name, telling a rate-limited client it is banned; the requirement itself names 429 + `Retry-After` as "the natural reading".
  By: propose
  Requester: confirmed (chat 2026-11-21, explore open question "What does a `captcha` bucket answer on a router without a usable captcha", answer "OK CON TUS PROPUESTAS, IMPLEMENTA")
