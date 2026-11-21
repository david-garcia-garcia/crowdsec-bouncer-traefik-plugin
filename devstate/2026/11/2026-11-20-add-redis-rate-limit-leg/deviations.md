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
