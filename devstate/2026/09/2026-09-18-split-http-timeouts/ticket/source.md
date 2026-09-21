Keep public `httpTimeoutSeconds` (default 10). Add three inheriting second knobs:
- lapiHttpTimeoutSeconds / LapiHttpTimeoutSeconds
- appsecHttpTimeoutSeconds / AppsecHttpTimeoutSeconds
- bouncerCaptchaHttpTimeoutSeconds / BouncerCaptchaHttpTimeoutSeconds
Zero or omitted inherits HTTPTimeoutSeconds. Do not rename HTTPTimeoutSeconds.

Wire effective seconds onto existing clients — do not invent a second HTTP stack:
- LAPI: pkg/lapi/client_http.go transport Timeout from EffectiveLapi (not raw HTTPTimeoutSeconds)
- AppSec: pkg/appsec/client_http.go same for EffectiveAppsec
- Captcha: pkg/bouncer/bouncer.go http.Client Timeout from EffectiveCaptcha (today line ~109 uses config.HTTPTimeoutSeconds)
AdoptTransport still last-writes a timeout-only reload on the same Client. Timeout MUST stay out of reclaim identity / IdentityHex / Key (session.go). A timeout-only YAML change must Adopt, not Open a new Client.

Document README knobs. Example: appsecHttpTimeoutSeconds: 1 with bouncerAppsecFailureAction: passthrough.

Tests that fail if wiring still reads raw HTTPTimeoutSeconds:
- LAPI client Timeout honors LapiHttpTimeoutSeconds (session/adopt already asserts HTTPTimeoutSeconds — extend for the override)
- AppSec Query against a hanging listener with AppSec override 1s + passthrough returns well under the 10s default
- bouncer captcha siteverify client Timeout honors BouncerCaptchaHttpTimeoutSeconds
- omit/0 inherit 10; identity hex unchanged when only timeout knobs differ

Bound: do not implement backendbackoff (separate PR 2026-09-18-backendbackoff-lapi-appsec). Do not change cache.Set, captcha gate cookie, Range, module path, or HTML-path deprecations. Do not put timeout back into identity.

Upstream context only (do not open upstream PRs): maxlerebourg/crowdsec-bouncer-traefik-plugin#388 — one shared timeout makes AppSec hang as long as LAPI stream.
