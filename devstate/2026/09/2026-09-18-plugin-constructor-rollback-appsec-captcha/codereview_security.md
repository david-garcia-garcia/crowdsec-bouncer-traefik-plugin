# Code review — Security

- [x] C1 The snapshot stops resolved secrets from travelling back into the struct Traefik keeps.
  Status: improvement. Argument: before this change, the caller's `*Config` came back carrying the
  resolved `crowdsecLapiKey`, `redisCachePassword`, and `crowdsecAppsecKey`. Anything that logs or
  serialises Traefik's own middleware config saw them. Now it does not.
- [x] C2 The new warning must not leak configuration values.
  Status: pass. Argument: it names the two keys and the consequence, and interpolates nothing.
- [x] C3 The appsec-plus-disabled case is a fail-open middleware. Warning, not rejection, leaves it
  serving traffic unchecked.
  Status: accepted — owner's decision, recorded on `explore.md` as resolved. Argument: rejecting
  refuses to boot over a config that only fails to enforce; implying `crowdsecAppsecEnabled` would
  aim at the `crowdsec:7422` default with the default `ban` action and ban every request on that
  router. The warning is at `WARN`, above the default `INFO` threshold, so it is visible without
  reconfiguration.
- [x] C4 Captcha in appsec mode does not weaken the AppSec ban path.
  Status: pass. Argument: the only behaviour change is that `crowdsecAppsecFailureAction: captcha`
  now challenges instead of banning — which is what the operator asked for. `ban` and `passthrough`
  are untouched, and the early return still applies to them.
- [x] C5 A failed `New` no longer leaves an authenticated LAPI stream ticker polling with the
  bouncer's API key for the process lifetime.
  Status: fixed. Argument: measured — 2 further polls in 2.5 s before the fix, 0 after.
