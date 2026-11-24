[Documentation](../README.md) › [How-to](README.md) › Choose what happens when CrowdSec is down

# Choose what happens when CrowdSec is down

`bouncerLapiFailureAction`, `bouncerAppsecFailureAction` and `bouncerModsecFailureAction` decide what happens when LAPI, AppSec or the ModSecurity sidecar cannot give an answer:

- `ban` (LAPI default) — block the request.
- `passthrough` (AppSec and ModSec default) — let it through. If LAPI is down, AppSec still checks the request.
- `captcha` — show a captcha. Requires a captcha on this router.

With the [LAPI Redis cache](../failure-modes.md#the-lapi-redis-cache), a failed Redis read follows `bouncerLapiRedisFailureAction` instead, with the same three values (default `ban`).

When the LAPI failure action applies depends on the LAPI mode:

- **`stream` and `alone`.** The plugin keeps using the decisions it already has when LAPI is down. The failure action only applies to clients without a known decision, after `lapiUpdateMaxFailure` failed refreshes.
- **`live` and `none`.** A client that is not in the cache is looked up in LAPI on the request itself (`none` has no cache). If LAPI does not answer, the failure action applies to that request right away. `lapiUpdateMaxFailure` has no effect. The failed lookup is not cached: the next request asks LAPI again. After 5 failed lookups in a row, the backoff gate stops calling LAPI for `lapiUnhealthyBackOffPeriodSecs` (default 10), and lookups get `bouncerLapiBackOffAction` (default `ban`) at once instead of waiting for the timeout. In `live`, decisions already in the cache keep applying until they expire.

In every mode, the failure action also applies while the connection is not published yet, including right after startup or a reload.

AppSec and the ModSecurity sidecar have the same backoff gate (10 seconds by default), with their own backoff action, `bouncerAppsecBackOffAction` and `bouncerModsecBackOffAction` (default `passthrough`). See [When a WAF is down](../failure-modes.md#when-a-waf-is-down-failure-action-and-backoff).

What every leg does when its backend is down (LAPI per mode, the Redis cache, AppSec, ModSecurity, the rate-limit Redis, the captcha provider), and how you notice it, is in [When a dependency is down](../failure-modes.md).

To let traffic through while LAPI is down in `live` or `none`, set `bouncerLapiFailureAction: passthrough` and `bouncerLapiBackOffAction: passthrough`. The original plugin used `updateMaxFailure: -1` for this. That key does not exist here, and Traefik ignores unknown keys without an error.
