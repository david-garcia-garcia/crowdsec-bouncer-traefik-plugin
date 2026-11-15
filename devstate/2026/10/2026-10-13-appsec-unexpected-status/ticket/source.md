# AppSec 401 and unexpected statuses follow the failure action

CrowdSec's challenge protocol: HTTP 401, 500, or an unexpected AppSec status uses the component's configured AppSec failure behaviour. 502, 503, and 504 count as unreachable.

This fork already applies `bouncerAppsecFailureAction` (passthrough | ban | captcha) to HTTP 500, transport failure, and listener 502/503/504. `Test_appsecQuery_failureActionOnServerError` covers those four statuses.

A bare 401 (and any other unexpected status that is not 200, not 502/503/504, and not a parseable JSON action) becomes `appsecQuery statusCode:<n>` from `interpretAppsecBody`. `applyAppsecServeHTTP` treats that error as a ban regardless of `bouncerAppsecFailureAction`, and logs it at Debug. A throwaway test showed passthrough on 401 returns `appsecQuery statusCode:401`.

Current spec `openspec/specs/core_plugin_appsec_failure-action` says legacy empty/non-JSON non-200 (other than 500/502/503/504) SHALL still ban. That sentence conflicts with the protocol. Update the spec so 401 and other unexpected listener statuses follow `bouncerAppsecFailureAction` the same way 500 does. 502/503/504 stay unreachable. Parseable JSON with a non-empty action (allow, ban, captcha, challenge, other) is not a failure status.

Desired: passthrough on 401 allows the request (Query returns allow, bouncer calls next). ban on 401 forbids. captcha on 401 is ErrFailureCaptcha / the captcha client. Log the failure at Error with the status code (this fork uses slog; match existing Error lines, do not invent a new logger).

Out of scope: changing 500/502/503/504 behavior. Client disconnect. Body limits.

Add a regression test that fails on dest when 401 ignores passthrough. Run tests on this machine.

Upstream (must appear on every delivery card / PR body): https://github.com/maxlerebourg/crowdsec-bouncer-traefik-plugin/pull/403 (fixes https://github.com/maxlerebourg/crowdsec-bouncer-traefik-plugin/issues/402, point 2). Say this fork's gap versus that PR. Do not claim we copied their patch.
