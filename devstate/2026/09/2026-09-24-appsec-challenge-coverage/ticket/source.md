Add test coverage that proves this plugin's AppSec challenge handling against upstream bug https://github.com/maxlerebourg/crowdsec-bouncer-traefik-plugin/issues/397

That report (maxlerebourg/crowdsec-bouncer-traefik-plugin issue 397) describes two failures in the other plugin:

1. An AppSec response with action=challenge, http_status=200, and empty or missing user_body_content is returned to the client as HTTP 200 with an empty body. The CrowdSec challenge protocol requires this case to fail closed as the configured ban response. The challenge status must not be committed before that empty-body check.

2. When the response writer already has a Content-Security-Policy header and AppSec supplies its challenge CSP in user_headers, that plugin appends a second CSP (Header().Add). The protocol says AppSec-provided headers of the same name replace the existing header. Multiple Set-Cookie values must remain separate headers.

Desired: tests in THIS repo that assert the protocol behavior for both cases (operator ban page, not HTTP 200 with an empty body, when challenge user_body_content is missing or empty; exactly one Content-Security-Policy equal to the AppSec value when a CSP was already on the writer; each user cookie remains its own Set-Cookie). A passing test is the proof. Do not change production behavior unless a test shows the protocol behavior is absent.

The delivery card (PR summary) must name the upstream issue: https://github.com/maxlerebourg/crowdsec-bouncer-traefik-plugin/issues/397

Out of scope: changing the upstream repository; the AppSec captcha empty-body path (that action is specified to relay status); new config keys.
