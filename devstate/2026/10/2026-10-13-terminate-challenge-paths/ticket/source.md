# Never forward /crowdsec-internal/challenge/ to origin

CrowdSec's challenge protocol: the remediation component forwards /crowdsec-internal/challenge/* to AppSec and never to the origin. When AppSec does not answer the path, the bouncer terminates it.

On master, pkg/bouncer/bouncer.go applyAppsecServeHTTP returns false for a nil decision or action allow, and the caller then calls next. AppSec allows /crowdsec-internal/challenge/custom.js when no custom script is configured, so a host-wide middleware leaks that prefix to origin. The same leak happens when the failure action is passthrough and AppSec is unreachable or failing in a way that continues to next.

Desired: when AppSec is in use for this request and the URL path is under /crowdsec-internal/challenge/, and AppSec did not itself produce a response the bouncer is relaying or a ban the bouncer is writing, respond 404 and do not call next. A real challenge, captcha, or ban envelope for that path is still written as today. Paths outside the prefix are unchanged. Do not add a new trusted-IP exception; trusted IPs that already skip the bouncer before this code stay as they are.

Update the live spec and the README sentence that says the prefix is safe whenever the middleware covers the host.

Regression test: AppSec HTTP 200 on /crowdsec-internal/challenge/custom.js is 404 and next is not called. A normal path that AppSec allows still calls next. Run the tests on this machine.

Out of scope: metrics counting, LAPI decision types, workflow files, the closed PR 192.

Upstream (must appear on the delivery card): https://github.com/maxlerebourg/crowdsec-bouncer-traefik-plugin/pull/403 point 4. Do not copy that patch.
