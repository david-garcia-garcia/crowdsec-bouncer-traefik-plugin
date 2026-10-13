# Never forward /crowdsec-internal/challenge/ to origin

CrowdSec's challenge protocol: the remediation component forwards `/crowdsec-internal/challenge/*` to AppSec and never to the origin. When AppSec does not answer the path, the bouncer terminates it.

This fork, on AppSec allow (or a nil decision), calls next. A throwaway test: AppSec HTTP 200 on `/crowdsec-internal/challenge/custom.js` returned status 200 and the next handler ran. AppSec allows the custom-script path when no custom script is configured. The same leak happens when failure action is passthrough and AppSec is unreachable or returns an unexpected status that is treated as allow.

Real e2e `Should keep challenge assets off the origin whoami` only proves a dedicated Traefik router sends that prefix to the AppSec listener. It does not prove the plugin returns 404. README says if the middleware already covers every path of the host, you are done — that layout is the leak.

Desired: when AppSec is in use for this request and the URL path is under `/crowdsec-internal/challenge/`, and AppSec did not itself produce a response the bouncer is relaying or a ban the bouncer is writing, the bouncer responds 404 and does not call next. A real challenge/captcha/ban envelope for that path is still written as today. Paths outside the prefix are unchanged.

Do not add a new trusted-IP exception. If trusted IPs already skip the bouncer before this code, leave that path alone.

Update the spec and the README sentence that tells operators the prefix is safe whenever the middleware covers the host.

Regression test: AppSec allow (HTTP 200) on `/crowdsec-internal/challenge/custom.js` is 404 and next is not called. A normal path that AppSec allows still calls next. Run the tests on this machine.

Upstream: https://github.com/maxlerebourg/crowdsec-bouncer-traefik-plugin/pull/403 (fixes https://github.com/maxlerebourg/crowdsec-bouncer-traefik-plugin/issues/402, point 4).
