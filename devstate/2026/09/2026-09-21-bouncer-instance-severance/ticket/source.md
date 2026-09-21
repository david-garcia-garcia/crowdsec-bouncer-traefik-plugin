# Source (local)

The middleware needs per-route configuration, while shared config such as LAPI settings stays shared.

(A) Add a new crowdsecMode=bouncer.
(B) This is the ONLY mode that bounces requests. It does NOT instantiate AppSec or LAPI settings. It SUBSCRIBES to existing instances BY NAME.
(C) Modes that are NOT bouncer do not bounce. They manage AppSec and LAPI configuration instances, which should be named.
(D) Modes that are not bouncer do not PROCESS incoming requests. They REJECT. They are supposed to be deployed on a PLACEHOLDER (dummy) router.
(E) There is no control over the order routes are created, so a bouncer instance can be created BEFORE the supporting LAPI and AppSec objects exist. The bouncer-only router can start before the supporting AppSec or LAPI backends.

As a consequence, some settings need to be promoted to the bouncer level: those that are cheap to instantiate and make sense at the router level (decision remapping, remediation header, and similar).

The plugin is still in beta. Changing current behaviour is acceptable.

The README must CLEARLY explain this severance: dummy routers are used for the CrowdSec LAPI and AppSec clients, and bouncer mode is used for per-router configuration.

The human is not sure whether to further polish the settings surface. crowdsecAppsecEnabled may no longer make sense; crowdsecMode=appsec could describe an AppSec-only backend. A non-bouncer instance must be able to create both an AppSec backend and a LAPI client at the same time.

Target branch is master.
