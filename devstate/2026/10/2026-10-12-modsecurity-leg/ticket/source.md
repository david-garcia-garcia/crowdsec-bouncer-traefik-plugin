Title: Add a ModSecurity leg

Absorb https://github.com/david-garcia-garcia/traefik-modsecurity into this project. What modsec does is exactly the same as appsec, so it feels totally pluggable.

Copy the back-off strategy from the modsec plugin to appsec. If appsec is down we do not want the ingress to go down.

This is intended: ModSecurity would become a new leg (alongside LAPI, AppSec, and captcha). Not a replacement for AppSec. Not a second Traefik plugin.

Bring in as much real e2e test coverage from the original traefik-modsecurity project as possible.

The README.md must clearly state the capabilities and configuration of the project as a whole, including docs on how to configure the modsec leg.

Source repo to absorb: https://github.com/david-garcia-garcia/traefik-modsecurity (Apache-2.0). The human owns both repos.
