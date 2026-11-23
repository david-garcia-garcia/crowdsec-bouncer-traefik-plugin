# Spec

1. [judgement] Connection table omits the new read-timeout keys — `docs/how-it-works.md:67` — the "What lives where" table lists the connection-level settings of each leg (`appsecBodyLimit`, `modsecBodyLimit`, ...) but not `appsecBodyReadTimeoutSeconds` / `modsecBodyReadTimeoutSeconds`, which the change specs put in each leg's reclaim identity (`core_plugin_appsec_client` "AppSec is reclaimed by listener identity", `core_plugin_modsecurity_client` "ModSecurity is reclaimed by sidecar identity"), so they live on the middleware that connects; an operator reading the table may set them on a router that only uses the connection and see no effect
   Fix: Add `appsecBodyReadTimeoutSeconds` to the AppSec row and `modsecBodyReadTimeoutSeconds` to the ModSec row (lines 67-68) of the "On the middleware that connects" column
   Status: skipped
   Argument: Judgement: docs table completeness; the keys are documented in `docs/configuration.md` with their per-connection scope. Not applied unattended.
2. [judgement] Streaming how-to implies one WARN per blocked request — `docs/how-to/streaming-request-bodies.md:5` — "Traefik logs a WARN line that names the request" reads as one line per request, while `core_plugin_middleware_bouncer` "Body read deadline is logged at WARN once per window per leg" debounces it to at most one line per leg per 5 s (implemented in `pkg/bouncer/bouncer_serve_waf.go:46`)
   Fix: Say the WARN is logged at most once every 5 seconds per WAF and names one of the blocked requests
   Status: skipped
   Argument: Judgement: docs wording; the debounce is documented in `docs/configuration.md`. Not applied unattended.
