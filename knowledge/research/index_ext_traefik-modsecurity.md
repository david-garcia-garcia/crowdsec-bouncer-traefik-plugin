# ext / traefik-modsecurity

## Health tracker backoff
priority: normal
local: ext_traefik-modsecurity_health_tracker/
description: Tumbling-window failure counter and timed backoff used to skip WAF sidecar calls when unhealthy.
