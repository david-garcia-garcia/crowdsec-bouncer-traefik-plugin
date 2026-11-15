# ext / traefik-modsecurity

## Unhealthy WAF admission gate
priority: normal
local: ext_traefik-modsecurity_backoff/
description: How traefik-modsecurity skips the CRS sidecar after inspect failures via backendbackoff.Gate.

## Inspect copy protocol
priority: normal
local: ext_traefik-modsecurity_inspect/
description: How traefik-modsecurity copies a request to CRS and classifies 2xx allow, 3xx-4xx block, and 5xx failure.

## Real e2e inventory
priority: normal
local: ext_traefik-modsecurity_e2e/
description: Apache-drain and nginx-drain Pester stacks in traefik-modsecurity, for porting into this repo’s tests/e2e/real suite.
