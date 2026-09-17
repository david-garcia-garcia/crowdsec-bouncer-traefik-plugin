# core / plugin

## Middleware New
priority: normal
local: core_plugin_middleware.md
description: How Traefik New reclaims a LAPI Client and an AppSec Client and returns a per-router Bouncer (`core_plugin_middleware_bouncer`).

## Decision scopes
priority: normal
local: core_plugin_decisionscope.md
description: How this plugin matches CrowdSec Range and header-mapped scopes without geolocating.

## AppSec challenge
priority: normal
local: core_plugin_appsec.md
description: How this plugin parses CrowdSec AppSec JSON and relays a bot-detection challenge.

## Trusted-IP lookup
priority: normal
local: core_plugin_ip.md
description: How this plugin stores trusted hop and client CIDRs and answers membership.

## LAPI usage-metrics
priority: normal
local: core_plugin_lapi_usage-metrics.md
description: How this plugin POSTs CrowdSec usage-metrics with origin and ip_type labels.

## LAPI reclaim key
priority: normal
local: core_plugin_lapi_reclaim-key.md
description: How this plugin keys a reclaimed LAPI Client (session prefix plus first-wins settings hash).

## Stream lease
priority: normal
local: core_plugin_lapi_stream-lease.md
description: The `updated` cache key that grants one CrowdSec stream GET on a shared DecisionStore.

## LAPI connection
priority: normal
local: core_plugin_lapi_connection.md
description: How this plugin stores replaceable LAPI HTTP+auth on the Client (`core_plugin_lapi_connection`).

## Captcha gate cookie
priority: normal
local: core_plugin_middleware_captcha-gate.md
description: How captcha grace is stored in a signed HttpOnly cookie instead of the connection cache.

## Captcha request routing
priority: normal
local: core_plugin_middleware_captcha-routing.md
description: How handleRemediationServeHTTP routes captcha-kind requests after the gate cookie.

