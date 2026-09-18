# core / plugin

## Middleware New
priority: normal
local: core_plugin_middleware.md
description: How Traefik New reclaims a LAPI Client and an AppSec Client and returns a per-router Bouncer (`core_plugin_middleware_bouncer`).

## Local plugin
priority: normal
local: core_plugin_middleware_local-plugin.md
description: How this unpublished fork is loaded by Traefik (import equals go.mod, localPlugins, no catalog version).

## Config validation
priority: normal
local: core_plugin_middleware_config-validation.md
description: How New rejects invalid Traefik Config (ValidateParams) before opening LAPI, including the LogFilePath writability-check handle.

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
description: How this plugin keys a reclaimed LAPI Client (cursor SessionHex plus Redis store params).

## LAPI scope union
priority: normal
local: core_plugin_lapi_scope-union.md
description: How a shared stream Client unions live routers' header-scope maps for scopes= and the store filter.

## Stream lease
priority: normal
local: core_plugin_lapi_stream-lease.md
description: The `updated` cache key that grants one CrowdSec stream GET on a shared DecisionStore.

## Stream single-flight
priority: normal
local: core_plugin_lapi_stream-single-flight.md
description: How one Client skips a stream poll that is already running and publishes health atomically.

## Stream apply
priority: normal
local: core_plugin_lapi_stream-apply.md
description: How this plugin writes one CrowdSec stream payload (deleted before new) into the DecisionStore.

## LAPI connection
priority: normal
local: core_plugin_lapi_connection.md
description: How this plugin stores replaceable LAPI HTTP+auth on the Client (`core_plugin_lapi_connection`).

## LAPI query round trip
priority: normal
local: core_plugin_lapi_query-round-trip.md
description: How one CrowdSec LAPI/CAPI exchange encodes the CAPI login body, renews a token once, releases its body, and names its own failure.

## Captcha gate cookie
priority: normal
local: core_plugin_middleware_captcha-gate.md
description: How captcha grace is stored in a signed HttpOnly cookie instead of the connection cache.

## Captcha request routing
priority: normal
local: core_plugin_middleware_captcha-routing.md
description: How handleRemediationServeHTTP routes captcha-kind requests after the gate cookie.

## Captcha siteverify
priority: normal
local: core_plugin_middleware_captcha-siteverify.md
description: How Validate encodes the provider siteverify request and classifies a JSON success reply.

