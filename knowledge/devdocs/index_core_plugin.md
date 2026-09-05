# core / plugin

## Middleware New
priority: normal
local: core_plugin_middleware.md
description: How Traefik New reclaims a CrowdsecConnection and returns a per-router Bouncer.

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

