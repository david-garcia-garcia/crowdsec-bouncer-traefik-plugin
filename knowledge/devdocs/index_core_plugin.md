# core / plugin

## Middleware New
priority: normal
local: core_plugin_middleware.md
description: How Traefik New reclaims a LAPI Client and an AppSec Client and returns a per-router Bouncer.

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

## Captcha Client
priority: normal
local: core_plugin_captcha.md
description: How this plugin renders a captcha template and verifies the token with a provider.

