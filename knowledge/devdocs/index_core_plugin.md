# core / plugin

## DecisionStore
priority: normal
local: core_plugin_decisionstore.md
description: How LAPI Clients share one Store keyed by CrowdSec cursor SessionHex.

## Middleware New
priority: normal
local: core_plugin_middleware.md
description: How Traefik New reclaims a LAPI Client, an AppSec Client, and a captcha Client and returns a per-router Bouncer (`core_plugin_middleware_bouncer`).

## Instance slots
priority: normal
local: core_plugin_middleware_instance-slots.md
description: How named LAPI, AppSec, and captcha slots Publish and Subscribe through Yaegi-safe atomic.Value.

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

## HTTP request rules
priority: normal
local: core_plugin_httprule.md
description: How this plugin compiles method, path, host, header, and cookie request rules once and matches them on *http.Request.

## LAPI usage-metrics
priority: normal
local: core_plugin_lapi_usage-metrics.md
description: How this plugin POSTs CrowdSec usage-metrics with origin and ip_type labels.

## LAPI reclaim key
priority: normal
local: core_plugin_lapi_reclaim-key.md
description: How this plugin keys a reclaimed LAPI Client (ownership key plus SessionHex for the store).

## LAPI scope union
priority: normal
local: core_plugin_lapi_scope-union.md
description: How a stream Client polls opener-only lapiStreamScopes (ip,range plus extras).

## Stream single-flight
priority: normal
local: core_plugin_lapi_stream-single-flight.md
description: How one DecisionStore skips a stream poll that is already running and publishes health atomically.

## Stream apply
priority: normal
local: core_plugin_lapi_stream-apply.md
description: How this plugin writes one CrowdSec stream payload (deleted before new) into the DecisionStore.

## OriginBasedDecisionRemap
priority: normal
local: core_plugin_lapi_origin-based-decision-remap.md
description: How each Bouncer remaps origin-keyed LAPI types at request apply, including per-list lists:name matching.

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

## Assessment
priority: normal
local: core_plugin_middleware_captcha-assessments.md
description: How recaptcha-enterprise posts a solver token to Cloud assessments and classifies valid, action, and score.

## Widget
priority: normal
local: core_plugin_middleware_captcha-widget.md
description: How captcha construction pairs challenge-page widget data with a verifier and how ServeHTTP renders, retries, or omits boot.

## Captcha enterprise config
priority: normal
local: core_plugin_middleware_captcha-enterprise-config.md
description: How ValidateParams accepts recaptcha-enterprise and gates its key-type, project, API key, action, and min-score knobs.

## Eucaptcha verify
priority: normal
local: core_plugin_middleware_captcha-eucaptcha-verify.md
description: How eucaptcha posts a solver token to EU CAPTCHA /v1/verify and classifies success and train.

## Forced decision header
priority: normal
local: core_plugin_middleware_forced-decision.md
description: How a config-named request header forces ban without lookup, or captcha unless a CrowdSec ban wins.

