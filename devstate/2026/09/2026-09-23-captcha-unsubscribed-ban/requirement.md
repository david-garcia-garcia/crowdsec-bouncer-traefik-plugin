# Requirement
IssueKey: 2026-09-23-captcha-unsubscribed-ban

## Problem
A bouncing router that is not subscribed to a captcha instance can still receive a captcha remediation (LAPI captcha kind, forced header `c`, or a captcha failure-action path). Today that request already becomes a ban, but the operator is not told that a captcha could not be served because this router never subscribed.

## Current (code)
- Subscribe is `BouncerEnabled` plus a non-empty `CaptchaInstanceName`: `plugin.go` `New` sets `subscribeCaptcha` and only then `reclaim.Watch`es captcha.
- A bounce-only `New` does not build a local captcha client: `pkg/bouncer/bouncer.go` `New`.
- A captcha kind with an empty or invalid loaded client remediates as ban and does not log WARN: `pkg/bouncer/bouncer.go` `handleRemediationServeHTTP`.
- Startup-block 503 plus WARN `crowdsec bouncer backend missing` runs only when this router **did** subscribe and the client is still nil: `pkg/bouncer/bouncer.go` `ServeHTTP`.
- Spec already requires a captcha verdict without a published client to ban: `openspec/specs/core_plugin_middleware_bouncer/spec.md`. It does not require a misconfiguration WARN for the unsubscribed case.

## Desired
When this router is not subscribed to a captcha provider and a captcha remediation/signal arrives, degrade to BAN and emit a WARN that captcha could not be served due to a misconfiguration.

## Affected
- `pkg/bouncer/bouncer.go` — captcha kind with no subscribe / no client
- `plugin.go` — `subscribeCaptcha` gate (read, not a new knob)

## Out of scope
- Changing subscribed-but-unpublished behavior (startup-block 503 vs ban when block is off).
- Serving a captcha challenge without a published client.
- New public config keys, or making `bouncerLapiFailureAction` / `bouncerAppsecFailureAction` `captcha` legal without a captcha instance name.

## Unknowns
- Exact WARN message text.
- Whether WARN is once per binding or on every remediating request.
- Whether "signal" is only LAPI captcha kind, or also forced header `c` and captcha failure-action (those already reach `handleRemediationServeHTTP`).

## Tensions
- Ticket asks BAN + WARN for **not subscribed**. Dest already BANs any captcha kind with a nil/invalid client (`handleRemediationServeHTTP`), including subscribed-unpublished with startup-block off. WARN is the gap; treating unpublished-subscribed the same as unsubscribed is not asked.
- Live spec `core_plugin_middleware_bouncer` already says captcha without a published client is a ban and does not mention WARN.
