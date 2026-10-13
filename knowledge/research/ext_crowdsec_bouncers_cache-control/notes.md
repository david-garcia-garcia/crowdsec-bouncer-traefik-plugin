# Remediation Cache-Control

How official CrowdSec HAProxy SPOA remediations and the AppSec challenge protocol set `Cache-Control` on captcha, ban, and challenge responses.

Fetched: 2026-09-25.

## Value is exactly `no-cache, no-store`

Official HAProxy SPOA config returns captcha HTML at HTTP 200 and ban HTML at HTTP 403 with `hdr Cache-Control "no-cache, no-store"`. The same directive is on the plain-text fallbacks. No `private`, `max-age`, `must-revalidate`, or `Pragma`. Owner: [HAProxy SPOA](https://docs.crowdsec.net/u/bouncers/haproxy_spoa.md). Extract: `.sources/haproxy_spoa.md`.

The shipped HAProxy example config matches that string. The Go response writer in the SPOA agent sets `Cache-Control: no-cache, no-store` when the header is still empty. Owners: `github.com/crowdsecurity/cs-haproxy-spoa-bouncer@60de9e913d65816d24e37bf6f8d33435a2aeae6c:README.md`, `config/haproxy.cfg`, `pkg/spoa/root.go`. Extracts: `.sources/readme.md`, `.sources/haproxy.cfg.md`, `.sources/root.go.md`.

Official AppSec bot-detection challenge protocol example puts `"Cache-Control": ["no-cache, no-store"]` on the challenge HTML envelope next to `Content-Type` and `Content-Security-Policy`. Owner: [challenge protocol](https://docs.crowdsec.net/docs/next/appsec/bot_detection/challenge_protocol.md). Extract: `.sources/challenge_protocol.md`.

Engine `setChallengeResponse` uses the same value on challenge submit JSON (`Content-Type: application/json` plus `Cache-Control: no-cache, no-store`). Owner: `github.com/crowdsecurity/crowdsec@9bbafcdef5f848d89caf621ba1a54a1672856071:pkg/appsec/appsec.go`. Extract: `.sources/appsec.go.md`.

## What this is not

This finding is the header string official CrowdSec remediations emit. It is not how a CDN keys or TTLs a response, and it is not this plugin's AppSec envelope relay (`user_headers` copy stays on `core_plugin_appsec`).

## Sources

- Official: [HAProxy SPOA](https://docs.crowdsec.net/u/bouncers/haproxy_spoa.md)
- Official: [Bot Detection Challenge Protocol](https://docs.crowdsec.net/docs/next/appsec/bot_detection/challenge_protocol.md)
- Source: `github.com/crowdsecurity/cs-haproxy-spoa-bouncer@60de9e913d65816d24e37bf6f8d33435a2aeae6c`
- Source: `github.com/crowdsecurity/crowdsec@9bbafcdef5f848d89caf621ba1a54a1672856071:pkg/appsec/appsec.go`
- Extracts: `.sources/`
