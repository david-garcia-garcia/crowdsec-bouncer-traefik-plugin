# AppSec protocol

Official CrowdSec WAF / bouncer HTTP contract: headers, methods, and response codes a remediation component must honour.

Fetched: 2026-09-05. Docs: CrowdSec v1.8 protocol page. Source pin for the Traefik plugin: `github.com/maxlerebourg/crowdsec-bouncer-traefik-plugin@04d928872df12bdb9d953b2d92948e0b89692d6a`.

## What the bouncer sends

The AppSec component is an out-of-band HTTP oracle. The remediation component forwards a copy of the original request (headers plus body) plus CrowdSec headers. ([protocol](https://docs.crowdsec.net/docs/appsec/protocol), extract `.sources/appsec-protocol.md`)

Required headers ([protocol](https://docs.crowdsec.net/docs/appsec/protocol)):

| Header | Meaning |
|---|---|
| `X-Crowdsec-Appsec-Ip` | Real client IP of the original request |
| `X-Crowdsec-Appsec-Uri` | Original URI |
| `X-Crowdsec-Appsec-Host` | Original Host |
| `X-Crowdsec-Appsec-Verb` | Original method |
| `X-Crowdsec-Appsec-Api-Key` | Bouncer API key (same key used to pull LAPI) |
| `X-Crowdsec-Appsec-User-Agent` | Original User-Agent |
| `X-Crowdsec-Appsec-Http-Version` | Original HTTP version as integer (`10`, `11`, …) |

Method: forward as `GET` unless the original request has a body, then `POST`. ([protocol](https://docs.crowdsec.net/docs/appsec/protocol))

**Official vs official (auth header name):** the contributing spec says AppSec auth is header **`X-Api-Key`**, same param as LAPI. ([bouncer specs](https://docs.crowdsec.net/docs/next/contributing/specs/bouncer_appsec_specs.md), extract `.sources/bouncer_appsec_specs.md`) The protocol page and the Traefik plugin send **`X-Crowdsec-Appsec-Api-Key`**. Follow the protocol page and Traefik source for the wire header. ([bouncer.go](https://github.com/maxlerebourg/crowdsec-bouncer-traefik-plugin/blob/04d928872df12bdb9d953b2d92948e0b89692d6a/bouncer.go), extract `.sources/bouncer.go.md`)

Default AppSec listen URL in the spec: `http://127.0.0.1:7422`. ([bouncer specs](https://docs.crowdsec.net/docs/next/contributing/specs/bouncer_appsec_specs.md))

## Response codes a bouncer must honour

| HTTP code | Official meaning | Body | What the bouncer should do |
|---|---|---|---|
| `200` | Request allowed | `{"action": "allow"}` | Allow. |
| `403` | One or more AppSec rules triggered | JSON with `action` (`ban`, `captcha`, or `challenge`) and usually `http_status` | Apply that action. For `challenge`, relay `http_status` / body / headers / cookies; do not return the AppSec `403` to the browser. |
| `500` | Error inside the AppSec component | `null` | Use the configured AppSec failure action (`APPSEC_FAILURE_ACTION`). |
| `401` | Bouncer not authenticated | `null` | Same API key as LAPI. Spec: treat as forwarding/auth failure and run the same fallback as `500`. |

Owners: [protocol](https://docs.crowdsec.net/docs/appsec/protocol) for 200 / 403 / 500 / 401 and bodies; [challenge protocol](https://docs.crowdsec.net/docs/next/appsec/bot_detection/challenge_protocol.md) (extract `.sources/challenge-protocol.md`) for `challenge` and the failure table; [bouncer specs](https://docs.crowdsec.net/docs/next/contributing/specs/bouncer_appsec_specs.md) for “500 and 401 trigger fallback”.

The protocol page itself says a remediation component **must support** an `APPSEC_FAILURE_ACTION` parameter for `500`. It does not name a parameter for `401`; the spec and the challenge-protocol failure table do. ([protocol](https://docs.crowdsec.net/docs/appsec/protocol); [challenge protocol](https://docs.crowdsec.net/docs/next/appsec/bot_detection/challenge_protocol.md))

## `403` is a verdict, not a failure

A `403` from AppSec is a successful evaluation that found a match. The body names the action. ([protocol](https://docs.crowdsec.net/docs/appsec/protocol))

Challenge-protocol extra rules ([challenge protocol](https://docs.crowdsec.net/docs/next/appsec/bot_detection/challenge_protocol.md)):

- `403` + `action: challenge` + non-empty `user_body_content` → serve the challenge (`http_status` to the browser, default 200 if absent/zero).
- `403` + `action: challenge` + empty body → fail closed (`ban`).
- `403` + any other action → apply it.
- `403` + empty body or invalid JSON → `ban`.
- Do not leak the AppSec JSON envelope to the browser on a block.

## `500` / `401` / unexpected / timeout are failures

Spec: timeout, `500`, `401`, and similar response failures all share one fallback field `appsec_failure_action`. Default **passthrough** (let the request through). Possible values: `passthrough`, `ban`, `captcha`. Default timeout **200ms** (`appsec_timeout`). AppSec forwarding is a blocking wait. ([bouncer specs](https://docs.crowdsec.net/docs/next/contributing/specs/bouncer_appsec_specs.md))

Challenge protocol: `401`, `500`, or an unexpected status → the component’s configured AppSec failure behaviour (`APPSEC_FAILURE_ACTION`). ([challenge protocol](https://docs.crowdsec.net/docs/next/appsec/bot_detection/challenge_protocol.md))

Unreachable (dial/timeout, no HTTP response) is not a protocol status. The spec folds it into the same timeout/fallback. Traefik splits it from `500` — see `ext_crowdsec_bouncers_failure-action/`.

## Traefik plugin vs protocol (this version)

Follow source for what `maxlerebourg/crowdsec-bouncer-traefik-plugin@04d92887` does; official protocol disagrees on several points. ([bouncer.go](https://github.com/maxlerebourg/crowdsec-bouncer-traefik-plugin/blob/04d928872df12bdb9d953b2d92948e0b89692d6a/bouncer.go))

- Auth header matches the protocol (`X-Crowdsec-Appsec-Api-Key`), not the spec’s `X-Api-Key`.
- `500` → `CrowdsecAppsecFailureBlock` (bool, default true = block). Not the spec enum.
- Network error or HTTP `502`/`503`/`504` → `CrowdsecAppsecUnreachableBlock` (bool, default true = block).
- Any other non-200, including protocol `401` and protocol `403`, returns an error and the request is banned. The plugin does **not** parse the `403` JSON `action` body.
- It does not send `X-Crowdsec-Appsec-Http-Version`.

## References

- Official: [WAF / Bouncer communication protocol](https://docs.crowdsec.net/docs/appsec/protocol), [challenge protocol](https://docs.crowdsec.net/docs/next/appsec/bot_detection/challenge_protocol.md), [bouncer AppSec specs](https://docs.crowdsec.net/docs/next/contributing/specs/bouncer_appsec_specs.md)
- Source: `github.com/maxlerebourg/crowdsec-bouncer-traefik-plugin@04d92887:bouncer.go`
- Related finding: `ext_crowdsec_bouncers_failure-action/`
- Extracts: `.sources/`
