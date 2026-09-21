# Source (local)

Per-route bounce policy with shared LAPI and AppSec clients. One middleware may still declare all three jobs. Dummy routers are optional (only when no real route should own the clients). Beta: breaking YAML is acceptable.

## Jobs on one middleware

- Open a named LAPI client, a named AppSec client, both, or neither.
- Bounce this router's requests using those clients (or subscribed names).
- `bouncerHold` publishes clients and rejects traffic (placeholder). Default false.

`bouncerEnabled` is today's `enabled` (default false, skip to next). It is not "this is a bouncer-only mode."

## Enable flags

- `lapiEnabled` (default true): this middleware uses the LAPI leg.
- `appsecEnabled` (default false): this middleware uses the AppSec leg.
- Secrets on this middleware + enabled → Open that named instance.
- `lapiInstance` / `appsecInstance` + enabled + no secrets → subscribe by name (do not Open).
- Empty instance name → this Traefik middleware name.
- Enabled + no secrets + no instance name → config error.
- Disabled + leftover secrets or instance name → config error.

## Mode

`lapiMode` is only how a LAPI client fetches: `live` | `stream` | `none` | `alone`. Value `appsec` is removed. AppSec-only is `lapiEnabled: false` + `appsecEnabled: true`. Read `lapiMode` only when this middleware Opens LAPI.

## Startup order

A bouncing router may `New` before the named clients exist. `New` must not wait. Request path loads the slot; missing client uses `bouncerLapiFailureAction` / `bouncerAppsecFailureAction`. Do not block the Traefik constructor.

## Placeholder

`bouncerHold: true` still Opens configured clients. `ServeHTTP` returns 503 (not 403). Dummy router remains required for Traefik to call `New` when no real route owns the clients. README must explain: optional dummy for shared clients; bouncing routers subscribe by instance name; one middleware can still open both clients and bounce.

## Config rename

All public keys are domain-prefixed. Drop the `crowdsec` repeat. Old keys are not accepted.

- LAPI client: `lapi*` (including CAPI and Redis store).
- AppSec client: `appsec*`.
- Bouncer: `bouncer*` (captcha, templates, headers, trusted IPs, failure actions, live TTL).
- Keep `logLevel` / `logFormat` / `logFilePath` and `httpTimeoutSeconds`.

TLS client cert: `lapiTlsCert` / `lapiTlsKey` (not CertificateBouncer).

## Settings split

Fetch knobs (`lapiLapiUpdateIntervalSeconds`, Redis, `lapiScopeHeaders`, body limit, TLS) live on the opener. Per-route knobs (remediation header/status, failure actions, captcha, trusted IPs) live on bouncing middlewares. Decision remap is not required in this change.

Target branch is master.
