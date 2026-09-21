# Requirement
IssueKey: 2026-09-21-bouncer-instance-severance

## Problem
Every Traefik middleware `New` both opens LAPI/AppSec clients and bounces this router. Sharing is implicit (identity hash) so every bouncing router must copy LAPI/AppSec YAML. Operators need named shareable clients, per-route bounce policy, optional dummy routers, and a domain-prefixed public config. One middleware must still be able to open both clients and bounce.

## Current (code)
- `plugin.go` — every `New` prepares LAPI and AppSec, opens LAPI unless `crowdsecMode` is `appsec`, opens AppSec when `crowdsecAppsecEnabled`, returns `bouncer.New` with those clients.
- `pkg/configuration/configuration.go` — one `Config`: modes `none|live|stream|alone|appsec`; keys mixed `crowdsec*` / unprefixed (`updateIntervalSeconds`, `captcha*`, `redisCache*`); `Enabled` default false pass-through.
- `pkg/bouncer/bouncer.go` — `ServeHTTP` remediates on every mode when `enabled`; holds `*lapi.Client` and `*appsec.Client` from construct.
- `pkg/lapi/session.go` — reclaim by URL+key (+ Redis); exclusive Traefik `name` on DecisionStore; no operator instance name.
- `pkg/appsec/session.go` — reclaim by listener URL+key+bodyLimit.
- `README.md` — modes as decision source; AppSec orthogonal; no named instances or dummy-router docs.

## Desired
- `lapiEnabled` (default true) and `appsecEnabled` (default false) choose which legs this middleware uses.
- `lapiInstance` / `appsecInstance`: empty means this Traefik name; with secrets → Open; without secrets → subscribe; disabled + leftover secrets/name → error; enabled + no secrets + no name → error.
- `lapiMode` is fetch strategy only (`live|stream|none|alone`). Remove `appsec` mode. AppSec-only = `lapiEnabled: false` + `appsecEnabled: true`.
- One middleware may Open LAPI and AppSec together and bounce.
- `bouncerEnabled` replaces `enabled` (default false, call next).
- `bouncerHold` (default false): Open configured clients; `ServeHTTP` 503 if the route matches (placeholder). Dummy router optional when a real route already Opens.
- Bouncing `New` must not wait for named clients. Missing slot at request time uses `bouncerLapiFailureAction` / `bouncerAppsecFailureAction`.
- Rename all public keys to `lapi*` / `appsec*` / `bouncer*` domains; keep `log*` and `httpTimeoutSeconds`. Do not accept old keys.
- README explains optional dummy routers for shared clients vs bouncing routers that subscribe; one-middleware setup remains valid.
- Beta: breaking YAML is acceptable.

## Affected
- `plugin.go`, `pkg/configuration/configuration.go`, `pkg/bouncer/bouncer.go`, `pkg/lapi/`, `pkg/appsec/`, `pkg/reclaim/` (if a named slot needs it), `README.md`, `docs/modes.md`, `examples/`, `tests/e2e/`, unit tests that set Config fields/JSON tags.

## Out of scope
- Decision remapping as a new product feature (ticket listed it as an example of cheap bouncer knobs; it does not exist yet).
- Traefik core changes.
- Accepting old YAML keys as aliases.

## Unknowns
- Exact named-slot implementation (Peek vs extra reclaim key) — explore.
- Whether `lapiScopeHeaders` stays opener-only (no live union from bouncing subscribers).

## Tensions
- First dump asked `crowdsecMode=bouncer` as the only bouncing mode and dummy routers always; confirmed spec keeps one-middleware bounce+open and optional hold.
- First dump left `crowdsecAppsecEnabled` vs `crowdsecMode=appsec` open; confirmed spec uses `lapiEnabled`/`appsecEnabled` and deletes `appsec` mode.
