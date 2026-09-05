# Bouncer failure action

How CrowdSec remediation components behave when LAPI or AppSec is down, times out, or returns `500`. There is no single ecosystem-wide fail-mode enum.

Fetched: 2026-09-05. Source pins: `github.com/crowdsecurity/cs-firewall-bouncer@1dd4492523e04a25faadc9d87d45a7dc1e06c654`, `github.com/maxlerebourg/crowdsec-bouncer-traefik-plugin@04d928872df12bdb9d953b2d92948e0b89692d6a`. Wire codes: `ext_crowdsec_appsec_protocol/`.

## Official spec: two enums, live-only for LAPI

CrowdSec’s contributing spec for a new bouncer is the strongest owner of the intended knobs. ([bouncer specs](https://docs.crowdsec.net/docs/next/contributing/specs/bouncer_appsec_specs.md), extract `.sources/bouncer_appsec_specs.md`)

**Live mode** (`GET /decisions` per request):

- Timeout if LAPI does not respond. Default **200ms**, field `lapi_timeout`.
- Fallback on that timeout: default **passthrough**. Values: `passthrough`, `ban`, `captcha`. Field **`lapi_failure_action`**.
- Cache per IP, default 1s (`cache_expiration`).

**Stream mode** (`GET /decisions/stream`):

- Default mode in the spec. Pull period default 10s (`stream_update_frequency`).
- The spec does **not** define a fail-open / fail-closed action for a failed poll. It only describes storing deltas and pruning deleted/expired decisions.

**AppSec**:

- Timeout default 200ms (`appsec_timeout`).
- Fallback on timeout **or** response failure (`500`, `401`, …): default **passthrough**. Values: `passthrough`, `ban`, `captcha`. Field **`appsec_failure_action`**.
- One field covers both “AppSec returned 500” and “could not reach AppSec”.

`FALLBACK_REMEDIATION` / `remediation_fallback` is a different knob: unknown **decision type**, not backend unavailability. ([bouncer specs](https://docs.crowdsec.net/docs/next/contributing/specs/bouncer_appsec_specs.md); [nginx](https://docs.crowdsec.net/u/bouncers/nginx), extract `.sources/nginx-bouncer.md`)

There is no official bool named `fail_open`. Open-bastion’s `crowdsec_fail_open` is a third-party SSH integration, not a CrowdSec bouncer. Do not treat it as owner.

## Official vs shipped bouncers: not one enum

| Bouncer | LAPI unreachable / error | AppSec 500 | AppSec unreachable / timeout | Shape |
|---|---|---|---|---|
| Spec (new RC) | Live: `lapi_failure_action` = passthrough\|ban\|captcha (default passthrough). Stream: unspecified. | Same `appsec_failure_action` | Same field (timeout + 500 + 401) | One enum per backend |
| Nginx (lua) | No LAPI fail-open documented. `REQUEST_TIMEOUT` only. | `APPSEC_FAILURE_ACTION` = `passthrough`\|`deny` (default passthrough). Docs: “when AppSec returns a 500”. | Not a separate knob. Timeouts `APPSEC_*_TIMEOUT`. | One AppSec enum; values are **deny**, not spec `ban`/`captcha` |
| Traefik plugin (community, CrowdSec docs) | Live: **no knob** — LAPI error bans. Stream: `updateMaxFailure` then **block all traffic**. | `crowdsecAppsecFailureBlock` bool (default **true** = block) | `crowdsecAppsecUnreachableBlock` bool (default **true** = block) | Two AppSec bools (failure vs unreachable). No LAPI enum. |
| Firewall | No fail-open/closed field. Stream-only. | n/a (no AppSec) | n/a | Keep last ipset while process stays up |

Owners: spec table as above; nginx [APPSEC_FAILURE_ACTION](https://docs.crowdsec.net/u/bouncers/nginx); Traefik [AppSec quickstart](https://docs.crowdsec.net/docs/next/appsec/quickstart/traefik.md) (extract `.sources/appsec-quickstart-traefik.md`) plus [plugin README](https://github.com/maxlerebourg/crowdsec-bouncer-traefik-plugin/blob/04d928872df12bdb9d953b2d92948e0b89692d6a/README.md) (extract `.sources/traefik-plugin-readme.md`); firewall [docs](https://docs.crowdsec.net/u/bouncers/firewall) (extract `.sources/firewall-bouncer.md`) and [config](https://github.com/crowdsecurity/cs-firewall-bouncer/blob/1dd4492523e04a25faadc9d87d45a7dc1e06c654/pkg/cfg/config.go) (extract `.sources/firewall-config.go.md`).

**Official vs official (defaults):** the spec defaults AppSec **and** live-LAPI fallbacks to passthrough (fail-open). Nginx AppSec default is passthrough (matches spec). Traefik AppSec bools default **true** (fail-closed). CrowdSec’s Traefik Kubernetes examples set both bools to `true`. ([appsec quickstart](https://docs.crowdsec.net/docs/next/appsec/quickstart/traefik.md))

**Official vs official (AppSec enum values):** spec `passthrough|ban|captcha`; nginx docs `passthrough|deny`. Follow each bouncer’s own page for that bouncer; follow the spec when writing a new RC.

## Stream mode after repeated LAPI poll failures

### Spec

No “after N failures, block everyone / keep last / pass” rule. ([bouncer specs](https://docs.crowdsec.net/docs/next/contributing/specs/bouncer_appsec_specs.md))

### Firewall (`cs-firewall-bouncer@1dd44925`)

Stream-only. `StreamBouncer.Run` feeds `bouncer.Stream`; the process applies `Deleted` then `New` to iptables/nftables/ipset/pf. A `nil` batch is skipped. There is no path that flushes the set or inserts a default-deny on a missed poll. ([cmd/root.go](https://github.com/crowdsecurity/cs-firewall-bouncer/blob/1dd4492523e04a25faadc9d87d45a7dc1e06c654/cmd/root.go), extract `.sources/firewall-root.go.md`; [yaml](https://github.com/crowdsecurity/cs-firewall-bouncer/blob/1dd4492523e04a25faadc9d87d45a7dc1e06c654/config/crowdsec-firewall-bouncer.yaml))

Official firewall docs list `update_frequency`, `api_url`, `api_key`, `deny_action` (`DROP`\|`REJECT` on matched packets). They do not mention fail-open, fail-closed, or poll-failure behaviour. ([firewall](https://docs.crowdsec.net/u/bouncers/firewall))

Authority **inference** (files read: `cmd/root.go`, `pkg/cfg/config.go`): while the process stays up, last decisions remain in the firewall set; ipset timeouts can still expire entries without a refresh. `go-cs-bouncer` internals were not cloned. If `Run` returns, `Execute` exits and `backend.ShutDown` runs (iptables path flushes/destroys sets) — that is process death, not a poll miss, and would leave no CrowdSec bans (packet-filter fail-open).

### Traefik plugin (`@04d92887`)

Stream/alone: `updateMaxFailure` (default **0**) is “maximum number of times we cannot reach Crowdsec before blocking traffic; `-1` never block”. After that many failed stream updates, `isCrowdsecStreamHealthy` becomes false and **every** uncached request is banned (`ReasonTECH`). A later successful poll restores healthy and cache-miss means allow. Cache hits still apply last decisions. ([README](https://github.com/maxlerebourg/crowdsec-bouncer-traefik-plugin/blob/04d928872df12bdb9d953b2d92948e0b89692d6a/README.md); [bouncer.go](https://github.com/maxlerebourg/crowdsec-bouncer-traefik-plugin/blob/04d928872df12bdb9d953b2d92948e0b89692d6a/bouncer.go), extract `.sources/traefik-bouncer.go.md`)

Default `0` plus `updateFailure >= updateMaxFailure` on the first failed tick means the **first** failed poll marks the stream unhealthy and blocks all new traffic. Set `-1` to keep last decisions forever (never block on poll failure).

`streamStartupBlock` (default true): plugin init waits for the first stream sync. When false, requests bypass remediation until the first sync completes. ([README](https://github.com/maxlerebourg/crowdsec-bouncer-traefik-plugin/blob/04d928872df12bdb9d953b2d92948e0b89692d6a/README.md))

CrowdSec Traefik docs do not document `updateMaxFailure`. Owner for that knob is the plugin README/source.

### Nginx

Official page: stream pulls every `UPDATE_FREQUENCY` seconds (timer starts on first request). No “N failures then block all” knob. ([nginx](https://docs.crowdsec.net/u/bouncers/nginx)) lua-cs-bouncer was not cloned (not in the named-repo list).

## Live mode: per-request LAPI error

### Spec

Timeout → `lapi_failure_action` (default passthrough). ([bouncer specs](https://docs.crowdsec.net/docs/next/contributing/specs/bouncer_appsec_specs.md))

### Nginx

Live: query LAPI per request if IP not in cache (`CACHE_EXPIRATION`). `REQUEST_TIMEOUT` (docs sample 1000ms) applies to LAPI (and captcha provider). No `lapi_failure_action` / fail-open documented. ([nginx](https://docs.crowdsec.net/u/bouncers/nginx))

**Official vs official (same nginx page):** the sample config sets `MODE=stream`; the MODE reference says “The default mode is `live`.”

### Traefik plugin

Live: `handleNoStreamCache` on LAPI HTTP error / unreachable / non-2xx returns `BannedValue`. `ServeHTTP` then remediates (ban). No `lapi_failure_action`. Unreachable includes transport error and `502`/`503`/`504`. ([bouncer.go](https://github.com/maxlerebourg/crowdsec-bouncer-traefik-plugin/blob/04d928872df12bdb9d953b2d92948e0b89692d6a/bouncer.go))

This is fail-closed on live LAPI errors. It conflicts with the spec default passthrough. Follow source for this plugin version; say the spec disagrees.

### Firewall

No live mode. ([firewall](https://docs.crowdsec.net/u/bouncers/firewall) — Stream only)

## AppSec knobs: failure vs unreachable

CrowdSec does **not** document one shared “fail mode” enum used by all bouncers.

- Spec: one AppSec enum (`appsec_failure_action`) covering timeout + 500 + 401.
- Nginx: one enum `APPSEC_FAILURE_ACTION` documented for **500** only (`passthrough`\|`deny`). Ingress-nginx env comment: “What to do if the appsec is down”. ([nginx](https://docs.crowdsec.net/u/bouncers/nginx); [ingress-nginx](https://docs.crowdsec.net/u/bouncers/ingress-nginx), extract `.sources/ingress-nginx.md`)
- Traefik: **two bools**. `crowdsecAppsecFailureBlock` — “If AppSec returns 500, block?”. `crowdsecAppsecUnreachableBlock` — “If AppSec is unreachable, block?”. Defaults true. ([quickstart](https://docs.crowdsec.net/docs/next/appsec/quickstart/traefik.md); [README](https://github.com/maxlerebourg/crowdsec-bouncer-traefik-plugin/blob/04d928872df12bdb9d953b2d92948e0b89692d6a/README.md))

Traefik source treats 502/503/504 as unreachable, `500` as failure, and other non-200 (including `401` and `403`) as ban without the failure bools. Spec wants `401` on the AppSec fallback path. Follow source for the plugin; protocol/spec disagree — see `ext_crowdsec_appsec_protocol/`.

**README vs source (Traefik `CrowdsecAppsecUnreadableBodyBlock`):** README says default `false`; `configuration.New()` sets default `true`. Follow source for this commit. ([configuration.go](https://github.com/maxlerebourg/crowdsec-bouncer-traefik-plugin/blob/04d928872df12bdb9d953b2d92948e0b89692d6a/pkg/configuration/configuration.go), extract `.sources/traefik-configuration.go.md`)

## Design takeaways for AppsecFailMode / LapiFailMode

1. CrowdSec’s written spec is two independent enums (`lapi_failure_action`, `appsec_failure_action`), each `passthrough|ban|captcha`, default fail-open, live-LAPI timeout only; stream poll failure is unspecified.
2. Shipped HTTP bouncers do not implement that spec as written. Nginx uses `passthrough|deny` for AppSec and has no LAPI fail action. Traefik splits AppSec into failure-vs-unreachable bools (default fail-closed) and uses a stream **count then block all** integer plus hardcoded live fail-closed.
3. Firewall has no fail-mode; it is a deny-list. Poll failure ≠ block all traffic.
4. `FALLBACK_REMEDIATION` is not LAPI/AppSec unavailability.

## References

- Official: [bouncer AppSec specs](https://docs.crowdsec.net/docs/next/contributing/specs/bouncer_appsec_specs.md), [nginx bouncer](https://docs.crowdsec.net/u/bouncers/nginx), [firewall bouncer](https://docs.crowdsec.net/u/bouncers/firewall), [Traefik AppSec quickstart](https://docs.crowdsec.net/docs/next/appsec/quickstart/traefik.md), [Traefik bouncer](https://docs.crowdsec.net/u/bouncers/traefik.md), [ingress-nginx](https://docs.crowdsec.net/u/bouncers/ingress-nginx)
- Source: `github.com/crowdsecurity/cs-firewall-bouncer@1dd44925`, `github.com/maxlerebourg/crowdsec-bouncer-traefik-plugin@04d92887`
- Related: `ext_crowdsec_appsec_protocol/`
- Extracts: `.sources/`
