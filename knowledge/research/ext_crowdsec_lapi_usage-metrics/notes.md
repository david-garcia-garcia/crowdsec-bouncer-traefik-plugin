# LAPI usage-metrics

What CrowdSec LAPI accepts on `POST /v1/usage-metrics` from a remediation component (bouncer), which metric item names and units the official docs ask for, which item labels LAPI actually stores or displays, and what two official bouncers send today.

Fetched: 2026-09-05. Engine pin: `github.com/crowdsecurity/crowdsec@909b5157986a2b2c2163300fdaef5ed01289f7d2`. Lua pin: `github.com/crowdsecurity/lua-cs-bouncer@59f3521e3918377fc1eb97d59a4056b6e9f5782f`. Firewall pin: `github.com/crowdsecurity/cs-firewall-bouncer@1dd4492523e04a25faadc9d87d45a7dc1e06c654`.

`github.com/crowdsecurity/go-cs-bouncer` was **not** cloned. Neither the CrowdSec engine nor official docs name it as the bouncer metrics client. The firewall bouncer `go.mod` depends on it for `NewMetricsProvider`; this finding reports only what that bouncer fills into `RemediationComponentsMetrics.Metrics` itself.

This worktree already POSTs a single `dropped` counter from `pkg/crowdsecconnection/connection.go` `reportMetrics`. That is **not** the owner of LAPI behavior; it is compared at the end.

## Route and auth

`POST /v1/usage-metrics` is registered on the LAPI v1 group with **either** API-key or JWT auth. A bouncer uses `X-Api-Key`. Owner: [controller.go](https://github.com/crowdsecurity/crowdsec/blob/909b5157986a2b2c2163300fdaef5ed01289f7d2/pkg/apiserver/controllers/controller.go). Extract: `.sources/controller.go.md`

Swagger: body is `AllMetrics`; documented success is **200**. Handler returns **201 Created** (`gctx.Status(http.StatusCreated)`). Tests assert `http.StatusCreated`. Follow source for this pin. Owners: [swagger](https://github.com/crowdsecurity/crowdsec/blob/909b5157986a2b2c2163300fdaef5ed01289f7d2/pkg/models/localapi_swagger.yaml); [UsageMetrics](https://github.com/crowdsecurity/crowdsec/blob/909b5157986a2b2c2163300fdaef5ed01289f7d2/pkg/apiserver/controllers/v1/usagemetrics.go); [usage_metrics_test.go](https://github.com/crowdsecurity/crowdsec/blob/909b5157986a2b2c2163300fdaef5ed01289f7d2/pkg/apiserver/usage_metrics_test.go). Extracts: `.sources/localapi_swagger.yaml.md`, `.sources/usagemetrics.go.md`, `.sources/usage_metrics_test.go.md`

A bouncer payload must contain exactly one `remediation_components` entry (zero → 400 "Missing remediation component data"; more than one → 400). JWT (log-processor) auth with an RC body is 400 "Missing log processor data". Owner: [UsageMetrics](https://github.com/crowdsecurity/crowdsec/blob/909b5157986a2b2c2163300fdaef5ed01289f7d2/pkg/apiserver/controllers/v1/usagemetrics.go)

## JSON payload LAPI accepts

Top-level `AllMetrics`: `remediation_components`, `log_processors`, `lapi`. A bouncer sends `remediation_components`. Owner: [swagger AllMetrics](https://github.com/crowdsecurity/crowdsec/blob/909b5157986a2b2c2163300fdaef5ed01289f7d2/pkg/models/localapi_swagger.yaml)

Each remediation-component object is `RemediationComponentsMetrics` = `BaseMetrics` plus:

| field | swagger | required |
| --- | --- | --- |
| `type` | string, type of the RC | no |
| `name` | string, name of the RC | no |
| `last_pull` | integer | no |
| `version` | string, max 255 | **yes** |
| `utc_startup_timestamp` | integer | **yes** |
| `os` | `OSversion` | no; if present, `name` and `version` are required (max 255); `family` optional |
| `feature_flags` | array of string, max 255 per item; "expected to be empty for remediation components" | no (omit is 201) |
| `metrics` | **array** of `DetailedMetrics` | no (empty array is 201) |

Each `DetailedMetrics`: required `meta` (`window_size_seconds`, `utc_now_timestamp`) and required `items` (array of `MetricsDetailItem`).

Each item: required `name` (string, max 255), `value` (number), `unit` (string, max 255); optional `labels` (`map[string]string`, each **value** max 255). There is **no enum** of item names, units, or label keys. Owner: [swagger](https://github.com/crowdsecurity/crowdsec/blob/909b5157986a2b2c2163300fdaef5ed01289f7d2/pkg/models/localapi_swagger.yaml); generated [MetricsDetailItem](https://github.com/crowdsecurity/crowdsec/blob/909b5157986a2b2c2163300fdaef5ed01289f7d2/pkg/models/metrics_detail_item.go), [MetricsLabels](https://github.com/crowdsecurity/crowdsec/blob/909b5157986a2b2c2163300fdaef5ed01289f7d2/pkg/models/metrics_labels.go). Extracts: `.sources/localapi_swagger.yaml.md`, `.sources/metrics_detail_item.go.md`, `.sources/metrics_labels.go.md`

`feature_flags` is `[]string`. An object `{}` fails bind with 400 (`cannot unmarshal object into Go struct field AllMetrics.remediation_components.feature_flags of type []string`). Owner: generated [BaseMetrics](https://github.com/crowdsecurity/crowdsec/blob/909b5157986a2b2c2163300fdaef5ed01289f7d2/pkg/models/base_metrics.go). Extract: `.sources/base_metrics.go.md`

**Official vs source (`metrics` shape):** the remediation-metrics spec example and its `buildUsageMetrics` pseudocode send `"metrics": { "meta": ..., "items": ... }` (one object). Swagger and Go are `"metrics": [ { "meta": ..., "items": ... } ]` (array). The RC tests POST an array. Follow source. Official owner: [bouncer_metrics_specs](https://docs.crowdsec.net/docs/next/contributing/specs/bouncer_metrics_specs). Extract: `.sources/bouncer_metrics_specs.md`

## Metric names and units (docs vs accept)

LAPI **accepts any** item `name`/`unit` that pass max-length. The RC test posts `name: "foo"`, `unit: "bla"` and gets 201. Owner: [usage_metrics_test.go](https://github.com/crowdsecurity/crowdsec/blob/909b5157986a2b2c2163300fdaef5ed01289f7d2/pkg/apiserver/usage_metrics_test.go)

Official docs tell a bouncer to send these three names:

- `dropped` — units `byte`, `packet`, or `request`; split by origin/remediation
- `processed` — same units; includes bypass
- `active_decisions` — unit must be `ip`

Owner: [bouncer_metrics_specs](https://docs.crowdsec.net/docs/next/contributing/specs/bouncer_metrics_specs)

`cscli metrics show bouncers` treats `active_decisions` (or any name ending `_gauge`) as a gauge (last value wins); every other name is summed. Display pluralizes `byte`/`packet`/`ip` only. Owner: [statbouncer.go](https://github.com/crowdsecurity/crowdsec/blob/909b5157986a2b2c2163300fdaef5ed01289f7d2/cmd/crowdsec-cli/climetrics/statbouncer.go). Extract: `.sources/statbouncer.go.md`

**Official vs official (stale AppSec spec):** [bouncer_appsec_specs](https://docs.crowdsec.net/docs/next/contributing/specs/bouncer_appsec_specs) still samples item name `blocked`, label `remediation_type`, top-level `features` (not `feature_flags`), and puts `meta` beside `metrics` instead of inside each metrics window. Follow swagger/source for this pin. Extract: `.sources/bouncer_appsec_specs.md`

## Label keys: what LAPI stores vs what it displays

Swagger `MetricsLabels` is an open `map[string]string`. LAPI does **not** whitelist `origin`, `remediation`, `ip_type`, `scenario`, `type`, or `name`. A `scenario` label is accepted and stored if sent. Owner: [swagger MetricsLabels](https://github.com/crowdsecurity/crowdsec/blob/909b5157986a2b2c2163300fdaef5ed01289f7d2/pkg/models/localapi_swagger.yaml)

What LAPI **stores**:

1. **Metric snapshot row** (`generated_type=RC`, `generated_by` = authenticated **bouncer row name**, not payload `name`): JSON `{"type": <payload type>, "metrics": <payload metrics array>}`. Every item label in that array is kept verbatim, including keys LAPI never looks at. Owner: [UsageMetrics](https://github.com/crowdsecurity/crowdsec/blob/909b5157986a2b2c2163300fdaef5ed01289f7d2/pkg/apiserver/controllers/v1/usagemetrics.go); [CreateMetric](https://github.com/crowdsecurity/crowdsec/blob/909b5157986a2b2c2163300fdaef5ed01289f7d2/pkg/database/metrics.go); [metric schema](https://github.com/crowdsecurity/crowdsec/blob/909b5157986a2b2c2163300fdaef5ed01289f7d2/pkg/database/ent/schema/metric.go). Extracts: `.sources/metrics.go.md`, `.sources/metric.go.md`
2. **Bouncer row** via `BouncerUpdateBaseMetrics`: `version`, `osname`/`osfamily`/`osversion`, `featureflags` (comma-joined), and `type` set from the **context bouncer.Type** (already on the row), **not** from payload `type`. Payload `name` is not written to the row. Owner: [bouncers.go](https://github.com/crowdsecurity/crowdsec/blob/909b5157986a2b2c2163300fdaef5ed01289f7d2/pkg/database/bouncers.go); [bouncer schema](https://github.com/crowdsecurity/crowdsec/blob/909b5157986a2b2c2163300fdaef5ed01289f7d2/pkg/database/ent/schema/bouncer.go). Extracts: `.sources/bouncers.go.md`, `.sources/bouncer_schema.go.md`

Row `type`/`version` are normally stamped from `User-Agent` `type/version` on API-key requests, not from the usage-metrics JSON. Owner: [api_key.go](https://github.com/crowdsecurity/crowdsec/blob/909b5157986a2b2c2163300fdaef5ed01289f7d2/pkg/apiserver/middlewares/v1/api_key.go). Extract: `.sources/api_key.go.md`

CAPI export rebuilds the RC envelope from the **bouncer row** (`Name`, `Type`, OS, feature flags, version) and appends the stored `metrics` array. The snapshot's `"type"` field is dropped on unmarshal (`dbPayload` only has `metrics`). Item labels are forwarded as stored. Owner: [apic_metrics.go](https://github.com/crowdsecurity/crowdsec/blob/909b5157986a2b2c2163300fdaef5ed01289f7d2/pkg/apiserver/apic_metrics.go). Extract: `.sources/apic_metrics.go.md`

What LAPI **displays**:

- `cscli metrics show bouncers` reads **only** `item.Labels["origin"]` and `item.Labels["ip_type"]`. It never reads `scenario`, `remediation`, `remediation_type`, `type`, or `name`. Empty `origin` is omitted from table rows (totals still include it — typical `processed` items). Owner: [statbouncer.go](https://github.com/crowdsecurity/crowdsec/blob/909b5157986a2b2c2163300fdaef5ed01289f7d2/cmd/crowdsec-cli/climetrics/statbouncer.go)
- `cscli bouncers inspect` shows row `Type`, `Version`, `OS`, `Feature Flags` — not item labels. Owner: [inspect.go](https://github.com/crowdsecurity/crowdsec/blob/909b5157986a2b2c2163300fdaef5ed01289f7d2/cmd/crowdsec-cli/clibouncer/inspect.go). Extract: `.sources/inspect.go.md`

Official supported **item** labels (docs, not schema): `origin`, `remediation`, `ip_type`. Not `scenario`. Owner: [bouncer_metrics_specs](https://docs.crowdsec.net/docs/next/contributing/specs/bouncer_metrics_specs)

Official origin **values**: `crowdsec`, `CAPI`, `cscli`, `cscli-import`, `appsec`, `console`, `lists:XXX`. Owner: [usage_metrics](https://docs.crowdsec.net/docs/next/observability/usage_metrics). Extract: `.sources/usage_metrics.md`

## `scenario` is not a usage-metrics label

LAPI usage-metrics has no `scenario` field and no `scenario` label key in swagger or cscli.

Official bouncers fold list identity into **`origin`**: when the decision `origin` is `lists`, they rewrite it to `lists:` + the decision's `scenario` (list name) and then use that string as the `origin` label. They do **not** send a `scenario` label. Owners: [lua stream.lua](https://github.com/crowdsecurity/lua-cs-bouncer/blob/59f3521e3918377fc1eb97d59a4056b6e9f5782f/lib/plugins/crowdsec/stream.lua); [lua live.lua](https://github.com/crowdsecurity/lua-cs-bouncer/blob/59f3521e3918377fc1eb97d59a4056b6e9f5782f/lib/plugins/crowdsec/live.lua); [firewall iptables_context.go](https://github.com/crowdsecurity/cs-firewall-bouncer/blob/1dd4492523e04a25faadc9d87d45a7dc1e06c654/pkg/iptables/iptables_context.go) (comment: other origins' scenarios are "too noisy"). Extracts: `.sources/stream.lua.md`, `.sources/live.lua.md`, `.sources/iptables_context.go.md`

nftables in the same firewall bouncer uses a hyphen: `lists-` + scenario. Owner: [nftables.go](https://github.com/crowdsecurity/cs-firewall-bouncer/blob/1dd4492523e04a25faadc9d87d45a7dc1e06c654/pkg/nftables/nftables.go). Extract: `.sources/nftables.go.md`

The observability page's mention of "scenarios" is about **decision-stream filters**, not usage-metrics labels. Owner: [usage_metrics](https://docs.crowdsec.net/docs/next/observability/usage_metrics)

## What official bouncers send today

Official metrics spec names the LUA library (NGINX), the PHP library (WordPress), and the firewall bouncer. AppSec spec links [lua-cs-bouncer](https://github.com/crowdsecurity/lua-cs-bouncer/) and [cs-nginx-bouncer](https://github.com/crowdsecurity/cs-nginx-bouncer). Firewall docs clone [cs-firewall-bouncer](https://github.com/crowdsecurity/cs-firewall-bouncer). PHP was not cloned (no GitHub URL on the metrics-spec page).

### lua-cs-bouncer (NGINX / OpenResty)

Envelope: `type` = `lua-bouncer`, `name` = `nginx bouncer`, `version` = User-Agent string, `os.name`/`os.version` from OS release, `utc_startup_timestamp`, `feature_flags` forced to JSON `[]` (Alpine lua-cjson would otherwise emit `{}` and LAPI 400). `metrics` is an **array** of one window. Also sends `"log_processors": null`. Owner: [metrics.lua](https://github.com/crowdsecurity/lua-cs-bouncer/blob/59f3521e3918377fc1eb97d59a4056b6e9f5782f/lib/plugins/crowdsec/metrics.lua). Extract: `.sources/metrics.lua.md`

Items:

| name | unit | labels |
| --- | --- | --- |
| `processed` | `request` | `ip_type` only |
| `dropped` | `request` | `ip_type`, `origin` |
| `active_decisions` | `ip` | `ip_type`, `origin` |

No `remediation` / `remediation_type` label. No `scenario` label. Tests assert `metrics[1].items` (array). Owners: [crowdsec.lua](https://github.com/crowdsecurity/lua-cs-bouncer/blob/59f3521e3918377fc1eb97d59a4056b6e9f5782f/lib/crowdsec.lua); [t/11_live_ban_and_metrics.t](https://github.com/crowdsecurity/lua-cs-bouncer/blob/59f3521e3918377fc1eb97d59a4056b6e9f5782f/t/11_live_ban_and_metrics.t). Extracts: `.sources/crowdsec.lua.md`, `.sources/11_live_ban_and_metrics.t.md`

### cs-firewall-bouncer

`type` constant `crowdsec-firewall-bouncer`. User-Agent `crowdsec-firewall-bouncer/<version>`. Metrics items filled locally; envelope POST is `go-cs-bouncer.NewMetricsProvider` (not inspected). Owner: [root.go](https://github.com/crowdsecurity/cs-firewall-bouncer/blob/1dd4492523e04a25faadc9d87d45a7dc1e06c654/cmd/root.go). Extract: `.sources/root.go.md`

Items:

| name | unit | labels |
| --- | --- | --- |
| `dropped` | `byte` and `packet` | `origin`, `ip_type` |
| `processed` | `byte` and `packet` | `ip_type` only |
| `active_decisions` | `ip` | `origin`, `ip_type` |

No `remediation` label (firewall is ban-only). No `scenario` label. Owner: [pkg/metrics/metrics.go](https://github.com/crowdsecurity/cs-firewall-bouncer/blob/1dd4492523e04a25faadc9d87d45a7dc1e06c654/pkg/metrics/metrics.go). Extract: `.sources/fw_metrics.go.md`

Official firewall docs: dropped bytes/packets per origin; processed only on the Total line; `active_decisions IPs`. Owner: [firewall](https://docs.crowdsec.net/u/bouncers/firewall). Extract: `.sources/firewall.md`

## Docs vs source conflicts (summary)

| claim | official | source (this pin) | follow |
| --- | --- | --- | --- |
| HTTP success | swagger 200 | handler 201 Created | source |
| `metrics` JSON | object `{meta, items}` in metrics spec | array `[{meta, items}]` | source |
| item names | `dropped` / `processed` / `active_decisions` | any string (max 255) | source for accept; docs for intended names |
| labels | `origin`, `remediation`, `ip_type` | any keys stored; cscli shows `origin` + `ip_type` only | source for store/display |
| `scenario` | not a usage-metrics label; `lists:XXX` origin | accepted if sent; official bouncers put list name in `origin` | source |
| AppSec spec sample | `blocked`, `remediation_type`, `features` | `dropped`, `feature_flags` `[]string`, metrics array | source (AppSec spec stale) |
| `feature_flags` | empty array | `[]string`; `{}` is 400 | source |

## This worktree (not LAPI owner)

`reportMetrics` POSTs `remediation_components[0]` with `type` `bouncer`, `name` `traefik_plugin`, `feature_flags` `[]`, `os` unknown/unknown, `metrics` as an **array** (matches LAPI), one item `dropped` / `request` / labels `type=traefik_plugin`. It does not send `processed`, `active_decisions`, `origin`, `ip_type`, or `remediation`. Path: `pkg/crowdsecconnection/connection.go`. LAPI will 201 and store the `type` label; `cscli metrics show bouncers` will not show it as an origin row.

## References

- Official: [Remediation Component Metrics](https://docs.crowdsec.net/docs/next/contributing/specs/bouncer_metrics_specs), [Usage Metrics](https://docs.crowdsec.net/docs/next/observability/usage_metrics), [AppSec/RC specs](https://docs.crowdsec.net/docs/next/contributing/specs/bouncer_appsec_specs), [Firewall bouncer](https://docs.crowdsec.net/u/bouncers/firewall)
- Source: `github.com/crowdsecurity/crowdsec@909b5157` paths above
- Official bouncers: `github.com/crowdsecurity/lua-cs-bouncer@59f3521e`, `github.com/crowdsecurity/cs-firewall-bouncer@1dd44925`
- Extracts: `.sources/`
