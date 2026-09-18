# Stream apply order

How official CrowdSec bouncers apply `new` vs `deleted` on one `GET /v1/decisions/stream` payload, and whether a same-window replacement (new ban plus deleted prior for the same IP or CIDR) stays active.

Fetched: 2026-09-18. Pins: `github.com/crowdsecurity/lua-cs-bouncer@ec94d512927cf70be865686e4eb928d128189633`, `github.com/crowdsecurity/cs-firewall-bouncer@20bd97a219259190229261b601e9f722178ac40d`, `github.com/crowdsecurity/crowdsec@a8dbeb94efb61c417b556b5468a7695a9410cb2f`. Related cursor/query shape: `ext_crowdsec_lapi_stream-cursor/`.

**Deleted-first: yes.** Both official bouncers apply `deleted` then `new` on one payload. Official docs do not name that order. LAPI can put the same IP or CIDR in both arrays on one response.

## Official docs do not specify apply order

The remediation-component spec tells a new bouncer to store decisions, then prune: “When you GET you’ll receive `deleted` decisions” and also clean expired TTLs. It does not say which array to apply first. The appendix JSON shows `"deleted"` then `"new"` as field order, not as an apply rule. Owner: [bouncer specs](https://docs.crowdsec.net/docs/next/contributing/specs/bouncer_appsec_specs.md). Extract: `.sources/bouncer_appsec_specs.md`

LAPI docs describe `/decisions/stream?startup=` as full state vs delta. The worked example also prints `"deleted"` then `"new"`. The page never says apply `deleted` first. Owner: [LAPI bouncers](https://docs.crowdsec.net/docs/next/local_api/bouncers.md). Extract: `.sources/lapi_bouncers.md`

Firewall docs say the component “will fetch new and old decisions” and put them in a blocklist. No apply order. Owner: [firewall](https://docs.crowdsec.net/u/bouncers/firewall). Extract: `.sources/firewall-bouncer.md`

Nginx docs say stream pulls “new/old decisions” on a timer. No apply order. Owner: [nginx](https://docs.crowdsec.net/u/bouncers/nginx). Extract: `.sources/nginx-bouncer.md`

Follow source for what shipped bouncers do.

## Official bouncers apply deleted then new

### lua-cs-bouncer (`@ec94d512`)

`stream:stream_query_process` decodes the body, then:

1. Comment `-- process deleted decisions`. Loop `decisions.deleted`. Key from `value` + `scope`. `self:delete(key)` removes `decision_cache/<key>`.
2. Comment `-- process new decisions`. Loop `decisions.new`. Same key. `self:set(key, type/origin/ip_type, ttl)` writes `decision_cache/<key>`.

Owner: [stream.lua](https://github.com/crowdsecurity/lua-cs-bouncer/blob/ec94d512927cf70be865686e4eb928d128189633/lib/plugins/crowdsec/stream.lua). Extract: `.sources/stream.lua.md`

The cache key is the parsed IP or CIDR (`ipv4_<netmask>_<addr>` / IPv6 equivalent), not the decision id. Scope `ip` and scope `range` share that helper; a `/32` IP and a named Range CIDR are different keys. Owner: [utils.lua](https://github.com/crowdsecurity/lua-cs-bouncer/blob/ec94d512927cf70be865686e4eb928d128189633/lib/plugins/crowdsec/utils.lua). Extract: `.sources/utils.lua.md`

A same-window replacement (same scope + same value in both arrays) deletes the slot, then writes the replacement. The new remediation remains.

The spec names lua-cs-bouncer as the complete reference implementation. ([bouncer specs](https://docs.crowdsec.net/docs/next/contributing/specs/bouncer_appsec_specs.md))

### cs-firewall-bouncer (`@20bd97a2`)

The stream worker reads `bouncer.Stream` and, on a non-nil batch, calls `deleteDecisions(backend, decisions.Deleted, config)` then `addDecisions(backend, decisions.New, config)`. Each helper filters by supported type, then `backend.Delete` / `backend.Add`, then `backend.Commit` when that half of the batch was non-empty. Two commits: deletes land before adds start. Owner: [cmd/root.go](https://github.com/crowdsecurity/cs-firewall-bouncer/blob/20bd97a219259190229261b601e9f722178ac40d/cmd/root.go). Extract: `.sources/firewall-root.go.md`

Backends that batch inside one `Commit` still do deletes first:

- nftables `Commit`: `commitDeletedDecisions` then `commitAddedDecisions`. Owner: [nftables.go](https://github.com/crowdsecurity/cs-firewall-bouncer/blob/20bd97a219259190229261b601e9f722178ac40d/pkg/nftables/nftables.go). Extract: `.sources/nftables.go.md`
- pf `Commit`: same pair. Owner: [pf.go](https://github.com/crowdsecurity/cs-firewall-bouncer/blob/20bd97a219259190229261b601e9f722178ac40d/pkg/pf/pf.go). Extract: `.sources/pf.go.md`
- iptables/ipset `commit`: writes `del` lines from `toDel`, then add lines from `toAdd`, keyed on `*decision.Value` (IP or CIDR string). Owner: [iptables_context.go](https://github.com/crowdsecurity/cs-firewall-bouncer/blob/20bd97a219259190229261b601e9f722178ac40d/pkg/iptables/iptables_context.go). Extract: `.sources/iptables_context.go.md`

A same-window replacement for the same IP or CIDR is removed, then inserted. The replacement remains.

`github.com/crowdsecurity/go-cs-bouncer` was not cloned. The firewall apply order is in `cmd/root.go`, not in the stream client.

## LAPI can put the same value in both arrays

LAPI writes one JSON object with two independent queries. There is no value-level intersection filter between `new` and `deleted`.

- Wire prefix is `{"new": [` then later `], "deleted": [`. Field order on the wire is **new then deleted**. Owner: [streamDecisions](https://github.com/crowdsecurity/crowdsec/blob/a8dbeb94efb61c417b556b5468a7695a9410cb2f/pkg/apiserver/controllers/v1/decisions.go). Extract: `.sources/decisions.go.md`
- `new` = `QueryAllDecisionsWithFilters`: `until > now`, optional longest-decision-per-scope-type-value, plus `id_gt` cursor. Owner: [decisions.go (db)](https://github.com/crowdsecurity/crowdsec/blob/a8dbeb94efb61c417b556b5468a7695a9410cb2f/pkg/database/decisions.go). Extract: `.sources/decisions_db.go.md`
- `deleted` = expired (`until < now`). Startup: all matching expired. Delta: `QueryExpiredDecisionsSinceWithFilters` with `since = LastPull-2s`. Always `startID 0` (not the stream cursor). Same longest-decision dedup **inside** that query only.

Dedup is per array. An expired row for `Ip:1.2.3.4` and a still-active row for `Ip:1.2.3.4` (new id, `until > now`) can both appear on one payload. That is a same-window replacement. Cursor/query detail: `ext_crowdsec_lapi_stream-cursor/`.

**Official vs source (JSON field order):** docs examples list `"deleted"` then `"new"`. This pin writes `"new"` then `"deleted"`. Follow source for the wire. Bouncers key by field name; apply order is not JSON order.

## Design takeaway

Apply `deleted` before `new` on one stream payload. Official source does that so a replacement for the same IP or CIDR stays active. Official docs are silent. Do not follow LAPI JSON field order (`new` first on this pin).

## References

- Official: [bouncer AppSec specs](https://docs.crowdsec.net/docs/next/contributing/specs/bouncer_appsec_specs.md), [LAPI for remediation components](https://docs.crowdsec.net/docs/next/local_api/bouncers.md), [firewall](https://docs.crowdsec.net/u/bouncers/firewall), [nginx](https://docs.crowdsec.net/u/bouncers/nginx)
- Source: `github.com/crowdsecurity/lua-cs-bouncer@ec94d512`, `github.com/crowdsecurity/cs-firewall-bouncer@20bd97a2`, `github.com/crowdsecurity/crowdsec@a8dbeb94`
- Related: `ext_crowdsec_lapi_stream-cursor/`
- Extracts: `.sources/`
