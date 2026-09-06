# Requirement
IssueKey: 2026-09-06-plugin-lifecycle-lapi

## Problem
Two stream (or alone) middlewares in one Traefik process can reclaim two CrowdsecConnection incarnations that both poll `GET /v1/decisions/stream` with the same LAPI (or CAPI) credentials. LAPI keeps one `stream_cursor` per bouncer row (same hashed API key + client IP). The two tickers split or race that session. Each incarnation prefixes Redis/memory with its own `IdentityHex`, so neither cache is complete. Operators see bans that apply on one router, the other, or neither. Compose currently forces `/trusted` to copy `/stream`'s `metricsUpdateIntervalSeconds=1` so the hashes match; that is a test paper, not a product fix.

## Current (code)
- Reclaim key is `crowdsecconnection:` + FNV-64a of JSON `identityFrom` in `pkg/crowdsecconnection/identity.go`. Identity includes mode, LAPI/CAPI, `UpdateIntervalSeconds`, `MetricsUpdateIntervalSeconds`, `UpdateMaxFailure`, `LapiFailureAction`, `StreamStartupBlock`, `DefaultDecisionSeconds`, `HTTPTimeoutSeconds`, Redis*, AppSec client, TLS. Comment excludes middleware name, templates, trusted IPs, Enabled. `decisionScopeHeaders` is **not** in identity.
- `plugin.go` `New` calls `reclaim.Open(ctx, crowdsecconnection.Key(config), …)` then `crowdsecconnection.New`. First put for a key constructs; a different hash is a second put (`pkg/reclaim/table.go`).
- `CrowdsecConnection.New` (`pkg/crowdsecconnection/connection.go`) always calls `startStream`. Stream/alone start a ticker that GETs `v1/decisions/stream?startup=…&scopes=…` (`connection_stream.go`, `connection_decisions.go` `streamQuery`). Live/none return from `startStream` with no poller. Appsec mode returns before cache/stream/metrics.
- `scopes=` is `decisionscope.StreamScopeList(c.decisionScopeHeaders)` (`pkg/decisionscope/lookup.go`). Headers live on the connection field set in `New`, not in the reclaim key. First `New` for a shared hash wins the scopes query.
- Redis/memory prefix is `IdentityHex(config)` (`connection.go` `cacheClient.New`). Two identities ⇒ two prefixes ⇒ two incomplete caches. Range-index follows that prefix (`hydrateRangeMembership`).
- Stream lease key `"updated"` is per prefix (`handleStreamCache`). Separate prefixes do not share the lease, so both poll LAPI.
- Metrics ticker starts after stream when `MetricsUpdateIntervalSeconds > 0` (`connection.go`). Default is 600 (`pkg/configuration/configuration.go`). `/stream` e2e sets 1; `/trusted` was forced to 1 in `tests/e2e/real/docker-compose.test.yml` with a comment that a mismatch steals deltas. `knowledge/devdocs/build_e2e_real.md` documents that workaround. `/custom-ban` is `none` on the same LAPI key (no stream poller). File-provider scopes bouncer uses `BOUNCER_KEY_TRAEFIK_SCOPES`.
- Spec `openspec/specs/core_plugin_middleware_instance-reclaim/spec.md` requires intervals in the reclaim key so two configs that disagree on interval get two connections (no first-wins globals). Usage `knowledge/devdocs/core_plugin_middleware.md` gotcha: “Same connection fields share one ticker; different LAPI/mode/redis/interval are two Connections.”
- LAPI session ownership is already researched: `knowledge/research/ext_crowdsec_lapi_stream-cursor/notes.md` (cursor is the bouncer row; same key + same client IP share one cursor; no lease on concurrent `startup=false`).
- No `identity_test.go` on dest. In-flight PR #18 (`2026-09-05-scope-headers-identity`) puts `DecisionScopeHeaders` on identity so different scopes do not first-win; it does not treat same-key extra identity fields as a config error.

## Desired
- Stream session is an explicit unique in-process resource: LAPI scheme/host/path + lapiKey (CAPI machine+password in alone) + `scopes=` from `NormalizeDecisionScopeHeaders`. Scopes belong in that key.
- Stream/alone: at most one `startStream` (and one decision cache / range-index prefix) per session in one Traefik process. Second `New` with the same session and a conflicting knob (metrics interval, update interval, redis, timeout, failure action, …) fails `New` naming both sides’ fields — or reclaims the existing session connection and ignores knobs only if they cannot diverge cache/ticker meaning. Prefer fail. Silent ignore is how this bug was born. Do not start a second poller because two intervals were requested. Isolated backends need a second bouncer key (or host).
- Redis prefix for stream/alone follows the session, not leftover extra identity fields.
- Live/none: no stream session; two connections on the same key remain OK for lookups. Usage-metrics POST is also per bouncer key; do not start two metrics tickers on one key without an explicit decision.
- Rewrite spec `core_plugin_middleware_instance-reclaim`: keep “same session fields ⇒ one ticker”; replace “disagree on update interval ⇒ two connections” with config error when LAPI key+scopes match. Update usage `core_plugin_middleware.md` and `build_e2e_real.md` (matching metrics labels is not the long-term story).
- Tests: Key/New pin for metrics-only and update-interval-only diffs (same key or fail `New`); different `decisionScopeHeaders` ⇒ different session; two live constructor `New`s never run two `handleStreamCache` loops on one session. E2e: `/stream` metrics=1 and `/trusted` default 600, same `BOUNCER_KEY_TRAEFIK_TEST`, either plugin init fails or `/stream` still 403s a cscli ban within the existing 30s wait. Compose workaround may stay until the product lands, then drop the forced match if fail-on-conflict is chosen.

## Affected
- `pkg/crowdsecconnection/identity.go`, `connection.go`, `connection_stream.go`, `connection_decisions.go`, `connection_metrics.go`
- `plugin.go` (`reclaim.Open` / `New` error path)
- `openspec/specs/core_plugin_middleware_instance-reclaim/spec.md`
- `knowledge/devdocs/core_plugin_middleware.md`, `knowledge/devdocs/build_e2e_real.md`, `knowledge/devdocs/core_cache_client.md` (prefix follows IdentityHex today)
- `tests/e2e/real/docker-compose.test.yml`, stream/trusted e2e, new unit tests around Key/New
- Possible interaction with OPEN PR #18 (scopes on identity)

## Out of scope
- Plugin fail-closed origin labels, lock-free processed counters, parse-once `net.IP`, range-index origin suffix
- Expanding CIDRs, changing plugin origin labels
- Treating “set the same metrics interval on `/trusted`” as the product fix
- Removing metrics from identity and stopping there
- First-wins a second stream ticker onto a connection with a different Redis prefix or different `scopes=` query
- Starting a second poller because the current spec wanted two intervals

## Unknowns
- Fail `New` vs reclaim-and-ignore for same-session conflicting knobs (ticket prefers fail).
- Whether live/none metrics tickers on the same bouncer key should also fail or share one reporter.
- Whether AppSec-only mode (no stream, no cache) is in the metrics-ticker uniqueness rule.
- Whether PR #18 should land first, fold into this change, or be superseded (scopes in session key is required here either way).
- CAPI `alone` session key details beyond machine+password (scenarios? host is hardcoded).

## Tensions
- Spec `core_plugin_middleware_instance-reclaim` “First-wins globals are gone” (two intervals ⇒ two connections) is the design that produces two LAPI stream sessions on one key. Ticket says that scenario is invalid against LAPI, not two isolated backends.
- Usage gotcha “different … interval are two Connections” documents the bug as intended behavior.
- PR #18 puts scopes on identity (stops first-win) but still splits pollers when scopes differ and the LAPI key is shared; this ticket wants scopes in the session key **and** fail/share instead of a second poller for extra knobs. E2e already uses `BOUNCER_KEY_TRAEFIK_SCOPES` for the scopes middleware.
- Stream lease `"updated"` would share a poller if two identities used one Redis prefix; they do not today, so both poll. Sharing prefix without collapsing tickers would still double-GET.
- LAPI may create a second bouncer row when client IPs differ (`ext_crowdsec_lapi_stream-cursor`); in-process uniqueness is still required for one Traefik (one outbound IP).
