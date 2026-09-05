## Context

On master, `plugin.go` reclaims with `crowdsecconnection.Key(config)`. `identityFrom` in `pkg/crowdsecconnection/identity.go` does not include `DecisionScopeHeaders`. Both `CrowdsecConnection` and `Bouncer` copy `NormalizeDecisionScopeHeaders(config.DecisionScopeHeaders)`. Stream `scopes=` and ingest use the connection copy (first `New` wins). Request matching uses the bouncer copy. Spec `core_plugin_middleware_instance-reclaim` lists identity fields without the map. AppSec failure action stays per-router (`core_plugin_appsec_failure-action`). Client IP stays `pkg/ip.GetRemoteIP`. Country/AS values stay the mapped header from the trusted hop.

## Goals / Non-Goals

**Goals:**
- One owner of the normalized map: CrowdsecConnection identity.
- Two `New()` with the same LAPI and different maps must not share a connection.
- Bouncer reads the connection map; no duplicate field.

**Non-Goals:**
- File-split of `connection.go`.
- Moving cache remediation constants.
- Prepare/CAPI mutation except hashing the new field.
- Minting a second LAPI API key so CrowdSec `stream_cursor` splits (same key + client IP still share a LAPI row).
- Changing AppSec client/host ownership or AppSec failure action (stays on Bouncer).
- Sibling tickets: split-connection-files, split-configuration-files, split-ip-trust, remediation-codes-owner, decisionscope-mode-bool, config-prepare-snapshot.

## Decisions

1. **Hash `NormalizeDecisionScopeHeaders(cfg.DecisionScopeHeaders)` on identity.** Alternative: hash the Traefik-raw map — rejected; `Country` vs `country` would split connections. Explore assumed.

2. **Hash the full scope→header map, not keys only.** Alternative: identity = sorted scope names, keep header names on Bouncer — rejected; that keeps a second owner. Different header names are different connections. Explore assumed.

3. **Empty and omitted maps are the same identity.** `NormalizeDecisionScopeHeaders` returns nil for both; stream stays `ip,range`. Explore assumed.

4. **Getter `DecisionScopeHeaders()` on CrowdsecConnection.** Bouncer MUST NOT mutate the returned map. Explore assumed.

5. **Do not mint a second LAPI key.** Local cache/stream isolation is the ticket. CrowdSec `stream_cursor` remains per bouncer row. Explore assumed.

6. **Reuse `identityFrom` / `Key` / `reclaim.Open`.** Do not add `sync.Once` or a second key scheme. Identity owner Decision from explore.

## Risks / Trade-offs

- [Two connections, one LAPI key, shared CrowdSec cursor] → accepted; documented in research. Local caches still isolate ingest.
- [Two routes mapping Country to different headers become two tickers] → accepted; cheaper than a second map owner on Bouncer.
- [Usage packet currently avoids putting Country on the reclaim key] → update `core_plugin_decisionscope.md` in this change.

## Migration Plan

No public YAML change. Operators who already attach two maps to one LAPI in one Traefik get two connections after upgrade (the intended fix). Rollback: previous tag restores first-wins sharing.
