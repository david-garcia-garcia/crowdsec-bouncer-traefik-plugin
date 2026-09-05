# Explore
IssueKey: 2026-09-05-scope-headers-identity

## Concepts

```
  Traefik New (per router)
           │
           ▼
  crowdsecconnection.Key(cfg)  ◄── identityFrom(cfg)  (today: no decisionScopeHeaders)
           │
           ▼
  reclaim.Open(ctx, key, create)
           │
           ├── CrowdsecConnection  stream scopes=, ingest, cache prefix IdentityHex
           └── Bouncer             duplicate map for RequestScopeValues(req)
```

**Reclaim identity** is `crowdsecconnection.identity` hashed by `IdentityHex`. Same key → one stream ticker and one cache. Spec `core_plugin_middleware_instance-reclaim` lists mode, LAPI/CAPI, redis, intervals, AppSec client, HTTP timeout. It does not list `decisionScopeHeaders`.

**Header-mapped scope** is a CrowdSec scope other than Ip/Range whose value comes from a request header. Stream `scopes=` and ingest filter live on `CrowdsecConnection`. Request header names are what `RequestScopeValues` needs.

**AppSec failure action** is per-router on `Bouncer` on purpose (`core_plugin_appsec_failure-action`). Header maps are not like that: they change LAPI stream query and cache keys.

**LAPI stream_cursor** is a CrowdSec bouncer-row column keyed by API key + client IP (`knowledge/research/ext_crowdsec_lapi_stream-cursor/`). Two local connections with the same key still share that cursor.

## Decisions

- Put the **normalized** `decisionScopeHeaders` map on `identity` and keep the live copy only on `CrowdsecConnection`. Different maps → different `Key` → different stream/cache.
- `Bouncer` drops `decisionScopeHeaders`. `ServeHTTP` calls `RequestScopeValues(conn.DecisionScopeHeaders(), req)`.
- Hash `NormalizeDecisionScopeHeaders(cfg.DecisionScopeHeaders)`, not the Traefik-raw map. Empty and omitted both normalize to nil → same identity (today’s `ip,range` stream).
- Hash the full scope→header map, not keys only. Two routes that map `Country` to different headers are two connections. Cheaper key-only hashing would force a second copy of header names on `Bouncer`, which the ticket forbids.
- Do not mutate `Prepare` / CAPI routing. `identityFrom` reads config and normalizes for the hash only.
- Do not file-split `connection.go`. Add a getter next to `Mode` / `Cache`.
- Do not change LAPI API keys to get two CrowdSec cursors. Local isolation is the ticket.
- Reuse `reclaim.Open` and `identityFrom`. Do not add `sync.Once` or a second key scheme.
- Client IP stays `pkg/ip.GetRemoteIP`. Country/AS values stay the mapped header from the trusted hop (`RequestScopeValues`). Do not geolocate.
- Usage packet `core_plugin_decisionscope.md` currently says pass the map into both types and avoid putting Country on the reclaim key. That contract is wrong for this ticket; update it in implement / devdocs-impact, not as a silent extra rename.

## Open questions

- Q: Who already owns the reclaim identity of a CrowdsecConnection?
  Decision: resolved — `pkg/crowdsecconnection/identity.go` `identityFrom` / `Key`. Add the normalized map to that owner. Do not invent a second key.
  By: explore

- Q: Who already owns Country/AS (and custom scope) values on the request?
  Decision: resolved — the trusted hop that writes the mapped header (CDN or geoenrich), same trust model as `X-Forwarded-For`. Reuse `decisionscope.RequestScopeValues`. Do not geolocate or parse `RemoteAddr` for country.
  By: explore

- Q: Should identity hash the raw Traefik map or `NormalizeDecisionScopeHeaders` output?
  Decision: assumed — hash the normalized map so `Country` vs `country` do not split connections.
  By: explore

- Q: Empty map vs omitted map — same connection?
  Decision: assumed — yes. `NormalizeDecisionScopeHeaders` returns nil for both; stream stays `ip,range`.
  By: explore

- Q: Hash full scope→header map, or only sorted scope keys (keep header names on Bouncer)?
  Decision: assumed — full map on identity; Bouncer has no copy. Different header names are different connections. Key-only hashing would keep a duplicate owner on Bouncer.
  By: explore

- Q: Two local connections with the same LAPI key will still share CrowdSec `stream_cursor`. Block this ticket?
  Decision: assumed — no. Ticket is local stream/cache isolation. LAPI row sharing is documented third-party behavior. Do not mint a second API key here.
  By: explore

- Q: Getter name on CrowdsecConnection?
  Decision: assumed — `DecisionScopeHeaders()` returning the stored normalized map. Callers must not mutate it.
  By: explore
