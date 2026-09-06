# Explore
IssueKey: 2026-09-06-domain-lapi-appsec

## Concepts

**LAPI** is CrowdSec Local API (or CAPI in `alone`): the decisions/remediation oracle. Modes `none`, `live`, `stream`, `alone` are how this plugin talks to it. Operator keys `crowdsecLapi*`. This package also POSTs usage-metrics to that same authenticated row.

**AppSec** is CrowdSec’s HTTP WAF / application-security engine. Different host (default `:7422`), key, TLS, body limit, failure action (`crowdsecAppsec*`). It inspects the request, not the decision list. Official protocol: `knowledge/research/ext_crowdsec_appsec_protocol/`.

**crowdsecAppsecEnabled** is orthogonal to LAPI mode. Stream/live can run AppSec on the pass path. **crowdsecMode: appsec** is a fifth mode that skips LAPI cache/stream and jumps to AppSec only (`bouncer.go` `ServeHTTP`).

**CrowdsecConnection** (today) is one reclaim value that holds both products: LAPI/CAPI HTTP, stream/metrics tickers, isolated cache, Range membership, **and** `httpAppsecClient` plus AppSec host/key/TLS (`pkg/crowdsecconnection/connection.go`).

**Measured coupling** (not a runtime crash): `CrowdsecConnection` fields include `appsecScheme`/`appsecHost`/`appsecPath`/`appsecKey`/`appsecBodyLimit`/`httpAppsecClient`. `AppsecQuery` is a method on that type (`connection_appsec.go`). Live/none `identity` JSON includes AppSec host/key/TLS (`identity.go`). Stream `streamSettings` includes the same AppSec knobs for warn-and-wire (`session.go`). Spec `core_plugin_connection_source-files` SHALL keep `AppsecQuery` on `package crowdsecconnection` and forbids a new module path.

```
                    TODAY (one reclaim type)
┌─────────────────────────────────────────────────────────┐
│                 CrowdsecConnection                      │
│  LAPI HTTP + stream + cache + metrics + Range           │
│  AppSec HTTP client + host/key/TLS/bodyLimit            │
└───────────────┬─────────────────────────┬───────────────┘
                │                         │
         LiveLookup / stream        AppsecQuery
                │                         │
                └──────────┬──────────────┘
                           ▼
                      Bouncer.conn
```

```
                 TARGET (two owners)
┌──────────────────────┐     ┌──────────────────────┐
│ pkg/lapi Connection  │     │ pkg/appsec Client    │
│ decisions, stream,   │     │ WAF round-trip,      │
│ cache, metrics, CAPI │     │ envelope, failure    │
└──────────┬───────────┘     └──────────┬───────────┘
           │  reclaim by LAPI row       │  reclaim by AppSec URL+key
           └──────────┬─────────────────┘
                      ▼
              Bouncer { conn, appsec }
                      │
         ServeHTTP: LAPI first, then AppSec on pass
```

## Decisions

- Rename `pkg/crowdsecconnection` → `pkg/lapi`. Human named that target. Do not keep the mixed package as a facade.
- New package `pkg/appsec` owns `AppsecQuery` (as `Query`), `AppsecResponse`, `AppsecPolicy`, `ErrFailureCaptcha`, AppSec HTTP client, and test helper `NewTestClient`.
- `pkg/bouncer` holds two pointers. `plugin.go` Opens LAPI and, when AppSec is enabled or mode is `appsec`, Opens AppSec. Neither package imports the other.
- LAPI reclaim identity / stream session MUST NOT include AppSec fields. AppSec reclaim is its own key (`appsec:` + scheme/host/path/key/TLS/bodyLimit/timeout).
- Operator Traefik keys stay (`crowdsecLapi*`, `crowdsecAppsec*`, `crowdsecMode: appsec`). No config YAML rename.
- Usage-metrics stay on LAPI (`IncDropped` with `OriginPluginAppsecFailure` still a LAPI label). AppSec does not POST metrics.
- Spec `core_plugin_connection_source-files` is superseded in this change (it forbids the split).
- Shared unexported HTTP helpers (`closeIdle`, `isReverseProxyError`) are copied into each package. No third `pkg/httpx`.
- Client IP stays `pkg/ip.GetRemoteIP`. AppSec `X-Crowdsec-Appsec-Ip` is that output. Do not re-parse `RemoteAddr`.
- Both packages reclaim with `reclaim.OpenWithGrace` + `*reclaim.Wrapped` (Yaegi). No `sync.Once`.

## Open questions

- Q: What is the AppSec package name?
  Decision: assumed — `pkg/appsec` (CrowdSec product name). Not `waf`, not `crowdsecappsec`.
  By: explore

- Q: What is the LAPI reclaim type name inside `package lapi`?
  Decision: assumed — `lapi.Connection`. Drop exported `CrowdsecConnection` (the name claims both products).
  By: explore

- Q: Is AppSec reclaimed separately, or constructed inside LAPI `New` as a field?
  Decision: assumed — separate reclaim; Bouncer holds `*lapi.Connection` and `*appsec.Client` (nil when AppSec off). Constructing AppSec inside LAPI would keep the mixed owner.
  By: explore

- Q: Live/none `IdentityHex` currently hashes AppSec host/key/TLS. Dropping those fields changes the live Redis cache prefix on upgrade.
  Decision: assumed — drop AppSec from LAPI identity. Accept a one-time live-mode cache miss/TTL refresh. Stream `SessionHex` is already LAPI URL+key only.
  By: explore

- Q: Stream warn-and-wire first-wins currently includes AppSec knobs. After split, two routers on one LAPI stream can use different AppSec hosts.
  Decision: assumed — drop AppSec from `streamSettings`. That is the point of two owners. Verdict protocol unchanged.
  By: explore

- Q: For `crowdsecMode: appsec`, does plugin still Open a LAPI connection?
  Decision: assumed — no LAPI Open (today `New` already skips cache/stream/metrics). Bouncer stores `crowdsecMode` from config instead of `conn.Mode()`. AppSec Open still runs.
  By: explore

- Q: Keep `Prepare` copying empty `crowdsecAppsecKey` from `crowdsecLapiKey` (and empty AppSec scheme from LAPI scheme)?
  Decision: assumed — keep. Official protocol often uses the same bouncer key; this plugin already has a distinct key with that fallback.
  By: explore

- Q: Reclaim table key prefix `crowdsecconnection:` / `crowdsecconnection:stream:`?
  Decision: assumed — `lapi:` / `lapi:stream:` and `appsec:`. In-process only; a reload during grace will not Wake the old prefix (same as any identity change).
  By: explore
