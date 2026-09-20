# Plugin middleware New

## Language

**LAPI Client**:
The reclaim value for one CrowdSec LAPI/CAPI decisions backend: stream/metrics tickers, LAPI HTTP, a reclaimed DecisionStore, and in-process Range membership. Stream/alone: keyed by cursor SessionHex plus Redis store params (`lapi:stream:`). Live/none: keyed by SessionHex plus a hash of Redis store params and `MetricsUpdateIntervalSeconds` (`lapi:`). Not middleware name. `IdentityHex` is not the live Open suffix.
_Avoid_: CrowdsecConnection, AppSec client, Bouncer, Plugin, process singleton, `sync.Once`, first-wins settings hash, PeekLivePrefix

**AppSec Client**:
The reclaim value for one CrowdSec AppSec listener: replaceable HTTP+auth, host, body limit. Keyed by AppSec URL+key+body limit. Last `New` adopts TLS/timeout. Not the LAPI Client.
_Avoid_: CrowdsecConnection, LAPI, `AppsecQuery` on the LAPI type, `atomic.Pointer[T]`

**Stream session**:
The CrowdSec bouncer row this process polls: LAPI scheme, host, and path plus lapiKey (CAPI machine and password in alone). Settings such as metrics interval are not the session. A live joiner `Open`s the same cursor-plus-Redis key.
_Avoid_: middleware name, IdentityHex as the Open suffix, `scopes=`, AppSec host, PeekLivePrefix

**Bouncer**:
The per-router `http.Handler` Traefik gets back from `New`. Holds `next`, request policy (trusted IPs, ban/captcha, Enabled, AppSec-on-pass, LAPI failure action, Redis fail-closed, live-cache TTL), `lapiClient` (`*lapi.Client`, nil in `crowdsecMode: appsec`), and `appsecClient` (`*appsec.Client`, nil when AppSec is off).
_Avoid_: ForRoute, Plugin core, the reclaim value

**Failure action**:
The operator enum (`passthrough` | `ban` | `captcha`) this plugin applies when LAPI or AppSec does not return a usable verdict. LAPI action is per-router on Bouncer; AppSec action is per-router on Bouncer. Default is `ban`.
_Avoid_: fail mode, FailMode, the three removed AppSec block bools, AppSec JSON `action: captcha`, LAPI Client identity

**Prepared config**:
`New`'s own shallow copy of the `*configuration.Config` Traefik owns (`prepared`). Everything downstream of `New` reads and writes that copy: normalised `logLevel`, the `Prepare` secret resolution, alone-mode LAPI rewrite. Its slice and map fields still alias the caller's.
_Avoid_: writing through Traefik's pointer, deep copy, mutating `DecisionScopeHeaders` or the trusted-IP slices in place

**Bind context**:
The `context.WithCancel` child of the constructor `ctx` that every reclaim `Open` in `New` binds. Released on a failed `New` so nothing opened so far stays held; never released on the success path, where Traefik's own `ctx` is what ends the holders.
_Avoid_: `context.Background()` as the bind parent, a Release API on the table, a closure-captured success bool

**Two configuration axes**:
`crowdsecMode` picks the decision source (`appsec` = none at all); `crowdsecAppsecEnabled` toggles the WAF leg, which runs on the pass path in every mode. `appsec` plus `crowdsecAppsecEnabled: false` enforces nothing and is warned about, not rejected.
_Avoid_: treating `appsec` as "AppSec on", implying `crowdsecAppsecEnabled` from the mode

## Overview

Traefik Yaegi loads `CreateConfig` and `New` from the module-root package. `New` snapshots the config Traefik owns and binds every reclaim `Open` to a bind context derived from the constructor `ctx` — that child is the reclaim holder, and releasing it is how a failed constructor hands back what it already opened. Keep `.traefik.yml` `import` equal to the `go.mod` `module` path. Specs: `core_plugin_middleware_bouncer` (Yaegi `New` / Bouncer). Open key: `core_plugin_lapi_reclaim-key.md`.

## How to use

- Keep `CreateConfig` / `New` on the module root (`plugin.go`).
- Keep `pluginVersion` in root `version.go` (release workflow bumps it). Pass it into `lapi.New` and `appsec.New`.
- Snapshot first: `prepared := *config`, then work on `&prepared` for the rest of `New`. Never write through Traefik's pointer.
- After the snapshot, do not copy leftover YAML keys or peer aliases into `BanFilePath` / `CaptchaFilePath`. Traefik’s decode of those two fields is the only owner.
- Derive `bindCtx, releaseHolders := context.WithCancel(ctx)` before the first `Open`, and release it from a `defer` that fires only when the named `err` is non-nil. `err` is named for that reason; a closure-captured bool is the form the ticket rejected.
- Call `lapi.Prepare` then `appsec.Prepare`. Stream/alone: `lapi.OpenStream` (registers this bind ctx on the live-router scope union). Live/none: `lapi.OpenLive`. `crowdsecMode: appsec`: skip LAPI Open. When `crowdsecAppsecEnabled`: `appsec.Open` (`AdoptTransport` inside). Return `bouncer.New(..., lapiClient, appsecClient, ...)`. Open key: `core_plugin_lapi_reclaim-key.md`. Stream `scopes=`: `core_plugin_lapi_scope-union.md`.
- `bouncer.New`'s appsec-mode early return is conditional: appsec mode still initialises the captcha client when the effective `crowdsecAppsecFailureAction` is `captcha`, because `handleRemediationServeHTTP` bans on an invalid captcha client.
- When `bouncer.New` builds the captcha siteverify `http.Client`, set `Timeout` from `cfg.EffectiveHTTPTimeoutSeconds(cfg.CaptchaSiteverifyHTTPTimeoutSeconds)`. Keep that client per-Bouncer. Do not reclaim it.
- Put stream tickers, replaceable LAPI HTTP (`transport` on `atomic.Value`), and Range membership on `lapi.Client`. Open the DecisionStore on the same `New` ctx (`core_plugin_decisionstore.md`). Put AppSec HTTP+auth (`transport` on `atomic.Value`) on `appsec.Client`. Put captcha, templates, LAPI failure action, Redis fail-closed, and live-cache TTL on Bouncer. After `OpenStream` / `OpenLive`, `AdoptTransport` last-wins LAPI TLS/timeout. After `appsec.Open`, last `New` last-wins AppSec TLS/timeout.
- Pass `config.DefaultDecisionSeconds` into `LiveLookup`. Two routers on one Client last-write that TTL into the shared live cache.
- Keep `StreamStartupBlock` write-once at `startStream`. First incarnation keeps it. Do not put it on Bouncer.
- Resolve client IP with `pkg/ip.GetRemoteIP`. Fold `remoteIP`, parsed `net.IP`, and `ipType` into `clientRequest`. Keep the name `req`. Do not parse `RemoteAddr` on LAPI or AppSec. Do not put scopes or origin on that type.
- After the trusted-client skip, a non-empty `crowdsecDecisionHeader` with exact `b` or `c` remediates without lookup (`core_plugin_middleware_forced-decision.md`).
- Range and header-mapped CrowdSec scopes live in `pkg/decisionscope`. Do not geolocate in `New` or `ServeHTTP`.
- Live LAPI error and stream-unhealthy cache miss use `crowdsecLapiFailureAction`. Cache hits still apply when the stream is unhealthy. `passthrough` uses the pass path (AppSec still runs if enabled).
- Watch logs `reclaim_put|bind|orphan|reclaim|dispose`.

## Pattern snippet

```go
func New(ctx context.Context, next http.Handler, config *configuration.Config, name string) (handler http.Handler, err error) {
	prepared := *config

	bindCtx, releaseHolders := context.WithCancel(ctx)
	defer func() {
		if err != nil {
			releaseHolders()
		}
	}()

	if prepared.CrowdsecMode == configuration.StreamMode || prepared.CrowdsecMode == configuration.AloneMode {
		lapiClient, err = lapi.OpenStream(bindCtx, &prepared, log, name, pluginVersion)
	} else if prepared.CrowdsecMode != configuration.AppsecMode {
		lapiClient, err = lapi.OpenLive(bindCtx, &prepared, log, name, pluginVersion)
	}
	handler, err = bouncer.New(next, name, &prepared, lapiClient, appsecClient, log)
	return handler, err
}
```

## Key files

- `plugin.go`
- `pkg/lapi/`
- `pkg/lapi/client_http.go`
- `pkg/lapi/client_live.go`
- `pkg/appsec/`
- `pkg/bouncer/bouncer.go`
- `pkg/bouncer/clientrequest.go`
- `.traefik.yml`

## Gotchas

- Unused keys (`banHtmlFilePath`, `captchaHtmlFilePath`, HTML-cased twins) never reach `New` (Traefik v3.7.11 drops them). Operators who set only those keys get CreateConfig defaults (`BanFilePath` empty, `CaptchaFilePath` `/captcha.html`). Do not re-add Config fields or `New` copies to catch leftovers.
- The reclaim table has no Release: a holder goes away only when the context it bound is Done (`std_go_reclaim.md`). That is why `New` opens on `bindCtx` — with Traefik's own long-lived ctx, a constructor that failed after `OpenStream` left the stream ticker polling LAPI for the process lifetime.
- Do not release `bindCtx` on the success path, and do not parent it on `context.Background()`: the first disposes the incarnation the handler is about to use, the second survives a Traefik shutdown.
- `crowdsecMode: appsec` with `crowdsecAppsecEnabled: false` is accepted and warned at `WARN` from `ValidateParams` (`warnUnenforcedAppsecMode`). Do not turn that into an error and do not imply `crowdsecAppsecEnabled` on — `crowdsecAppsecHost` defaults to `crowdsec:7422` and `crowdsecAppsecFailureAction` to `ban`, so implying it bans every request on that router.
- When `crowdsecAppsecEnabled` is true, `ValidateParams` rejects an empty `crowdsecAppsecHost` (`http.NewRequest` accepts `http:///`). Disabled-AppSec empty host still passes. Do not require the host in `validateURL` or `validateParamsRequired`.
- Do not put middleware name, `next`, ban/captcha templates, trusted IPs, Enabled, AppSec knobs, LAPI failure action, Redis fail-closed, live-cache TTL, `StreamStartupBlock`, HTTP timeout, or LAPI TLS in the LAPI reclaim key. Do not put AppSec TLS or HTTP timeout in the AppSec reclaim key.
- `crowdsecLapiFailureAction` is per-router on Bouncer. `crowdsecAppsecFailureAction` stays on Bouncer. Two routers on one Client MAY disagree.
- Stream/alone: CrowdSec stores one `GET /v1/decisions/stream` cursor per hashed API key plus the IP LAPI sees (this process’s outbound address). Reclaim `Open` key is `lapi:stream:` plus SessionHex plus Redis store params. A second stream `New` on the same cursor plus Redis `Open`s that key. Interval, CAPI scenario, `updateMaxFailure`, and header-map mismatch is silent first-wins for those create-time scalars. Do not call `Peek` / `PeekLivePrefix`. Last New `AdoptTransport`s TLS/timeout (INFO `adopted`). Last holder Sleeps tickers; reload with the same Redis snapshot Wakes (`startup=false`); a different Redis host Opens a new key and the sleeper dies on grace. Isolated backends need a second bouncer key. Live/none `Key` is `lapi:` plus SessionHex plus Redis and `MetricsUpdateIntervalSeconds` (AppSec excluded). `IdentityHex` is not the live Open suffix.
- LAPI `Close()` stops tickers and idle LAPI HTTP. It does not Close the shared DecisionStore. AppSec `Close()` releases idle AppSec HTTP. Do not use `sync.Once`.
- Both puts use `Open` / `OpenWithHooks` on the process table (`ProcessGrace` 30s). Utilities `DefaultGrace` (10s) is only the table’s negative-grace fallback.
- Lifecycle INFO lines include reclaim `sessionKey` and `reason` (`started|sleeping|waking|closed`). DecisionStore INFO uses the same reasons with `storeKey` and `engine` (`crowdsec decision store started|sleeping|waking|closed`). Stream health transitions: `crowdsec stream became unhealthy|healthy` (not every poll). INFO also names `lapi transport replaced` and a live joiner `adopted` (no `ignored` / warn-and-wire). `reclaim_put`, `reclaim_reclaim`, and `reclaim_dispose` stay DEBUG. Stream poll stems `handleStreamTicker:poll` and `handleStreamCache:updated` are DEBUG. A dropped in-flight tick logs `handleStreamTicker:skip` at WARN. `startup` is an attribute on poll/updated (`true` for the full-set GET). Finish lines carry applied `new`/`deleted` counts.
