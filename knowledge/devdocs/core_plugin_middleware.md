# Plugin middleware New

## Language

**LAPI Client**:
The reclaim value for one CrowdSec LAPI/CAPI decisions backend: stream/metrics tickers, LAPI HTTP, a reclaimed DecisionStore, and in-process Range membership. Stream/alone: keyed by cursor SessionHex plus Redis store params (`lapi:stream:`). Live/none: keyed by SessionHex plus a hash of Redis store params and `LapiMetricsIntervalSeconds` (`lapi:`). Not middleware name. `IdentityHex` is not the live Open suffix.
_Avoid_: CrowdsecConnection, AppSec client, Bouncer, Plugin, process singleton, `sync.Once`, first-wins settings hash, PeekLivePrefix

**AppSec Client**:
The reclaim value for one CrowdSec AppSec listener: replaceable HTTP+auth, host, body limit. Keyed by AppSec URL+key+body limit. Last `New` adopts TLS/timeout. Not the LAPI Client.
_Avoid_: CrowdsecConnection, LAPI, `AppsecQuery` on the LAPI type, `atomic.Pointer[T]`

**Stream session**:
The CrowdSec bouncer row this process polls: LAPI scheme, host, and path plus lapiKey (CAPI machine and password in alone). Settings such as metrics interval are not the session. A live joiner `Open`s the same cursor-plus-Redis key.
_Avoid_: middleware name, IdentityHex as the Open suffix, `scopes=`, AppSec host, PeekLivePrefix

**Bouncer**:
The per-router `http.Handler` Traefik gets back from `New`. Holds `next`, request policy (trusted IPs, ban/captcha, `bouncerEnabled`, AppSec-on-pass, LAPI failure action, Redis fail-closed, live-cache TTL), instance names, and enable flags. Peeks named LAPI/AppSec slots on each request. `bouncerHold` returns a 503 holder instead of a Bouncer.
_Avoid_: ForRoute, Plugin core, the reclaim value, storing `*Client` from construct as the request-path owner

**Named instance slot**:
Process table keyed by operator `lapiInstance` / `appsecInstance` (empty = Traefik `New` name). Openers Publish after identity Open. Bounce path Peek. Yaegi-safe `atomic.Value`. Beside identity reclaim, not a replacement.
_Avoid_: reclaim Key, SessionHex, `atomic.Pointer[T]`, blocking `New` until the slot exists

**Failure action**:
The operator enum (`passthrough` | `ban` | `captcha`) this plugin applies when LAPI or AppSec does not return a usable verdict, including Peek miss of a named slot. LAPI action is per-router on Bouncer; AppSec action is per-router on Bouncer. Default is `ban`.
_Avoid_: fail mode, FailMode, the three removed AppSec block bools, AppSec JSON `action: captcha`, LAPI Client identity

**Prepared config**:
`New`'s own shallow copy of the `*configuration.Config` Traefik owns (`prepared`). Everything downstream of `New` reads and writes that copy: normalised `logLevel`, the `Prepare` secret resolution, alone-mode LAPI rewrite. Its slice and map fields still alias the caller's.
_Avoid_: writing through Traefik's pointer, deep copy, mutating `LapiScopeHeaders` or the trusted-IP slices in place

**Bind context**:
The `context.WithCancel` child of the constructor `ctx` that every reclaim `Open` in `New` binds. Released on a failed `New` so nothing opened so far stays held; never released on the success path, where Traefik's own `ctx` is what ends the holders.
_Avoid_: `context.Background()` as the bind parent, a Release API on the table, a closure-captured success bool

**Two configuration axes**:
`lapiMode` is the LAPI fetch strategy (`live` | `stream` | `none` | `alone`). `lapiEnabled` and `appsecEnabled` turn each backend on. AppSec-only is `lapiEnabled: false` plus `appsecEnabled: true`. `bouncerEnabled` is whether this router remediates.
_Avoid_: `lapiMode: appsec`, implying `appsecEnabled` from the mode

**Failure action**:
The operator enum (`passthrough` | `ban` | `captcha`) this plugin applies when LAPI or AppSec does not return a usable verdict. LAPI action is per-router on Bouncer; AppSec action is per-router on Bouncer. Default is `ban`.
_Avoid_: fail mode, FailMode, the three removed AppSec block bools, AppSec JSON `action: captcha`, LAPI Client identity

**Prepared config**:
`New`'s own shallow copy of the `*configuration.Config` Traefik owns (`prepared`). Everything downstream of `New` reads and writes that copy: normalised `logLevel`, the `Prepare` secret resolution, alone-mode LAPI rewrite. Its slice and map fields still alias the caller's.
_Avoid_: writing through Traefik's pointer, deep copy, mutating `LapiScopeHeaders` or the trusted-IP slices in place

**Bind context**:
The `context.WithCancel` child of the constructor `ctx` that every reclaim `Open` in `New` binds. Released on a failed `New` so nothing opened so far stays held; never released on the success path, where Traefik's own `ctx` is what ends the holders.
_Avoid_: `context.Background()` as the bind parent, a Release API on the table, a closure-captured success bool

**Two configuration axes**:
`lapiMode` picks the decision source (`appsec` = none at all); `appsecEnabled` toggles the WAF leg, which runs on the pass path in every mode. `appsec` plus `appsecEnabled: false` enforces nothing and is warned about, not rejected.
_Avoid_: treating `appsec` as "AppSec on", implying `appsecEnabled` from the mode

## Overview

Traefik Yaegi loads `CreateConfig` and `New` from the module-root package. `New` snapshots the config Traefik owns and binds every reclaim `Open` to a bind context derived from the constructor `ctx` — that child is the reclaim holder, and releasing it is how a failed constructor hands back what it already opened. Keep `.traefik.yml` `import` equal to the `go.mod` `module` path. Specs: `core_plugin_middleware_bouncer` (Yaegi `New` / Bouncer). Open key: `core_plugin_lapi_reclaim-key.md`.

## How to use

- Keep `CreateConfig` / `New` on the module root (`plugin.go`).
- Keep `pluginVersion` in root `version.go` (release workflow bumps it). Pass it into `lapi.New` and `appsec.New`.
- Snapshot first: `prepared := *config`, then work on `&prepared` for the rest of `New`. Never write through Traefik's pointer.
- After the snapshot, do not copy leftover YAML keys or peer aliases into `BouncerBanFile` / `BouncerCaptchaFile`. Traefik’s decode of those two fields is the only owner.
- Derive `bindCtx, releaseHolders := context.WithCancel(ctx)` before the first `Open`, and release it from a `defer` that fires only when the named `err` is non-nil. `err` is named for that reason; a closure-captured bool is the form the ticket rejected.
- Call `lapi.Prepare` then `appsec.Prepare`. Stream/alone: `lapi.OpenStream` when `OpensLAPI`. Live/none: `lapi.OpenLive`. `createdBy` is the LAPI instance name. A different instance name on the same SessionHex fails `New` before Open. Skip LAPI Open when `lapiEnabled` is false or this middleware only subscribes. When `OpensAppsec`: `appsec.Open` (`AdoptTransport` inside). Publish each opened Client into `pkg/instance`. `bouncerHold`: return the 503 holder. Else return `bouncer.New(...)`. Open key: `core_plugin_lapi_reclaim-key.md`. Stream `scopes=`: opener-only, `core_plugin_lapi_scope-union.md`.
- `bouncer.New`'s LAPI-off early return is conditional: AppSec-only still initialises the captcha client when the effective `bouncerAppsecFailureAction` is `captcha`, because `handleRemediationServeHTTP` bans on an invalid captcha client.
- ServeHTTP Peeks the named slot on each request. Miss uses `bouncerLapiFailureAction` / `bouncerAppsecFailureAction`. Injected `*Client` args are a test fallback after Peek.
- When `bouncer.New` builds the captcha siteverify `http.Client`, set `Timeout` from `cfg.EffectiveHTTPTimeoutSeconds(cfg.BouncerCaptchaHttpTimeoutSeconds)`. Keep that client per-Bouncer. Do not reclaim it.
- Put stream tickers, replaceable LAPI HTTP (`transport` on `atomic.Value`), and Range membership on `lapi.Client`. Open the DecisionStore on the same `New` ctx (`core_plugin_decisionstore.md`). Put AppSec HTTP+auth (`transport` on `atomic.Value`) on `appsec.Client`. Put captcha, templates, LAPI failure action, Redis fail-closed, and live-cache TTL on Bouncer. After `OpenStream` / `OpenLive`, `AdoptTransport` last-wins LAPI TLS/timeout. After `appsec.Open`, last `New` last-wins AppSec TLS/timeout.
- Pass `config.BouncerLiveTtlSeconds` into `LiveLookup`. Two routers on one Client last-write that TTL into the shared live cache.
- Keep `LapiStreamStartupBlock` write-once at `startStream`. First incarnation keeps it. Do not put it on Bouncer.
- Resolve client IP with `pkg/ip.GetRemoteIP`. Fold `remoteIP`, parsed `net.IP`, and `ipType` into `clientRequest`. Keep the name `req`. Do not parse `RemoteAddr` on LAPI or AppSec. Do not put scopes or origin on that type.
- After the trusted-client skip, a non-empty `bouncerDecisionHeader` with exact `b` remediates without lookup; `c` still looks up so a ban wins (`core_plugin_middleware_forced-decision.md`).
- Range and header-mapped CrowdSec scopes live in `pkg/decisionscope`. Do not geolocate in `New` or `ServeHTTP`.
- Live LAPI error and stream-unhealthy cache miss use `bouncerLapiFailureAction`. Cache hits still apply when the stream is unhealthy. `passthrough` uses the pass path (AppSec still runs if enabled).
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

	if configuration.OpensLAPI(&prepared) {
		if prepared.LapiMode == configuration.StreamMode || prepared.LapiMode == configuration.AloneMode {
			lapiClient, err = lapi.OpenStream(bindCtx, &prepared, log, lapiName, pluginVersion)
		} else {
			lapiClient, err = lapi.OpenLive(bindCtx, &prepared, log, lapiName, pluginVersion)
		}
		if err != nil {
			return nil, err
		}
		if err = instance.PublishLAPI(lapiName, lapiClient); err != nil {
			return nil, err
		}
	}
	if prepared.BouncerHold {
		return newHoldHandler(log, name), nil
	}
	handler, err = bouncer.New(next, name, &prepared, lapiClient, appsecClient, log)
	return handler, err
}
```

## Key files

- `plugin.go`
- `pkg/instance/instance.go`
- `pkg/lapi/`
- `pkg/lapi/client_http.go`
- `pkg/lapi/client_live.go`
- `pkg/appsec/`
- `pkg/bouncer/bouncer.go`
- `pkg/bouncer/clientrequest.go`
- `.traefik.yml`

## Gotchas

- Unused keys (`banHtmlFilePath`, `captchaHtmlFilePath`, HTML-cased twins) never reach `New` (Traefik v3.7.11 drops them). Operators who set only those keys get CreateConfig defaults (`BouncerBanFile` empty, `BouncerCaptchaFile` `/captcha.html`). Do not re-add Config fields or `New` copies to catch leftovers.
- The reclaim table has no Release: a holder goes away only when the context it bound is Done (`std_go_reclaim.md`). That is why `New` opens on `bindCtx` — with Traefik's own long-lived ctx, a constructor that failed after `OpenStream` left the stream ticker polling LAPI for the process lifetime.
- Do not release `bindCtx` on the success path, and do not parent it on `context.Background()`: the first disposes the incarnation the handler is about to use, the second survives a Traefik shutdown.
- `lapiEnabled: false` plus leftover `lapiKey` or `lapiInstance` fails `ValidateParams`. AppSec-only is `lapiEnabled: false` with `appsecEnabled: true` and AppSec secrets. Do not restore `lapiMode: appsec`.
- When `appsecEnabled` is true, `ValidateParams` rejects an empty `appsecHost` (`http.NewRequest` accepts `http:///`). Disabled-AppSec empty host still passes. Do not require the host in `validateURL` or `validateParamsRequired`.
- Do not put middleware name, `next`, ban/captcha templates, trusted IPs, Enabled, AppSec knobs, LAPI failure action, Redis fail-closed, live-cache TTL, `LapiStreamStartupBlock`, HTTP timeout, or LAPI TLS in the LAPI reclaim key. Do not put AppSec TLS or HTTP timeout in the AppSec reclaim key.
- `bouncerLapiFailureAction` is per-router on Bouncer. `bouncerAppsecFailureAction` stays on Bouncer. Two routers on one Client MAY disagree.
- Stream/alone: CrowdSec stores one `GET /v1/decisions/stream` cursor per hashed API key plus the IP LAPI sees (this process’s outbound address). Reclaim `Open` key is `lapi:stream:` plus SessionHex plus Redis store params. Peek the DecisionStore key (`decisionstore:` + SessionHex) before Open; a different Traefik `name` fails `New`. Same name on many routers shares. Do not call `PeekLivePrefix`. Do not Peek to retitle a sleeper. Last New `AdoptTransport`s TLS/timeout (INFO `adopted`). Last holder Sleeps tickers; reload with the same Redis snapshot Wakes (`startup=false`); a different Redis host Opens a new Client key and reuses the store when the name matches. Isolated backends need a second bouncer key. Live/none `Key` is `lapi:` plus SessionHex plus Redis and `LapiMetricsIntervalSeconds` (AppSec excluded). `IdentityHex` is not the live Open suffix.
- LAPI `Close()` stops tickers and idle LAPI HTTP. It does not Close the shared DecisionStore. AppSec `Close()` releases idle AppSec HTTP. Do not use `sync.Once`.
- Both puts use `Open` / `OpenWithHooks` on the process table (`ProcessGrace` 30s). Utilities `DefaultGrace` (10s) is only the table’s negative-grace fallback.
- Lifecycle INFO lines include reclaim `sessionKey` and `reason` (`started|sleeping|waking|closed`). DecisionStore INFO uses the same reasons with `storeKey` and `engine` (`crowdsec decision store started|sleeping|waking|closed`). Stream health transitions: `crowdsec stream became unhealthy|healthy` (not every poll). INFO also names `lapi transport replaced` and a live joiner `adopted` (no `ignored` / warn-and-wire). `reclaim_put`, `reclaim_reclaim`, and `reclaim_dispose` stay DEBUG. Stream poll stems `handleStreamTicker:poll` and `handleStreamCache:updated` are DEBUG. A dropped in-flight tick logs `handleStreamTicker:skip` at WARN. `startup` is an attribute on poll/updated (`true` for the full-set GET). Finish lines carry applied `new`/`deleted` counts.
