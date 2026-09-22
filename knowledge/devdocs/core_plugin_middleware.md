# Plugin middleware New

## Language

**LAPI Client**:
The reclaim value for one CrowdSec LAPI/CAPI decisions backend. Opened by ownership key (middleware name plus client knobs). Writes a DecisionStore keyed by SessionHex. Not the slot name.
_Avoid_: CrowdsecConnection, AppSec client, Bouncer, Plugin, process singleton, `sync.Once`, first-wins settings hash, PeekLivePrefix

**AppSec Client**:
The reclaim value for one CrowdSec AppSec listener: replaceable HTTP+auth, host, body limit. Keyed by middleware name plus listener knobs including TLS and effective timeout. Not the LAPI Client.
_Avoid_: CrowdsecConnection, LAPI, `AppsecQuery` on the LAPI type, `atomic.Pointer[T]`

**Stream session**:
The CrowdSec bouncer row this process polls: LAPI scheme, host, and path plus lapiKey (CAPI machine and password in alone), plus canonical stream scopes and Redis when enabled. Interval knobs are the Client, not the session.
_Avoid_: slot name, IdentityHex as the Open suffix, `decisionScopeHeaders`, AppSec host, PeekLivePrefix

**Bouncer**:
The per-router `http.Handler` Traefik gets back from `New`. Holds `next`, request policy, and two optional `atomic.Value` bindings (LAPI and AppSec). `ServeHTTP` only Loads those fields. Mode comes from the loaded LAPI client.
_Avoid_: ForRoute, Plugin core, the reclaim value, `atomic.Pointer[T]`

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
`crowdsecLapiEnabled` owns a LAPI client; `crowdsecAppsecEnabled` owns an AppSec client; `enabled` only bounces. `crowdsecMode` is the owned LAPI fetch strategy (`live` | `stream` | `none` | `alone`). AppSec-only is LAPI flag false plus AppSec flag true. `crowdsecMode: appsec` is rejected.
_Avoid_: treating mode as which legs run, implying AppSec from mode

## Overview

Traefik Yaegi loads `CreateConfig` and `New` from the module-root package. `New` snapshots the config Traefik owns, Opens owned legs on a bind context, Publishes named slots (`core_plugin_middleware_instance-slots.md`), then returns a Bouncer that late-binds via `atomic.Value`. Keep `.traefik.yml` `import` equal to the `go.mod` `module` path. Specs: `core_plugin_middleware_bouncer`. Open key: `core_plugin_lapi_reclaim-key.md`.

## How to use

- Keep `CreateConfig` / `New` on the module root (`plugin.go`).
- Keep `pluginVersion` in root `version.go` (release workflow bumps it). Pass it into `lapi.New` and `appsec.New`.
- Snapshot first: `prepared := *config`, then work on `&prepared` for the rest of `New`. Never write through Traefik's pointer.
- After the snapshot, do not copy leftover YAML keys or peer aliases into `BanFilePath` / `CaptchaFilePath`. Traefik’s decode of those two fields is the only owner.
- Derive `bindCtx, releaseHolders := context.WithCancel(ctx)` before the first `Open`, and release it from a `defer` that fires only when the named `err` is non-nil.
- Call `lapi.Prepare` then `appsec.Prepare` (AppSec key/scheme copy only when AppSec is enabled). `PrepopulateInstanceNames` only when that leg is owned. Stream/alone: `lapi.OpenStream`. Live/none: `lapi.OpenLive`. When `crowdsecAppsecEnabled`: `appsec.Open`. Then `instance.PublishAll`. When this `New` did not Open a leg, `instance.ClearPublisher` that leg for this middleware name. `bouncer.New` takes subscribe flags, not client pointers. Subscribe after New. Open key: `core_plugin_lapi_reclaim-key.md`. Stream `scopes=`: `core_plugin_lapi_scope-union.md`. Slots: `core_plugin_middleware_instance-slots.md`.
- `ServeHTTP` Loads `atomic.Value` only. `streamStartupBlock` on the request path is “every subscribed backend is published?” — 503 when not. Do not block `New`. Do not put the flag on the client.
- When `bouncer.New` builds the captcha siteverify `http.Client`, set `Timeout` from `cfg.EffectiveHTTPTimeoutSeconds(cfg.CaptchaSiteverifyHTTPTimeoutSeconds)`. Keep that client per-Bouncer. Do not reclaim it.
- Put stream tickers, replaceable LAPI HTTP (`transport` on `atomic.Value`), and Range membership on `lapi.Client`. Open the DecisionStore on the same `New` ctx (`core_plugin_decisionstore.md`). Put AppSec HTTP+auth on `appsec.Client`. Put captcha, templates, LAPI failure action, Redis fail-closed, and live-cache TTL on Bouncer. Timeout/TLS changes are a new ownership key, not Adopt-only.
- Do not pass `config.DefaultDecisionSeconds` from the bouncer into `LiveLookup`; the bound client already has it.
- Resolve client IP with `pkg/ip.GetRemoteIP`. Fold `remoteIP`, parsed `net.IP`, and `ipType` into `clientRequest`. Keep the name `req`.
- After the trusted-client skip, a non-empty `crowdsecDecisionHeader` with exact `b` remediates without lookup; `c` still looks up so a ban wins (`core_plugin_middleware_forced-decision.md`).
- Range and header-mapped CrowdSec scopes live in `pkg/decisionscope`. Do not geolocate in `New` or `ServeHTTP`.
- Live LAPI error and stream-unhealthy cache miss use `crowdsecLapiFailureAction`. Cache hits still apply when the stream is unhealthy. `passthrough` uses the pass path (AppSec still runs if enabled).
- Watch logs `reclaim_put|bind|orphan|reclaim|dispose` and `crowdsec lapi instance|crowdsec appsec instance|crowdsec bouncer bound|crowdsec bouncer unbound`.

## Pattern snippet

```go
func New(ctx context.Context, next http.Handler, config *configuration.Config, name string) (handler http.Handler, err error) {
	prepared := *config
	configuration.PrepopulateInstanceNames(&prepared, name)
	bindCtx, releaseHolders := context.WithCancel(ctx)
	defer func() {
		if err != nil {
			releaseHolders()
		}
	}()
	if prepared.CrowdsecLapiEnabled {
		lapiClient, err = lapi.OpenStream(bindCtx, &prepared, log, name, pluginVersion)
	}
	err = instance.PublishAll(attempts)
	handler, err = bouncer.New(next, name, &prepared, subscribeLAPI, subscribeAppSec, log)
	return handler, err
}
```

## Key files

- `plugin.go`
- `pkg/instance/`
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
- `crowdsecMode: appsec` is invalid (E4). AppSec-only is `crowdsecLapiEnabled: false` plus `crowdsecAppsecEnabled: true`.
- When `crowdsecAppsecEnabled` is true, `ValidateParams` rejects an empty `crowdsecAppsecHost` (`http.NewRequest` accepts `http:///`). Disabled-AppSec empty host still passes. Do not require the host in `validateURL` or `validateParamsRequired`.
- Ownership Open key includes middleware name plus client knobs (LAPI: mode, URL, key, TLS, effective timeout, Redis, stream scopes, CAPI, intervals, `updateMaxFailure`, `defaultDecisionSeconds`). Slot name, `enabled`, `decisionScopeHeaders`, `crowdsecAppsecFailureAction`, and `streamStartupBlock` are not in it. AppSec key includes middleware name plus listener knobs including TLS and effective timeout. `core_plugin_lapi_reclaim-key.md`.
- `crowdsecLapiFailureAction` is per-router on Bouncer. `crowdsecAppsecFailureAction` stays on Bouncer. Two routers on one published client MAY disagree.
- Stream/alone: CrowdSec stores one `GET /v1/decisions/stream` cursor per hashed API key plus the IP LAPI sees. Two stream owners with the same host and key log `crowdsec lapi stream collision` and both `New` succeed. DecisionStore key is `SessionHex` (canonical stream scopes; Redis block only when enabled). Subscribers must not Bind reclaim. Isolated backends still need a second bouncer key unless they only subscribe.
- LAPI `Close()` stops tickers and idle LAPI HTTP. It does not Close the shared DecisionStore unless this incarnation still owns it. AppSec `Close()` releases idle AppSec HTTP. Do not use `sync.Once`.
- Both puts use `Open` / `OpenWithHooks` on the process table. First `New` sets table grace from `reclaimGraceSeconds` (default 30). Utilities `DefaultGrace` (10s) is only the table’s negative-grace fallback.
- Backend Create/Close at INFO (`crowdsec lapi instance started|closed`); Sleep/Wake at DEBUG. Bouncer bound/unbound at INFO. DecisionStore INFO uses `storeKey` and `engine`. `reclaim_put`, `reclaim_reclaim`, and `reclaim_dispose` stay DEBUG. Stream poll stems are DEBUG. `startup` is an attribute on poll/updated (`true` for the full-set GET).
