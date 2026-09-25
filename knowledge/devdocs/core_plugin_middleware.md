# Plugin middleware New

## Language

**LAPI Client**:
The reclaim value for one CrowdSec LAPI/CAPI decisions backend. Opened by ownership key (middleware name plus client knobs). Writes a DecisionStore keyed by SessionHex. Not the slot name.
_Avoid_: CrowdsecConnection, AppSec client, Bouncer, Plugin, process singleton, `sync.Once`, first-wins settings hash, PeekLivePrefix

**AppSec Client**:
The reclaim value for one CrowdSec AppSec listener: replaceable HTTP+auth, host, body limit. Keyed by middleware name plus listener knobs including TLS and `appsecHttpTimeoutSeconds`. Not the LAPI Client.
_Avoid_: CrowdsecConnection, LAPI, `AppsecQuery` on the LAPI type, `atomic.Pointer[T]`

**Captcha Client**:
The reclaim value for one named captcha widget, verifier, template, and gate. Opened by ownership key (middleware name plus instance-owned captcha knobs including the recaptcha-enterprise knobs and `logLevel`, `logFilePath`, `logFormat`). Not a Bouncer field and not the slot name.
_Avoid_: per-Bouncer captcha, local construct on bounce-only, storing the remediation header on Client, siteverify-only client

**Stream session**:
The CrowdSec bouncer row this process polls: LAPI scheme, host, and path plus lapiKey (CAPI machine and password in alone), plus canonical stream scopes and Redis when enabled. Interval knobs are the Client, not the session.
_Avoid_: slot name, IdentityHex as the Open suffix, `bouncerDecisionScopeHeaders`, AppSec host, PeekLivePrefix

**Bouncer**:
The per-router `http.Handler` Traefik gets back from `New`. Holds `next`, request policy, and three optional `atomic.Value` bindings (LAPI, AppSec, and captcha). `ServeHTTP` only Loads those fields. Mode comes from the loaded LAPI client.
_Avoid_: ForRoute, Plugin core, the reclaim value, `atomic.Pointer[T]`

**Failure action**:
The operator enum (`passthrough` | `ban` | `captcha`) this plugin applies when LAPI or AppSec does not return a usable verdict. LAPI action is per-router on Bouncer; AppSec action is per-router on Bouncer. Default is `ban`.
_Avoid_: fail mode, FailMode, the three removed AppSec block bools, AppSec JSON `action: captcha`, LAPI Client identity

**Bypass rule**:
One exemption block (optional method, path, headers map, cookies map) on `bouncerAppsecBypassRules` or `bouncerLapiBypassRules`. Omitted field = any. Set fields AND. List OR, first match wins. Method and path are Go RE2 on `req.Method` and `req.URL.Path`. Not a trusted-IP skip, not the forced-decision header, not a captcha-leg list.
_Avoid_: Exclude match string, `host://path`, `bouncerAppsecExcludeRegex`, `bouncerLapiExcludeRegex`

**Config snapshot**:
`New`'s own shallow copy of Traefik's `rawConfig` (`config := *rawConfig`). Everything downstream of `New` reads and writes `config`: normalised `logLevel`, the `Prepare` secret resolution, alone-mode LAPI rewrite. Its slice and map fields still alias the caller's.
_Avoid_: writing through Traefik's pointer, deep copy, mutating `DecisionScopeHeaders` or the trusted-IP slices in place, calling the snapshot `prepared`

**Bind context**:
The `context.WithCancel` child of the constructor `ctx` that every reclaim `Open` in `New` binds. Released on a failed `New` so nothing opened so far stays held; never released on the success path, where Traefik's own `ctx` is what ends the holders.
_Avoid_: `context.Background()` as the bind parent, a Release API on the table, a closure-captured success bool

**Two configuration axes**:
`lapiEnabled` owns a LAPI client; `appsecEnabled` owns an AppSec client; `captchaEnabled` owns a captcha client; `bouncerEnabled` only bounces. `lapiMode` is the owned LAPI fetch strategy (`live` | `stream` | `none` | `alone`). AppSec-only is LAPI flag false plus AppSec flag true. `lapiMode: appsec` is rejected.
_Avoid_: treating mode as which legs run, implying AppSec from mode, crowdsecMode, enabled as own, implicit captcha own from provider

## Overview

Traefik Yaegi loads `CreateConfig` and `New` from the module-root package. `New` snapshots the config Traefik owns, Opens owned legs on a bind context, Publishes named slots (`core_plugin_middleware_instance-slots.md`), then returns a Bouncer that late-binds via `atomic.Value`. Keep `.traefik.yml` `import` equal to the `go.mod` `module` path. Specs: `core_plugin_middleware_bouncer`. Open key: `core_plugin_lapi_reclaim-key.md`.

## How to use

- Keep `CreateConfig` / `New` on the module root (`plugin.go`).
- Keep `pluginVersion` in root `version.go` (release workflow bumps it). Pass it into `lapi.New` and `appsec.New`.
- Snapshot first: `config := *rawConfig`, then work on `&config` for the rest of `New`. Never write through Traefik's pointer.
- After the snapshot, do not copy leftover YAML keys or peer aliases into `BouncerBanFilePath` / `CaptchaFilePath`. Traefik’s decode of those two fields is the only owner.
- Derive `bindCtx, releaseHolders := context.WithCancel(ctx)` before the first `Open`, and release it from a `defer` that fires only when the named `err` is non-nil.
- Call `lapi.Prepare` then `appsec.Prepare` then `captcha.Prepare` (each fills an omitted instance name when that leg is owned; AppSec key/scheme copy only when AppSec is enabled). When `lapiEnabled`: `lapi.Open` (do not read `lapiMode` to pick an entry point; mode stays on `Config`). When `appsecEnabled`: `appsec.Open`. When `captchaEnabled`: `captcha.Open`. Then `reclaim.SetAlias` with group `lapi`/`appsec`/`captcha`. When this `New` did not Open a leg, `reclaim.ClearPublisher(name, group)`. `bouncer.New` takes subscribe flags, not client pointers. `Watch` after New. Open key: `core_plugin_lapi_reclaim-key.md`. Stream `scopes=`: `core_plugin_lapi_scope-union.md`. Slots: `core_plugin_middleware_instance-slots.md`.
- `ServeHTTP` Loads `atomic.Value` only. `startupBlock` (`bouncerStartupBlock`) on the request path is “every subscribed backend is published?” — 503 when not. Do not block `New`. Do not put the flag on the client.
- When a captcha owner Opens the captcha `http.Client`, set `Timeout` from `cfg.CaptchaSiteverifyHTTPTimeoutSeconds`. Siteverify and assessments share that client. Publish it. Do not construct captcha on bounce-only.
- Put stream tickers, replaceable LAPI HTTP (`transport` on `atomic.Value`), and Range membership on `lapi.Client`. Open the DecisionStore on the same `New` ctx (`core_plugin_decisionstore.md`). Put AppSec HTTP+auth on `appsec.Client`. Put captcha widget, verifier, template, and gate on `captcha.Client`. Put ban templates, LAPI failure action, Redis fail-closed, live-cache TTL, and this router’s remediation header on Bouncer. Timeout/TLS changes are a new ownership key, not Adopt-only.
- Do not pass `config.LapiDefaultDecisionSeconds` from the bouncer into `LiveLookup`; the bound client already has it.
- Resolve client IP with `pkg/ip.GetRemoteIP`. Fold `remoteIP`, parsed `net.IP`, and `ipType` into `clientRequest`. Keep the name `req`.
- After the trusted-client skip, a non-empty `bouncerDecisionHeader` with exact `b` remediates without lookup; `c` still looks up so a ban wins unless a LAPI bypass rule already skipped lookup (`core_plugin_middleware_forced-decision.md`).
- Compile `bouncerLapiBypassRules` / `bouncerAppsecBypassRules` once in `bouncer.New` via `httprule.New` (`core_plugin_httprule.md`). Do not compile on the request path. After trusted-IP skip and forced `b`, skip that CrowdSec leg when `Set.Match` is true. Path owner is `req.URL.Path` as `net/http` decoded it; do not rebuild from `RequestURI`, `EscapedPath`, or AppSec forwarded URI. Host is not part of the path match. A LAPI match continues at `passOrForcedCaptcha` (AppSec may still Query; forced `c` still applies). An AppSec match in `handleNextServeHTTP` skips `applyAppsecServeHTTP` and calls `next`. Do not hash these lists into LAPI ownership or AppSec identity.
- Range and header-mapped CrowdSec scopes live in `pkg/decisionscope`. Do not geolocate in `New` or `ServeHTTP`.
- Live LAPI error and stream-unhealthy cache miss use `bouncerLapiFailureAction`. Cache hits still apply when the stream is unhealthy. `passthrough` uses the pass path (AppSec still runs if enabled).
- Watch logs `reclaim_put|bind|orphan|reclaim|dispose` and `crowdsec lapi instance|crowdsec appsec instance|crowdsec captcha instance|crowdsec bouncer bound|crowdsec bouncer unbound`.

## Pattern snippet

```go
func New(ctx context.Context, next http.Handler, rawConfig *configuration.Config, name string) (handler http.Handler, err error) {
	config := *rawConfig
	_ = lapi.Prepare(&config, log, name)
	_ = appsec.Prepare(&config, log, name)
	_ = captcha.Prepare(&config, log, name)
	bindCtx, releaseHolders := context.WithCancel(ctx)
	defer func() {
		if err != nil {
			releaseHolders()
		}
	}()
	if config.LapiEnabled {
		lapiClient, err = lapi.Open(bindCtx, &config, log, name, pluginVersion)
	}
	err = reclaim.SetAlias(lapi.OwnershipKey(&config, name), instanceAlias("lapi", config.LapiInstanceName), name, "lapi")
	handler, err = bouncer.New(next, name, &config, subscribeLAPI, subscribeAppSec, subscribeCaptcha, log)
	return handler, err
}
```

## Key files

- `plugin.go`
- `pkg/reclaim/default.go`
- `pkg/lapi/`
- `pkg/lapi/client_http.go`
- `pkg/lapi/client_live.go`
- `pkg/appsec/`
- `pkg/captcha/captcha.go`
- `pkg/captcha/session.go`
- `pkg/bouncer/bouncer.go`
- `pkg/bouncer/clientrequest.go`
- `pkg/httprule/`
- `.traefik.yml`

## Gotchas

- Unused keys (`banHtmlFilePath`, `captchaHtmlFilePath`, leftover `bouncerCaptcha*`, leftover `bouncerAppsecExcludeRegex` / `bouncerLapiExcludeRegex`, HTML-cased twins) never reach `New` (Traefik v3.7.11 drops them). Operators who set only those keys get CreateConfig defaults (`BouncerBanFilePath` empty, `CaptchaFilePath` `/captcha.html`). Do not re-add Config fields or `New` copies to catch leftovers. A leftover pre-prefix `captchaFilePath` binds `CaptchaFilePath` again (the captcha stem, not an alias).
- The reclaim table has no Release: a holder goes away only when the context it bound is Done (`std_go_reclaim.md`). That is why `New` opens on `bindCtx` — with Traefik's own long-lived ctx, a constructor that failed after `Open` left the stream ticker polling LAPI for the process lifetime.
- Do not release `bindCtx` on the success path, and do not parent it on `context.Background()`: the first disposes the incarnation the handler is about to use, the second survives a Traefik shutdown.
- `lapiMode: appsec` is invalid (E4). AppSec-only is `lapiEnabled: false` plus `appsecEnabled: true`.
- When `appsecEnabled` is true, `ValidateParams` rejects an empty `appsecHost` (`http.NewRequest` accepts `http:///`). Disabled-AppSec empty host still passes. Do not require the host in `validateURL` or `validateParamsRequired`.
- Ownership Open key includes middleware name plus client knobs (LAPI: mode, URL, key, TLS, `lapiHttpTimeoutSeconds`, Redis, stream scopes, CAPI, intervals, `lapiUpdateMaxFailure`, `lapiDefaultDecisionSeconds`). Slot name, `bouncerEnabled`, `bouncerDecisionScopeHeaders`, `bouncerAppsecFailureAction`, bypass rule lists, and `bouncerStartupBlock` are not in it. AppSec key includes middleware name plus listener knobs including TLS and `appsecHttpTimeoutSeconds`. Captcha key includes middleware name plus instance-owned captcha knobs (provider, keys, files, timeouts, template, gate, custom paths, recaptcha-enterprise knobs, `logLevel`, `logFilePath`, `logFormat`). Slot name, bounce, failure actions, remediation header, bypass rule lists, and `bouncerStartupBlock` stay off it. `core_plugin_lapi_reclaim-key.md`. `pkg/captcha/session.go`.
- `bouncerLapiFailureAction` is per-router on Bouncer. `bouncerAppsecFailureAction` stays on Bouncer. Two routers on one published client MAY disagree. Bypass rule lists are the same: two routers MAY disagree, and they are not in reclaim keys.
- Stream/alone: CrowdSec stores one `GET /v1/decisions/stream` cursor per hashed API key plus the IP LAPI sees. Two stream owners with the same host and key log `crowdsec lapi stream collision` and both `New` succeed. DecisionStore key is `SessionHex` (canonical stream scopes; Redis block only when enabled). Subscribers must not Bind reclaim. Isolated backends still need a second bouncer key unless they only subscribe.
- LAPI `Close()` stops tickers and idle LAPI HTTP. It does not Close the shared DecisionStore unless this incarnation still owns it. AppSec `Close()` releases idle AppSec HTTP. Do not use `sync.Once`.
- Both puts use `Open` / `OpenWithHooks` on the process table. First `New` sets table grace from `reclaimGraceSeconds` (default 30). Utilities `DefaultGrace` (10s) is only the table’s negative-grace fallback.
- Backend Create/Close at INFO (`crowdsec lapi instance started|closed`); Sleep/Wake at DEBUG. Watch calls `func(any)` with `reclaim.Published` when the published client changes. `ReceiveLAPI` / `ReceiveAppSec` / `ReceiveCaptcha` store that value and log bound at INFO and unbound at DEBUG once per pointer. `ReceiveLAPI` warns `crowdsec bouncer stream scopes missing`. `ServeHTTP` only Loads. DecisionStore INFO uses `storeKey` and `engine`. `reclaim_put`, `reclaim_reclaim`, and `reclaim_dispose` stay DEBUG. Stream poll stems are DEBUG. `startup` is an attribute on poll/updated (`true` for the full-set GET).
