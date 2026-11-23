# Plugin middleware New

## Language

**LAPI Client**:
The reclaim value for one CrowdSec LAPI/CAPI decisions backend. Opened by ownership key (middleware name plus client knobs). Writes a DecisionStore keyed by SessionHex. Not the slot name.
_Avoid_: CrowdsecConnection, AppSec client, Bouncer, Plugin, process singleton, `sync.Once`, first-wins settings hash, PeekLivePrefix

**AppSec Client**:
The reclaim value for one CrowdSec AppSec listener: replaceable HTTP+auth, host, body limit. Keyed by middleware name plus listener knobs including TLS, `appsecHttpTimeoutSeconds`, and `appsecUnhealthyBackOffPeriodSecs`. Not the LAPI Client.
_Avoid_: CrowdsecConnection, LAPI, `AppsecQuery` on the LAPI type, `atomic.Pointer[T]`

**Captcha Client**:
The reclaim value for one named captcha widget, verifier, template, and gate. Opened by ownership key (middleware name plus instance-owned captcha knobs including the recaptcha-enterprise knobs and `logLevel`, `logFilePath`, `logFormat`). Not a Bouncer field and not the slot name.
_Avoid_: per-Bouncer captcha, local construct on bounce-only, storing the remediation header on Client, siteverify-only client

**ModSec Client**:
The reclaim value for one OWASP CRS sidecar inspect listener (`pkg/modsecurity`). Opened by ownership key (middleware name plus sidecar URL, timeout, body limit, and `modsecUnhealthyBackOffPeriodSecs`). Not the AppSec Client and not CrowdSec AppSec JSON.
_Avoid_: AppSec client, `modSecurityUrl`, the failure action as ownership, `atomic.Pointer[T]`

**Stream session**:
The CrowdSec bouncer row this process polls: LAPI scheme, host, and path plus lapiKey (CAPI machine and password in alone), plus canonical stream scopes and Redis when enabled. Interval knobs are the Client, not the session.
_Avoid_: slot name, IdentityHex as the Open suffix, `bouncerDecisionScopeHeaders`, AppSec host, PeekLivePrefix

**Bouncer**:
The per-router `http.Handler` Traefik gets back from `New`. Holds `next`, request policy, and five `legBinding`s (LAPI, AppSec, captcha, ModSec, and the rate limit), each an `atomic.Value` holding a `*reclaim.Box` (`core_plugin_middleware_instance-slots.md`). `ServeHTTP` only Loads those fields. Mode comes from the loaded LAPI client.
_Avoid_: ForRoute, Plugin core, the reclaim value, `atomic.Pointer[T]`

**Remediation header**:
The optional outgoing response header named by `bouncerRemediationHeadersCustomName`. When the name is non-empty, remediating writers set `kind:reason` or `kind:reason:origin`. Colon is the field separator; consumers split at most three fields. Empty name omits the header. Not an incoming action-rule header predicate.
_Avoid_: solved-captcha, single-token `ban`/`captcha`, copying raw AppSec `action`, storing the name on captcha.Client

**Failure action**:
The operator enum (`passthrough` | `ban` | `captcha`) this plugin applies when an admitted LAPI, AppSec, or ModSec hop does not return a usable verdict. Each is per-router on Bouncer (`bouncerLapiFailureAction`, `bouncerAppsecFailureAction`, `bouncerModsecFailureAction`). The rate limit's `rateLimitFailureAction` is not: it is the owner's policy on the published rate-limit Client, and every subscriber applies it (`core_plugin_ratelimit.md`). Default is `ban` for LAPI and `passthrough` for AppSec and ModSec. A gate skip on any gated leg is not this enum: it gets the backoff action (`core_plugin_appsec.md`, `core_plugin_modsecurity_inspect.md`).
_Avoid_: fail mode, `bouncerModsecFailMode`, the three removed AppSec block bools, AppSec JSON `action: captcha`, LAPI Client identity

**Backoff action**:
The operator enum (`passthrough` | `ban` | `captcha`) this plugin applies to a gate skip: a request whose LAPI (`live` / `none`), AppSec, or ModSec hop the leg's admission gate did not admit. Each is per-router on Bouncer (`bouncerLapiBackOffAction`, `bouncerAppsecBackOffAction`, `bouncerModsecBackOffAction`); the gate it answers is one per Client. Default is `ban` for LAPI and `passthrough` for AppSec and ModSec. Not the failure action, and the rate-limit leg has none.
_Avoid_: failure action on a skip, a hard-coded continue, inheriting the failure action, a backoff action on the Client or its ownership key

**Action rule**:
One authoring row on `bouncerActionRules` (unique `name`, `action` tokens, plus httprule predicates). All matching rows contribute. Ban remediates immediately; otherwise OR skipLapi / skipAppsec / skipModsec / skipRateLimit / captchaFlag. Not a trusted-IP skip, not CrowdSec identity, not the outgoing remediation header.
_Avoid_: first-match-wins, `bouncerAppsecBypassRules`, `bouncerLapiBypassRules`, `bouncerDecisionHeader`, `modsecBypassRules`

**Config snapshot**:
`New`'s own shallow copy of Traefik's `rawConfig` (`config := *rawConfig`). Everything downstream of `New` reads and writes `config`: normalised `logLevel`, the `Prepare` secret resolution, alone-mode LAPI rewrite. Its slice and map fields still alias the caller's.
_Avoid_: writing through Traefik's pointer, deep copy, mutating `DecisionScopeHeaders` or the trusted-IP slices in place, calling the snapshot `prepared`

**Bind context**:
The `context.WithCancel` child of the constructor `ctx` that every reclaim `Open` in `New` binds. Released on a failed `New` so nothing opened so far stays held; never released on the success path, where Traefik's own `ctx` is what ends the holders.
_Avoid_: `context.Background()` as the bind parent, a Release API on the table, a closure-captured success bool

**Two configuration axes**:
`lapiEnabled` owns a LAPI client; `appsecEnabled` owns an AppSec client; `captchaEnabled` owns a captcha client; `modsecEnabled` owns a ModSec client; `rateLimitEnabled` owns the rate-limit Client; `bouncerEnabled` only bounces. `lapiMode` is the owned LAPI fetch strategy (`live` | `stream` | `none` | `alone`). AppSec-only is LAPI flag false plus AppSec flag true. `lapiMode: appsec` is rejected.
_Avoid_: treating mode as which legs run, implying AppSec from mode, crowdsecMode, enabled as own, implicit captcha own from provider

## Overview

Traefik Yaegi loads `CreateConfig` and `New` from the module-root package. `New` snapshots the config Traefik owns, Opens owned legs on a bind context, Publishes named slots (`core_plugin_middleware_instance-slots.md`), then returns a Bouncer that late-binds via `atomic.Value`. Keep `.traefik.yml` `import` equal to the `go.mod` `module` path. Specs: `core_plugin_middleware_bouncer`. Open key: `core_plugin_lapi_reclaim-key.md`.

## How to use

- Keep `CreateConfig` / `New` on the module root (`plugin.go`).
- Keep `pluginVersion` in root `version.go` (release workflow bumps it). Pass it into `lapi.New`, `appsec.New`, and `modsecurity.New`.
- Snapshot first: `config := *rawConfig`, then work on `&config` for the rest of `New`. Never write through Traefik's pointer.
- After the snapshot, do not copy leftover YAML keys or peer aliases into `BouncerBanFilePath` / `CaptchaFilePath`. Traefik’s decode of those two fields is the only owner.
- Derive `bindCtx, releaseHolders := context.WithCancel(ctx)` before the first `Open`, and release it from a `defer` that fires only when the named `err` is non-nil.
- Walk the `publishedLegs()` table (LAPI, AppSec, captcha, ModSec, rate limit) for every per-leg step; do not wire a leg by hand (`core_plugin_middleware_instance-slots.md`). Call each `prepare` (`lapi.Prepare`, `appsec.Prepare`, `captcha.Prepare`, `modsecurity.Prepare`, `prepareRateLimit`: each fills an omitted instance name when that leg is owned; AppSec key/scheme copy only when AppSec is enabled; `prepareRateLimit` also resolves the Redis password and parses the sync rate). Then each enabled leg's `open` (`lapi.Open` does not read `lapiMode` to pick an entry point; mode stays on `Config`). Then `reclaim.SetAlias` with group `lapi`/`appsec`/`captcha`/`modsec`/`ratelimit`. A later claim failure `ClearPublisher`s the enabled legs before it in table order. When this `New` did not Open a leg, `reclaim.ClearPublisher(name, group)`. `bouncer.New` takes one `bouncer.Subscriptions` value, not client pointers. `Watch` after New. Open key: `core_plugin_lapi_reclaim-key.md`. Stream `scopes=`: `core_plugin_lapi_scope-union.md`. Slots: `core_plugin_middleware_instance-slots.md`.
- `ServeHTTP` Loads `atomic.Value` only, the rate-limit Client included. Order after trusted-IP and action-rule ban: LAPI, rate limit (`serveRateLimit`), AppSec, ModSec, `next`. A missing subscribed LAPI or AppSec client uses that leg's failure action. A missing subscribed captcha client bans a captcha verdict. A missing subscribed ModSec client uses that router's `bouncerModsecFailureAction` (`core_plugin_modsecurity_inspect.md`). Do not block `New`. Do not put a startup flag on the client.
- When a captcha owner Opens the captcha `http.Client`, set `Timeout` from `cfg.CaptchaSiteverifyHTTPTimeoutSeconds`. Siteverify and assessments share that client. Publish it. Do not construct captcha on bounce-only.
- The rate limit is the last published leg: `rateLimitEnabled` Opens the rate-limit Client (Redis counter, buckets, policy) and publishes it under `rateLimitInstanceName`; `bouncerEnabled` plus that name Watches it (`core_plugin_ratelimit.md`).
- Put stream tickers, replaceable LAPI HTTP (`transport` on `atomic.Value`), Range membership, and the `live` / `none` admission gate on `lapi.Client` (`core_plugin_lapi_connection.md`). Open the DecisionStore on the same `New` ctx (`core_plugin_decisionstore.md`). Put AppSec HTTP+auth and the AppSec admission gate on `appsec.Client`. Put captcha widget, verifier, template, and gate on `captcha.Client`. Put sidecar HTTP and the ModSec admission gate on `modsecurity.Client`. Put the rate-limit counter, buckets, failure action, status code, and `Retry-After` switch on `ratelimit.Client`. Put ban templates, the LAPI, AppSec, and ModSec failure actions and backoff actions, Redis fail-closed, live-cache TTL, and this router’s remediation header on Bouncer. Timeout/TLS/backoff changes are a new ownership key, not Adopt-only.
- Format the remediation header in `pkg/bouncer/remediation_header.go` (`formatRemediationHeader`). Join `kind:reason`; append a third field only through `headerThirdField`, and only when it is non-empty: the encoded origin when reason is `lapi`, the bucket name (origin minus `plugin:ratelimit:`) when reason is `ratelimit`. Strip CR/LF/TAB from that field; rewrite only the prefix `lists:` → `lists_`. Map the other plugin `OriginPlugin*` origins (`ratelimit-failure` included) and AppSec specials to closed reason tokens, never a third field. Never derive `lapi-backoff`, `appsec-backoff`, or `modsec-backoff` from an origin: a backoff answer shares its leg's failure origin, so the writer passes that reason. Empty kind or reason MUST NOT invent `allow: pass`. Pass the already-formatted challenge-page value into `captcha.Client.ServeHTTP`; Pass 302 and `WriteSolvedRedirect` write `captcha:solved` inside captcha. Do not emit this header on pass, bypass, trusted, passthrough, remap-to-pass, widget-asset, valid gate-cookie origin GET, or disabled.
- Do not pass `config.LapiDefaultDecisionSeconds` from the bouncer into `LiveLookup`; the bound client already has it.
- Resolve client IP with `pkg/ip.GetRemoteIP`. Pass that string and `ipAddr` into `clientrequest.New` (`core_plugin_clientrequest_inbound-request.md`). Keep the name `req`.
- After the trusted-client skip, fold `bouncerActionRules` (`core_plugin_middleware_action-rules.md`). Any matching ban remediates immediately. Else skip LAPI and/or the rate limit and/or AppSec and/or ModSec and/or set a captcha flag. Captcha is not an early return. Trusted clients skip LAPI, the rate limit, AppSec, and ModSec.
- Compile `bouncerActionRules` once in `bouncer.New` via `httprule.NewActionSet` (`core_plugin_httprule.md`). Do not compile on the request path. Path owner is `req.URL.Path` as `net/http` decoded it; do not rebuild from `RequestURI`, `EscapedPath`, or AppSec forwarded URI. Host owner is the hostname of `req.Host` (`net.SplitHostPort` when that succeeds). Do not hash this list into LAPI ownership or AppSec identity.
- Range and header-mapped CrowdSec scopes live in `pkg/decisionscope`. Do not geolocate in `New` or `ServeHTTP`.
- Live LAPI error and stream-unhealthy cache miss use `bouncerLapiFailureAction` through `applyLapiFailureAction`, which takes the header reason from its caller (`lapi-failure` or `stream-unhealthy`). Cache hits still apply when the stream is unhealthy. `passthrough` uses the pass path (AppSec still runs if enabled).
- Answer a gate skip (`lapi.ErrGateSkip`, `appsec.ErrGateSkip`, `modsecurity.ErrGateSkip`) with `applyBackOffAction` and that leg's backoff action, never the failure action. Pass the leg's ban reason (`LAPI` / `APPSEC` / `MODSEC`), header reason `<leg>-backoff`, and the leg's failure origin (`plugin:lapi_failure`, `plugin:appsec_failure`, `plugin:modsec_failure`). `passthrough` writes nothing and the next leg runs; `ban` goes through `banWarnCaptchaRule`; `captcha` goes through `captchaUnlessBypassed` (`core_plugin_lapi_connection.md`, `core_plugin_appsec.md`, `core_plugin_modsecurity_inspect.md`).
- In `bouncer.New`, call `warnStricterBackOffActions` after the actions are resolved: one WARN `crowdsec bouncer backoff action stricter than failure action` (`leg`, `failureAction`, `backOffAction`) per subscribed leg whose backoff action outranks its failure action (`passthrough` < `captcha` < `ban`). Skip LAPI when this router opens LAPI itself in `stream` / `alone`. Never fail `New` on it.
- Watch logs `reclaim_put|bind|orphan|reclaim|dispose` and `crowdsec lapi instance|crowdsec appsec instance|crowdsec captcha instance|crowdsec modsec instance|crowdsec ratelimit instance|crowdsec bouncer bound|crowdsec bouncer unbound`.

## Pattern snippet

```go
func New(ctx context.Context, next http.Handler, rawConfig *configuration.Config, name string) (handler http.Handler, err error) {
	config := *rawConfig
	legs := publishedLegs()
	for _, leg := range legs {
		_ = leg.prepare(&config, log, name)
	}
	bindCtx, releaseHolders := context.WithCancel(ctx)
	defer func() {
		if err != nil {
			releaseHolders()
		}
	}()
	err = openOwned(bindCtx, legs, &config, log, name)
	err = claimOwned(legs, &config, log, name)
	var subscriptions bouncer.Subscriptions
	for _, leg := range legs {
		if leg.subscribes(&config) {
			leg.subscribe(&subscriptions)
		}
	}
	route, err := bouncer.New(next, name, &config, subscriptions, log)
	return route, err
}
```

## Key files

- `plugin.go`
- `pkg/reclaim/default.go`
- `pkg/lapi/`
- `pkg/lapi/client_http.go`
- `pkg/lapi/client_live.go`
- `pkg/appsec/`
- `pkg/modsecurity/`
- `pkg/captcha/captcha.go`
- `pkg/captcha/session.go`
- `pkg/bouncer/bouncer.go`
- `pkg/bouncer/bouncer_backoff_action.go`
- `pkg/bouncer/bouncer_serve_lapi.go`
- `pkg/bouncer/bouncer_serve_appsec.go`
- `pkg/bouncer/bouncer_serve_appsec_verdict.go`
- `pkg/bouncer/bouncer_serve_captcha.go`
- `pkg/bouncer/bouncer_serve_remediation.go`
- `pkg/bouncer/bouncer_serve_modsec.go`
- `pkg/bouncer/bouncer_leg_modsec.go`
- `pkg/bouncer/leg_binding.go`
- `pkg/bouncer/bouncer_serve_ratelimit.go`
- `pkg/ratelimit/`
- `pkg/bouncer/remediation_header.go`
- `pkg/clientrequest/request.go`
- `pkg/httprule/`
- `.traefik.yml`

## Gotchas

- Unused keys (`banHtmlFilePath`, `captchaHtmlFilePath`, leftover `bouncerCaptcha*`, leftover `bouncerAppsecExcludeRegex` / `bouncerLapiExcludeRegex`, leftover `bouncerAppsecBypassRules` / `bouncerLapiBypassRules` / `bouncerDecisionHeader`, source-plugin `modSecurityUrl`, HTML-cased twins) never reach `New` (Traefik v3.7.11 drops them). Operators who set only those keys get CreateConfig defaults (`BouncerBanFilePath` empty, `CaptchaFilePath` `/captcha.html`). Do not re-add Config fields or `New` copies to catch leftovers. A leftover pre-prefix `captchaFilePath` binds `CaptchaFilePath` again (the captcha stem, not an alias).
- The reclaim table has no Release: a holder goes away only when the context it bound is Done (`std_go_reclaim.md`). That is why `New` opens on `bindCtx` — with Traefik's own long-lived ctx, a constructor that failed after `Open` left the stream ticker polling LAPI for the process lifetime.
- Do not release `bindCtx` on the success path, and do not parent it on `context.Background()`: the first disposes the incarnation the handler is about to use, the second survives a Traefik shutdown.
- `lapiMode: appsec` is invalid (E4). AppSec-only is `lapiEnabled: false` plus `appsecEnabled: true`.
- When `appsecEnabled` is true, `ValidateParams` rejects an empty `appsecHost` (`http.NewRequest` accepts `http:///`). Disabled-AppSec empty host still passes. Do not require the host in `validateURL` or `validateParamsRequired`.
- Ownership Open key includes middleware name plus client knobs (LAPI: mode, URL, key, TLS, `lapiHttpTimeoutSeconds`, Redis, stream scopes, CAPI, intervals, `lapiUpdateMaxFailure`, `lapiDefaultDecisionSeconds`, and `lapiUnhealthyBackOffPeriodSecs` in `live` / `none` only). Slot name, `bouncerEnabled`, `bouncerDecisionScopeHeaders`, every failure and backoff action, and action rules are not in it. AppSec key includes middleware name plus listener knobs including TLS, `appsecHttpTimeoutSeconds`, and `appsecUnhealthyBackOffPeriodSecs`. ModSec key includes middleware name plus sidecar URL, timeout, body limit, and `modsecUnhealthyBackOffPeriodSecs` (`core_plugin_modsecurity_client.md`). Captcha key includes middleware name plus instance-owned captcha knobs (provider, keys, files, timeouts, template, gate, custom paths, recaptcha-enterprise knobs, `logLevel`, `logFilePath`, `logFormat`). Slot name, bounce, failure actions, remediation header, and action rules stay off it. `core_plugin_lapi_reclaim-key.md`. `pkg/captcha/session.go`.
- `bouncerLapiFailureAction`, `bouncerAppsecFailureAction`, `bouncerModsecFailureAction`, and the three backoff actions are per-router on Bouncer. Two routers on one published client MAY disagree, and share that Client's one gate. Rate-limit subscribers cannot: the buckets, failure action, status code, and `Retry-After` switch travel on the owner's Client. Action rules are the same: two routers MAY disagree, and they are not in reclaim keys.
- Stream/alone: CrowdSec stores one `GET /v1/decisions/stream` cursor per hashed API key plus the IP LAPI sees. Two stream owners with the same host and key log `crowdsec lapi stream collision` and both `New` succeed. DecisionStore key is `SessionHex` (canonical stream scopes; Redis block only when enabled). Subscribers must not Bind reclaim. Isolated backends still need a second bouncer key unless they only subscribe.
- LAPI `Close()` stops tickers, Closes a non-nil live admission gate, and idle LAPI HTTP. It does not Close the shared DecisionStore unless this incarnation still owns it. AppSec `Close()` Closes a non-nil admission gate and idle AppSec HTTP. ModSec `Close()` Closes a non-nil admission gate and idle sidecar HTTP. Do not use `sync.Once`.
- Both puts use `Open` / `OpenWithHooks` on the process table. First `New` sets table grace from `reclaimGraceSeconds` (default 30). Utilities `DefaultGrace` (10s) is only the table’s negative-grace fallback.
- Backend Create/Close at INFO (`crowdsec lapi instance started|closed`); Sleep/Wake at DEBUG. Watch calls `func(any)` with `reclaim.Published` when the published client changes. `ReceiveLAPI` / `ReceiveAppSec` / `ReceiveCaptcha` / `ReceiveModSec` / `ReceiveRateLimit` store that value and log bound at INFO and unbound at DEBUG once per pointer. `ReceiveLAPI` warns `crowdsec bouncer stream scopes missing`; `ReceiveRateLimit` logs the owner-unavailable WARN / owner-available INFO and the captcha-unavailable ERROR (`core_plugin_ratelimit.md`). `ServeHTTP` only Loads. DecisionStore INFO uses `storeKey` and `engine`. `reclaim_put`, `reclaim_reclaim`, and `reclaim_dispose` stay DEBUG. Stream poll stems are DEBUG. `startup` is an attribute on poll/updated (`true` for the full-set GET).
