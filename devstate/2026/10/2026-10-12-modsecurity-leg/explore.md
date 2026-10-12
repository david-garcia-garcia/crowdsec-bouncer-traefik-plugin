# Explore

## Concepts

Absorb `david-garcia-garcia/traefik-modsecurity` (Apache-2.0, `@e860d249`) as a fourth reclaim leg beside LAPI, AppSec, and captcha. Copy that plugin's `backendbackoff.Gate` onto AppSec so a down listener stops being hammered and does not keep banning every request. Port as much of that repo's real Pester coverage as this stack can host. README documents the whole product including the ModSecurity leg.

### Units this change would touch

| Name | Path | Job |
| --- | --- | --- |
| Yaegi New | `plugin.go` | Open / claim / Watch one more group (`modsec`) using the existing two-axis (own vs bounce) pattern. |
| Bouncer | `pkg/bouncer/bouncer.go`, `pkg/bouncer/bouncer_leg_*.go` | Fourth `atomic.Value` binding; `ServeHTTP` runs ModSec after AppSec; `ReceiveModSec` mirrors AppSec. |
| AppSec Client | `pkg/appsec/client.go`, `pkg/appsec/query.go`, `pkg/appsec/session.go` | Own a `backendbackoff.Gate` on the listener; Query admits then Reports; ownership key includes backoff knobs. |
| AppSec failure action | `pkg/configuration/configuration.go`, `openspec/specs/core_plugin_appsec_failure-action/spec.md` | Keep public `bouncerAppsecFailureAction` default `ban` for an admitted failure. Unhealthy skip does not call AppSec. |
| ModSecurity Client | `pkg/modsecurity/` (new; absorb source `pkg/modsecurity`) | Reclaim value: sidecar HTTP, body pool, deny-verbs, compiled bypass folded into action rules, admission gate, inspect copy. |
| Action rules | `pkg/httprule/action.go` | Token `bypassModsec`; `bypass` also skips ModSec; `ActionMatch.SkipModsec`. |
| Config | `pkg/configuration/configuration.go` | `modsec*` ownership knobs; `bouncerModsecFailMode` per-router; AppSec backoff knobs on the AppSec Client identity. |
| Real e2e | `tests/e2e/real/`, `PesterDomains.ps1`, `.github/workflows/e2e.yml` | New domain `modsec`; CRS sidecar compose; port source Pester families. |
| README | `README.md` | Whole-project capabilities and ModSec config. Traefik Security list no longer advertises a second plugin. |
| Utilities gate | `github.com/david-garcia-garcia/traefik-middleware-utilities/backendbackoff` at dest pin `v1.0.7` | Owner of the admission algorithm. Dest already requires `v1.0.7`; it does not import this package yet. |

### How they connect

```
Traefik New
  Prepare lapi → appsec → captcha → modsec
  openOwned  (holder)     groups: lapi | appsec | captcha | modsec
  claimOwned (SetAlias)   alias:<group>:<instanceName>
  bouncer.New(subscribe flags)
  Watch each subscribed alias → atomic.Value

ServeHTTP
  GetRemoteIP → clientrequest.New
  trusted client? → next
  actionRules.Fold  (ban | skipLapi | skipAppsec | skipModsec | captcha)
  serveLAPI
  serveAppSec          AppSec Client.Query + Gate
  serveModSec          ModSec Client inspect copy + Gate
  next

AppSec Client                         ModSec Client
  CrowdSec AppSec JSON protocol         CRS sidecar: copy request, classify status
  FailureAction on admitted miss        failMode open|close on admitted miss / skip
  Gate skip → next (assumed)            Gate skip → failMode (default open)
```

### Call sites that matter

Roots searched in the worktree: `*.go` under `plugin.go`, `pkg/bouncer/`, `pkg/appsec/`, `pkg/httprule/`, `pkg/configuration/`.

- Production `appsec.Client.Query`: **1** (`pkg/bouncer/bouncer.go` `applyAppsecServeHTTP`). Tests call Query directly; they migrate with this change.
- `openOwnedLeg` / `claimOwnedLeg` / Watch / subscribe flags: **1 file** `plugin.go`, three existing legs each.
- `bouncer.New` subscribe arity: **1** production constructor (`plugin.go`); tests construct `Bouncer` literals.
- `httprule.compileActionTokens` / `Fold`: **1** owner (`pkg/httprule/action.go`). Request-path Fold: **1** (`pkg/bouncer/bouncer.go` `ServeHTTP`).
- Trusted-client skip: **1** (`ServeHTTP` `isTrusted`).
- `backendbackoff` in dest: **0** imports (package exists on utilities `v1.0.7` = `42e6a1a`).

### Reproduce

**not reproduced** — no failure is claimed. Dest was inspected: `plugin.go` names `legLAPI`, `legAppSec`, `legCaptcha` only; `pkg/modsecurity` is absent; `bouncerAppsecFailureAction` default is `ban` with per-request `resultForFailureAction` and no gate; README Traefik Security still lists `traefik-modsecurity` as a sibling plugin.

### Outside facts used

- `https://github.com/david-garcia-garcia/traefik-modsecurity@e860d249` via GitHub MCP (README, `modsecurity.go`, `pkg/modsecurity/{config,plugin,serve}.go`, `Test-Integration.ps1`, `scripts/*.Tests.ps1`).
- `https://github.com/david-garcia-garcia/traefik-middleware-utilities@v1.0.7` (`42e6a1a`) `backendbackoff/gate.go`.
- In-tree: `knowledge/devdocs/core_plugin_middleware.md`, `core_plugin_middleware_instance-slots.md`, `core_plugin_appsec.md`, `core_plugin_clientrequest_inbound-request.md`, `core_plugin_httprule.md`, `core_plugin_middleware_action-rules.md`, `build_e2e_real.md`; `knowledge/research/ext_crowdsec_bouncers_failure-action/`; live specs `core_plugin_middleware_bouncer`, `core_plugin_middleware_instance-slots`, `core_plugin_appsec_failure-action`.
- In-tree research: `knowledge/research/ext_traefik-modsecurity_backoff/`, `ext_traefik-modsecurity_inspect/`, `ext_traefik-modsecurity_e2e/` (pin `traefik-modsecurity@e860d249`).

## Decisions

- Chosen seam: extend the dest three-leg reclaim pattern. New group `modsec`, package `pkg/modsecurity`, JSON stems `modsec*`. Own (`modsecEnabled`) vs bounce (`bouncerEnabled` + `modsecInstanceName`) stay independent, same as AppSec.
- Chosen inspect protocol: keep the source sidecar contract (copy request; 2xx allow; 3xx/4xx copy block page; 5xx is a WAF failure, not a block). Do not speak CrowdSec AppSec JSON on this leg. Not a replacement for AppSec.
- Chosen AppSec backoff: import utilities `backendbackoff.Gate` onto `appsec.Client` (one gate per listener). Do not copy Gate into this repo. Do not change `bouncerAppsecFailureAction` default `ban`. After the gate trips, skipped requests do not call AppSec and continue (`next`), so a down AppSec does not keep taking ingress down. Admitted failures still use FailureAction.
- Chosen ModSec fail path: per-router `bouncerModsecFailMode` (`open` default / `close` → empty HTTP 502), matching dest's per-router AppSec FailureAction placement, while the gate stays on the Client. Source plugin stored failMode on the shared Plugin; dest siblings put fallback on the Bouncer.
- Chosen skip list: do not add a parallel `bypassRules` config. Fold source bypass into `bouncerActionRules` (`bypassModsec`; `bypass` skips LAPI+AppSec+ModSec). See `deviations.md`.
- Chosen identity: this plugin's client address stays `pkg/ip.GetRemoteIP` → `clientrequest.Request`. The CRS sidecar `REMOTE_ADDR` stays Traefik `forwardedheaders` plus CRS RemoteIP config. The inspect copy sets `Host` and copies headers as Traefik left them; it does not set `X-Real-IP` and does not append `RemoteAddr` to XFF (source plugin).
- Chosen ServeHTTP order: trusted → action-rule ban → LAPI → AppSec → ModSec → `next`. Each writer short-circuits.
- Chosen e2e: new Pester domain `modsec` (CI matrix fourth job). Port source families that map: basic allow, CRS block (`?test=../etc`), body-size 413, failMode/backoff, deny-verbs-with-body, action-rule skip. Apache CRS inspect-only sidecar first; nginx stack if it fits the same harness. Do not port bombardier benches as product tests.
- Chosen README: document ModSec as a leg of this plugin; stop listing `traefik-modsecurity` as a separate Traefik plugin in Traefik Security. Geoblock and Ratelimit stay sibling middlewares (out of scope).
- Rejected: replacing or removing AppSec (out of scope).
- Rejected: shipping a second Traefik plugin (out of scope).
- Rejected: changing LAPI/captcha product behavior except the fourth-leg open/claim/Watch/rollback wiring.
- Rejected: changing AppSec FailureAction default to `passthrough` (live spec default `ban`; backoff is the commissioned extra layer).
- Rejected: a second slot table or `atomic.Pointer[T]`.
- Live contract: `openspec/specs/core_plugin_middleware_bouncer` (fourth binding, serve order), `core_plugin_middleware_instance-slots` (fourth group), `core_plugin_middleware_config-validation` (open-vs-subscribe matrix), `core_plugin_appsec_failure-action` (backoff layer; default `ban` remains), action-rule / httprule specs (new token), `build_e2e_pester_crowdsec-stack` (new domain). New ModSec inspect/client specs at propose (`FindSpecHost` new under `core` / `plugin`).

## Open questions

- Q: How does a fourth leg bind (instance name, reclaim, subscribe) once designed?
  Rank: bounded asked — changes existing `plugin.go` open/claim/Watch and `bouncer.New` (1 file + 1 constructor; three existing legs enumerated); Desired "A new ModSecurity leg alongside LAPI, AppSec, and captcha"
  Decision: assumed — copy the dest pattern. Group `modsec`, alias `alias:modsec:<name>`, `modsecEnabled` owns, `bouncerEnabled` + non-empty `modsecInstanceName` subscribes, `Open` + `SetAlias` + `Watch` + `ReceiveModSec`. Exclusive publish and multi-leg rollback include this group (captcha-claim failure also `ClearPublisher` modsec). JSON stems `modsec*` (dest `appsec*`/`lapi*`/`captcha*`), not the source plugin's `modSecurityUrl` camelCase.
  By: explore

- Q: Who already owns client address / Host / trust hop for the ModSec inspect copy?
  Rank: additive asked — new sidecar forward this change creates; Desired absorb + inspect copy
  Decision: assumed — reuse owners, do not reconstruct. Plugin remediations and logs: `pkg/ip.GetRemoteIP` then `clientrequest.New` (existing). Sidecar `Host`: inbound `req.Host`. Sidecar `REMOTE_ADDR`: Traefik entrypoint `forwardedheaders` (`X-Real-Ip` / leftover XFF) plus CRS `REMOTEIP_*` / `REAL_IP_*` on the WAF container. Copy headers as Traefik left them; do not set `X-Real-IP`; do not append `RemoteAddr` to XFF (`traefik-modsecurity` README + `serve.go` `@e860d249`).
  By: explore

- Q: What is the exact back-off algorithm, knobs, and pass/fail behavior to copy onto AppSec?
  Rank: bounded asked — reshapes `appsec.Client.Query` (1 production caller `applyAppsecServeHTTP`; roots `pkg/appsec/**`, `pkg/bouncer/**`); Desired "Copy the back-off strategy from the modsec plugin onto AppSec so a down AppSec does not take ingress down"
  Decision: assumed — same Gate as the source plugin: `backendbackoff.Gate` from utilities `v1.0.7`, built when backoff seconds > 0. Knobs on the AppSec Client identity (not per-router): `appsecUnhealthyBackOffPeriodSecs` default **30** (source README "Set to 30+" so the commissioned outcome holds without an extra operator step; **0** disables), threshold default 5, ratio default packaged 0.30, max backoff default = base. `Allow` then sidecar/AppSec; `Report` success on usable verdict; `Report` failure on transport / 5xx / AppSec unreachable; inbound cancel does not Report. After trip, skip does not call AppSec and continues to `next` (and ModSec if subscribed), even when `bouncerAppsecFailureAction` is `ban`. Admitted failures still use FailureAction (`ban` default unchanged). Close the Gate on Client `Close`.
  By: explore

- Q: Does AppSec default `ban` stay, with back-off as an extra layer, or does back-off imply a different down-path?
  Rank: bounded asked — live spec `core_plugin_appsec_failure-action` default `ban`; same Desired line as backoff
  Decision: assumed — default `ban` stays for an admitted AppSec miss (500, unreachable, unreadable body). Backoff is the extra layer: once unhealthy, skip is pass. Do not retarget the public enum to `open`/`close`.
  By: explore

- Q: Does "exactly the same as AppSec" hold at the HTTP and config layer, or only at "forward request, allow or block"?
  Rank: additive asked — new ModSec inspect this change creates; Unknowns on requirement.md
  Decision: assumed — only the last layer. AppSec is CrowdSec JSON (`X-Crowdsec-Appsec-*`, `action` allow/ban/challenge). ModSec is a CRS sidecar status class (2xx / 3xx-4xx / 5xx) with a raw request copy. Keep both protocols. Config is dest-shaped (`modsecUrl` absolute http(s) base like source `modSecurityUrl`, plus dest ownership/instance flags), not a clone of AppSec host/path/key/TLS.
  By: explore

- Q: Where does ModSec run on the request path relative to LAPI and AppSec?
  Rank: additive asked — new serve step; Desired "beside LAPI, AppSec, and captcha"
  Decision: assumed — after AppSec, before `next`. LAPI (cheap decision) then CrowdSec WAF then CRS WAF. A writer short-circuits. Trusted clients skip all three. Action-rule ban still returns before any WAF.
  By: explore

- Q: How do source `bypassRules` map onto this project's request-rule owner?
  Rank: bounded incidental — changes `pkg/httprule/action.go` `compileActionTokens`/`Fold` (1 owner; Fold at `ServeHTTP` + tests); no criterion names a second bypass list — means to absorb skip-sidecar
  Decision: assumed — no `modsecBypassRules` field. Add `bypassModsec`; `bypass` sets skipLapi+skipAppsec+skipModsec; `ActionMatch.SkipModsec`. Path/method predicates stay on `httprule.Rule` (already unanchored RE2 on `req.URL.Path`, same as source). Caller: deviations row.
  By: explore

- Q: Is ModSec failMode per-router or on the Client?
  Rank: additive asked — new fallback this change creates; source stored it on Plugin
  Decision: assumed — per-router `bouncerModsecFailMode` (`open` default, `close` empty 502) on Bouncer, like `bouncerAppsecFailureAction`. Gate stays on the Client so all routers sharing a listener skip together. Missing subscribed ModSec client uses that router's failMode.
  By: explore

- Q: How much of traefik-modsecurity real e2e maps onto `tests/e2e/real`?
  Rank: additive asked — Desired "Bring in as much real e2e coverage from the original traefik-modsecurity project as possible"
  Decision: assumed — new Pester domain `modsec` and CI matrix value `modsec` (partition must list every `*.Tests.ps1`). Compose adds an inspect-only CRS sidecar (Apache drain first; nginx if the same whoami/Traefik harness can switch). Port: service availability, CRS block on `../etc`, allow on clean GET, body-size 413, deny GET-with-body, failMode open/close, backoff skip `unhealthy`, action-rule skip. Unit tests in `pkg/modsecurity` absorb source `zzz_*` that do not need Docker. Skip bombardier benches. Source files: `Test-Integration.ps1`, `scripts/integration-tests.Tests.ps1` (Describe "ModSecurity Plugin Basic Functionality", "WAF Protection Tests"), `scripts/integration-tests.BodySize.Tests.ps1`.
  By: explore

- Q: Does README keep listing traefik-modsecurity as a sibling plugin?
  Rank: bounded asked — one existing README section; Desired "README.md states capabilities and configuration of the project as a whole, including how to configure the ModSecurity leg"; Out of scope keeps Geoblock and Ratelimit
  Decision: assumed — Traefik Security lists this plugin once; ModSec is a documented leg (config table + how it works). Remove the separate `traefik-modsecurity` sibling link. Leave Geoblock and Traefik Rate Limit.
  By: explore