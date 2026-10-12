## Context

Dest already has three reclaim legs (LAPI, AppSec, captcha) with own vs bounce axes, `atomic.Value` bindings, and action-rule skips. `pkg/modsecurity` is absent. AppSec `Query` applies `bouncerAppsecFailureAction` per admitted miss with no admission gate. Dest `go.mod` requires utilities `v1.0.7`; `backendbackoff` is not imported yet. Source plugin: `traefik-modsecurity@e860d249`. See proposal.md for motivation. Live contracts: proposal Capabilities.

## Goals / Non-Goals

**Goals:**

- Copy the captcha-leg wiring pattern (`openOwned` / `claimOwned` / `Watch` / rollback) to a fourth group `modsec`. Do not rewrite `plugin.go` into an N-leg registry.
- Absorb source `pkg/modsecurity` inspect, gate, deny-verbs, and body cap into dest-shaped types and JSON stems.
- Put `backendbackoff.Gate` on `appsec.Client` and on `modsecurity.Client`. One gate per listener.
- Port source Pester families that this stack can host as domain `modsec`.

**Non-Goals:**

- Replacing AppSec or speaking AppSec JSON on the CRS hop.
- A second Traefik plugin or a second slot table.
- Changing LAPI or captcha product behavior except fourth-leg Open/claim/Watch/rollback.
- Public `X-Waf-Status` request header (dest remediation header owns `ban:modsec`).
- Source unused `unhealthyWafFailureWindowSecs` knob.
- Source `maxBodySizeBytesForPool` as a public knob (pool stays internal).
- Bombardier benches as product tests.

## Decisions

1. **Fourth reclaim group, not a new table.** Same as captcha-leg. Alternative: `atomic.Pointer[T]` or a second slot package — rejected (Yaegi + existing owner).

2. **Inspect protocol stays CRS status class.** 2xx allow, 3xx/4xx copy block, 5xx failure. Alternative: wrap CRS as CrowdSec AppSec JSON — rejected (not a replacement for AppSec).

3. **`modsecUrl` absolute URL, not AppSec host/path/scheme/key/TLS.** Source is a sidecar base URL. Alternative: clone AppSec URL pieces — rejected (explore: only the last layer matches).

4. **FailMode per-router on Bouncer; Gate on Client.** Matches dest AppSec FailureAction vs Client identity. Alternative: source stored failMode on the shared Plugin — rejected (dest siblings put fallback on the Bouncer).

5. **AppSec skip-after-trip is pass; ModSec skip-after-trip follows failMode.** Desired: down AppSec must not take ingress down. ModSec default failMode `open` already passes. Alternative: retarget AppSec FailureAction default to passthrough — rejected (live spec default `ban`; backoff is the extra layer).

6. **AppSec backoff default 30; ModSec backoff default 0.** Source README says set AppSec-equivalent to 30+ for the commissioned outcome; ModSec fail-open does not need it. Alternative: copy source default 0 onto AppSec — rejected (Desired would not hold without an operator step).

7. **`bypassModsec` / `bypass` on action rules.** No `modsecBypassRules`. See deviations.md.

8. **`modsecBodyLimit` `0` is unlimited.** Dest `appsecBodyLimit` already owns that zero. Source Prepare treated `0` as omit-fill 8 MiB. See deviations.md.

9. **Identity owners.** Plugin remediations: `pkg/ip.GetRemoteIP` then `clientrequest.New`. Sidecar Host: inbound `req.Host`. Sidecar REMOTE_ADDR: Traefik forwardedheaders plus CRS RemoteIP config. Do not set `X-Real-IP`; do not append `RemoteAddr` to XFF.

10. **ServeHTTP order.** trusted → action-rule ban → LAPI → AppSec → captcha write → ModSec → `next`. Unsolved captcha still short-circuits before CRS (do not change captcha product behavior). AppSec gate skip does not return.

11. **Import Gate, do not vendor-copy.** `github.com/david-garcia-garcia/traefik-middleware-utilities/backendbackoff` at dest `v1.0.7`. Implement vendors the package.

12. **E2e Apache CRS first.** New domain `modsec` in `PesterDomains.ps1` and e2e.yml matrix. Nginx-drain only if the same harness can switch. Port: allow, `../etc` block, 413, deny GET-with-body, failMode, backoff skip, action-rule skip.

## Risks / Trade-offs

- [AppSec default backoff 30] → Operators who needed fail-closed on every down-AppSec request must set `appsecUnhealthyBackOffPeriodSecs: 0`. README must name this. Specs: `core_plugin_appsec_failure-action`.
- [CRS sidecar in real e2e] → First boot downloads CRS; matrix job time grows. Mitigation: fourth job only, Apache drain first, keep existing AppSec CRS job unchanged.
- [Yaegi + utilities Gate] → Gate must stay Yaegi-safe (no generics the interpreter rejects). Mitigation: dest already runs utilities `v1.0.7`; prove with constructor tests.
- [Source `0` body limit vs dest unlimited] → Operators copying source YAML `maxBodySizeBytes: 0` expecting 8 MiB get unlimited. Mitigation: dest key is `modsecBodyLimit`; README states `0` unlimited.

## Migration Plan

- New keys only for ModSec. Existing AppSec YAML keeps working; omitted AppSec backoff enables the 30s gate.
- README: how to configure the ModSec leg; drop `traefik-modsecurity` from Traefik Security; name the AppSec skip-after-trip behavior.
- Rollback: revert the change; dest three-leg tree has no ModSec keys to decode.

## Open Questions

None. Explore rows on `devstate/explore.md` stay assumed; this design takes those choices.
