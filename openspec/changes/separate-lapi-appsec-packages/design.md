## Context

See proposal.md — Why. Today `CrowdsecConnection` holds LAPI stream/cache/metrics and an AppSec HTTP client. Live identity and stream settings hash AppSec fields. Yaegi `New` must stay on the module root and keep using constructor `ctx` with `reclaim.OpenWithGrace`. Client IP stays `pkg/ip.GetRemoteIP`.

## Goals / Non-Goals

**Goals:**
- Two packages, two reclaim keys, Bouncer holds both pointers.
- LAPI identity/session exclude AppSec; AppSec reclaim is listener URL+key+TLS.
- Compile, unit tests, and Yaegi tests pass with the new import paths.

**Non-Goals:**
- Changing public Traefik JSON keys or `crowdsecMode: appsec`.
- Splitting `pkg/configuration`.
- Changing AppSec protocol, challenge relay, or LAPI stream/live lookup algorithm.
- A third shared HTTP-helper package.

## Decisions

1. **`pkg/lapi` + `pkg/appsec`, no facade.** Alternative: keep `crowdsecconnection` as a re-export — rejected; the mixed name stays the call-site.

2. **Type names `lapi.Connection` and `appsec.Client`.** Alternative: keep `CrowdsecConnection` inside `package lapi` — rejected; the identifier still claims AppSec.

3. **Separate reclaim, not AppSec-inside-LAPI-New.** Alternative: `lapi.Connection` holds `*appsec.Client` constructed in `lapi.New` — rejected; one owner still has two jobs and AppSec stays in LAPI identity.

4. **Copy `closeIdle` / `isReverseProxyError` into each package.** Alternative: `pkg/httpx` — rejected; not enough job to own a package.

5. **`appsec.Prepare` after `lapi.Prepare`** so empty AppSec key can copy the resolved LAPI key. Alternative: plugin.go copies keys — rejected; that is AppSec's fallback job.

6. **`crowdsecMode: appsec` skips LAPI Open** (`conn` nil). AppSec Open only when `crowdsecAppsecEnabled`. Alternative: always Open a dummy LAPI connection — rejected; no stream/cache/metrics to own.

7. **Reclaim prefixes `lapi:`, `lapi:stream:`, `appsec:`.** Alternative: keep `crowdsecconnection:` — rejected; the prefix would name a deleted package.

## Risks / Trade-offs

- [Live Redis prefix changes] → one-time cache miss; TTL is `defaultDecisionSeconds`. Stream `SessionHex` unchanged.
- [Reload during grace after prefix rename] → old `crowdsecconnection:` slot is not Woken; same as any identity change; 30s Close.
- [Yaegi foreign type assert] → both creates return `*reclaim.Wrapped`.
- [Nil LAPI conn on appsec mode] → Bouncer nil-guards `conn` on ServeHTTP / metrics.

## Migration Plan

Deploy the plugin binary/module as usual. No operator YAML change. Live-mode Redis keys get a new prefix; old keys expire. Rollback is the previous module version.

## Open Questions

None. Explore decisions were resolved by the human.
