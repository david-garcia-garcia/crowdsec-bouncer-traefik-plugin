# Explore

## Concepts

On `master`, one request is one cache key: the client IP `pkg/ip.GetRemoteIP` already resolved. Stream writes `decision.Value` as that key. LAPI `Decision.Scope` is decoded and ignored.

```
request ──► GetRemoteIP ──► Cache.Get(remoteIP) ──► ban | captcha | pass
                              ▲
stream New ── Set(decision.Value)   (Scope unused)
live/none ── GET /decisions?ip=     (LAPI expands Range)
```

CrowdSec scope is the *target* (Ip, Range, Country, AS, or any string). Type is the *action* (ban, captcha). Research: `knowledge/research/ext_crowdsec_decisions_scopes/`.

Live/none already get Range hits from LAPI `?ip=` containment. Stream/alone do not: a Range value `10.0.0.0/8` never equals `10.1.2.3`. Header scopes never match: Country `FR` is not an IP.

Upstream [PR 383](https://github.com/maxlerebourg/crowdsec-bouncer-traefik-plugin/pull/383) (head `newdecisions`) implemented:

- `decisionScopeHeaders` map (public). Empty = header scopes off. `Ip`/`Range` rejected as keys.
- Range: one cache key `range-index` (`cidr=remediation` lines). Ban wins overlap. No radix tree.
- Header scopes: cache key `scope:value`. Country/AS only special in value normalize.
- Stream `scopes=` includes every mapped header scope (unfiltered stream defaults to `ip,range`).
- Live/none: keep `?ip=`; add `scope`+`value` when a mapped header is present.

That work lives in the **root plugin package** (`bouncer.go`, `decision_scope.go`, `decision_ranges.go`). This fork's `master` split `New` (`plugin.go`) from `pkg/bouncer` and `pkg/crowdsecconnection`. Cherry-pick will not apply.

`pkg/ip` on `master` has `Checker.Contains` (trusted lists) and no `InNetwork`. 383 added `InNetwork` for one CIDR.

In-tree `pkg/simpleredis` already has `MGet`. 383 looped `GET` because CI vendored published v1.0.12. Do not keep that loop.

Identity: client address is already owned by `pkg/ip.GetRemoteIP`. Country/AS/username are owned by the **mapped request header** (CDN or geoblock). This plugin must not geolocate.

Real-stack e2e (`tests/e2e/real/`) injects only `cscli --ip` and `X-Forwarded-For`. Compose has no `decisionScopeHeaders`. Mock e2e on 383 (`tests/e2e/mock/scenarios/scope-headers/`) is not the real suite the caller asked for.

## Decisions

Port 383's behavior onto the split packages. Shared helpers cannot live in `pkg/bouncer` (`crowdsecconnection` must not import bouncer). New `pkg/decisionscope` owns scope keys, range-index, and ban-over-captcha. `pkg/cache.GetMany` uses `MGet` + prefix. `pkg/ip.InNetwork` is the one-CIDR helper (Checker stays the trusted-IP pool). Real e2e: new Pester file + compose middleware with `decisionScopeHeaders`; `cscli --range` and `--scope`/`--value`; extra headers on `Test-HttpRequest`. Keep mock `scope-headers` for fast CI.

Spec host: MASTER allowlist has `plugin`, not 383's `bouncer`. New spec `core_plugin_decisions_scopes`.

## Open questions

- Q: Who already owns the client address, country, ASN, and username used for matching?
  Decision: assumed — client IP is `pkg/ip.GetRemoteIP`; Country/AS/custom scopes are the mapped request header (CDN or geoblock). Do not geolocate or re-parse `RemoteAddr`.
  By: explore

- Q: Where do Range-index and header-scope helpers live under the `pkg/bouncer` + `pkg/crowdsecconnection` split?
  Decision: assumed — new `pkg/decisionscope` (connection cannot import bouncer; Yaegi already loads `pkg/*`).
  By: explore

- Q: How do we store Range decisions so Redis-sharing instances can match?
  Decision: assumed — one key `range-index` (`cidr=remediation`); CIDR containment via `ip.InNetwork`; no radix tree on this PR. Redis keys stay prefixed with `IdentityHex`.
  By: explore

- Q: Should Redis GetMany use in-tree `MGet` instead of 383's looped GET?
  Decision: assumed — yes. `pkg/simpleredis.MGet` exists on `master`. Prefix each key. One `nextReader()`.
  By: explore

- Q: Should CAPI (alone) send a `scopes` query parameter?
  Decision: assumed — no; apply any streamed scope this bouncer is configured to match.
  By: explore

- Q: What if a configured scope header is missing on a request?
  Decision: assumed — skip that scope; do not fail closed.
  By: explore

- Q: How do real-stack tests inject Range and header-mapped scopes?
  Decision: assumed — `cscli decisions add --range` and `--scope <name> --value <v>` (v1.7 docs). Range uses private `X-Forwarded-For`. Country is proven with traefik-geoblock enrich (public IP → `X-IPCountry`), not a client-set `CF-IPCountry`. Nested plugin maps use a file provider. Mock `scope-headers` still injects synthetic headers. Cover stream (cache) and none (live LAPI) for Range and Country.
  By: implement

- Q: Should [PR 368](https://github.com/maxlerebourg/crowdsec-bouncer-traefik-plugin/pull/368) merge onto `master` first?
  Decision: assumed — no. Stream-only Range keyed off `/` in `decision.Value`; does not close [#271](https://github.com/maxlerebourg/crowdsec-bouncer-traefik-plugin/issues/271).
  By: explore

- Q: Which OpenSpec id on this allowlist?
  Decision: assumed — new `core_plugin_decisions_scopes` (domain `plugin` already allowed). Do not add a `bouncer` domain just to copy 383's folder name.
  By: explore
