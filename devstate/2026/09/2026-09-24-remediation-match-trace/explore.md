# Explore

## Concepts

Units this change would touch:

- **Bouncer ServeHTTP TRACE** — `pkg/bouncer/bouncer.go`. Emits request-path breadcrumbs. After IP parse it logs `ip` + `isTrusted`. On a live/stream/alone store hit it logs a second `ServeHTTP` line with `ip`, leftover `cache=hit`, and `remediation` letter. Live/none miss uses stem `ServeHTTP:LiveLookup` (`ip`, `isBanned`). Apply uses `handleRemediationServeHTTP` (`ip`, `remediation`).
- **Request-path Trace style** — `pkg/logger/logger.go` `Trace`, usage `knowledge/devdocs/std_go_logger_debug-attrs.md`, live spec `openspec/specs/std_go_logger_debug-attrs/spec.md`. Stem + slog attributes; first `ServeHTTP` MUST keep `ip` and `isTrusted`. Tests: `pkg/bouncer/zzz_debug_attrs_test.go` (3 tests).
- **Header-mapped scopes** — `pkg/decisionscope/lookup.go` `RequestScopeValues`. One production call site: `pkg/bouncer/bouncer.go:443`. Country/AS normalized; missing headers omitted. Owner of header identity for the request.
- **Store merge** — `pkg/decisionstore/lookup.go` `lookupHits`. Merges Ip key, present header-scope keys, and Range membership. Ban wins. Return is kind, origin, originID — no winning scope or identifier. `RangeMembership.Remediation` returns `KindOriginString` only, not the CIDR text.
- **Client address** — `pkg/ip.GetRemoteIP` then `clientRequest.remoteIP` (`req.ipAddr.String()` after parse). Already logged. Do not re-parse.

```
  GetRemoteIP → clientRequest.remoteIP
        │
        ▼
  TRACE ServeHTTP (ip, isTrusted)     ← first breadcrumb; spec-required
        │
        ▼
  RequestScopeValues(headers, req)    ← in hand, not logged
        │
        ├── live/stream/alone ── LookupRemediation ── TRACE ServeHTTP (ip, cache=hit, remediation)
        │                                              └── handleRemediationServeHTTP (ip, remediation)
        │
        └── live/none miss ── LiveLookup ── TRACE ServeHTTP:LiveLookup (ip, isBanned)
```

Call sites that matter (bounded enumeration):

- `logger.Trace` remediating `ServeHTTP` (the leftover `cache=hit` line): **1** (`pkg/bouncer/bouncer.go:465`). Roots: `pkg/bouncer`, `pkg/logger`.
- First `ServeHTTP` TRACE (`ip`, `isTrusted`): **1** (`pkg/bouncer/bouncer.go:419`). Same roots. Spec + `zzz_debug_attrs_test.go` assert this line only.
- `ServeHTTP:LiveLookup` TRACE: **1** (`pkg/bouncer/bouncer.go:500`).
- `handleRemediationServeHTTP` TRACE: **1** (`pkg/bouncer/bouncer.go:588`). Also reached by forced-decision (out of scope).
- `RequestScopeValues`: **1** production (`pkg/bouncer/bouncer.go:443`); definition `pkg/decisionscope/lookup.go:53`; tests `pkg/decisionscope/zzz_scope_test.go`.
- `Client.LookupRemediation` request-path caller: **1** (`pkg/bouncer/bouncer.go:450`). Wrapper `pkg/lapi/client_lookup.go:8`. Store `pkg/decisionstore/store.go:197`. Engines: `memory.go`, `redis.go`. Test callers under `pkg/lapi`, `pkg/decisionstore`, `zzz_plugin_test.go` (search `LookupRemediation` in `*.go`).
- Live spec + TRACE attribute tests: **1** spec folder, **1** test file (3 tests). Search `"isTrusted"` in `*.go` / `openspec/specs`.

Reproduce: **reproduced**. Path: `go test ./pkg/bouncer -run "TestHunt_ServeHTTPTraceUsesAttributes|TestExplore_ServeHTTPTraceRemediationHit" -count=1 -v` in the ticket worktree (throwaway remediating test deleted after the dump). Allow-path `TestHunt_ServeHTTPTraceUsesAttributes` keeps `msg=ServeHTTP`, `ip=203.0.113.10`, `isTrusted=false`. Remediating stream seed (Ip ban on `203.0.113.10`, `CF-IPCountry=FR` and `CF-ASN=13335` mapped, headers present) dumped three TRACE records:

- `ServeHTTP` `ip=203.0.113.10` `isTrusted=false`
- `ServeHTTP` `ip=203.0.113.10` `cache=hit` `remediation=t`
- `handleRemediationServeHTTP` `ip=203.0.113.10` `remediation=t`

No Country, AS, or other mapped-scope attributes. Matches the ticket paste (`msg=ServeHTTP … ip=… cache=hit remediation=t`). Test sink prints Trace as `DEBUG-4`; product `NewWithFormat` names it `TRACE` (`std_go_logger_debug-attrs`).

Outside facts used: in-tree `knowledge/research/ext_crowdsec_decisions_scopes/` (scope is an open string; Country/AS/username are header-or-exact matches; this plugin does not geolocate). No new research write.

## Decisions

- Chosen seam: remediating TRACE on `pkg/bouncer/bouncer.go` (`ServeHTTP` store-hit line, and `ServeHTTP:LiveLookup`). Drop leftover `cache`. Keep `ip` and the remediation letter. Attach present `RequestScopeValues` as a slog group `scopes`.
- Chosen identity: reuse `GetRemoteIP` / `clientRequest.remoteIP` and the `RequestScopeValues` map already collected. Do not re-parse `RemoteAddr` or re-read headers at log time.
- Chosen contract: keep live `std_go_logger_debug-attrs` SHALL for first-breadcrumb `ip` + `isTrusted` + stem `ServeHTTP`. Add a remediating-line scenario (no `cache`; include present mapped scopes). Do not require `scopes` on the allow/trust breadcrumb.
- Rejected: change `LookupRemediation` / `lookupHits` to return a winning key — not asked; ServeHTTP can log the request scope map without a winner.
- Rejected: log only the winning scope/value — Desired asks for values **in play**; winner needs a lookup-return reshape this run will not take.
- Rejected: name the Range CIDR on TRACE — ticket named headers and AS; membership returns kind+origin, not CIDR text.
- Rejected: add match fields to `handleRemediationServeHTTP` — apply path, also forced-decision (out of scope).
- Rejected: fold DEBUG `ServeHTTP:Get` `cache` (that attr is the lookup error) — Out of scope unless this phase folded it; it does not.
- Live contract: `openspec/specs/std_go_logger_debug-attrs/spec.md` (ip, isTrusted, stem `ServeHTTP` stay).

## Open questions

- Q: Attribute names, and dump every present `RequestScopeValues` entry versus only the winning scope/value?
  Rank: additive asked — new slog attributes on a remediating TRACE this change edits; Desired "values of scoped remediations in play (headers, AS, and the other mapped scopes)"
  Decision: assumed — slog group `scopes` with each present `RequestScopeValues` key (CrowdSec scope name) and its header value. Omit missing headers. Do not add a separate winner field.
  By: explore

- Q: Should a Range membership hit name the CIDR (ticket named headers and AS, not Range)?
  Rank: additive incidental — would add a Range identifier field; no Desired/In-scope line names Range or CIDR (Unknowns only)
  Decision: assumed — do not log a Range CIDR. `RangeMembership.Remediation` returns `KindOriginString` only; Ip vs Range stays indistinguishable on TRACE.
  By: explore

- Q: Must `LookupRemediation` / `lookupHits` start returning the winning key, or can ServeHTTP log the request scope map without a winner?
  Rank: bounded incidental — changing the existing 4-tuple would migrate 1 request-path caller (`pkg/bouncer/bouncer.go:450`) plus wrapper/engines/tests (roots `pkg/bouncer`, `pkg/lapi`, `pkg/decisionstore`, `zzz_plugin_test.go`); no criterion names a lookup-return reshape
  Decision: assumed — do not change the lookup return. Log the `RequestScopeValues` map already in hand on ServeHTTP.
  By: explore

- Q: Must `ServeHTTP:LiveLookup` and `handleRemediationServeHTTP` TRACE carry the same match fields (ticket pasted the `cache=hit` ServeHTTP line only)?
  Rank: additive asked — new attributes on existing TRACE calls this change already owns; Desired "When a remediation fires, TRACE must show what triggered it"
  Decision: assumed — `ServeHTTP:LiveLookup` gets the same `ip` + `scopes` group + kind field (`isBanned` stays as today's kind attr). `handleRemediationServeHTTP` stays `ip` + `remediation` (apply path; forced-decision TRACE is out of scope).
  By: explore

- Q: Blast radius on `std_go_logger_debug-attrs` if new required fields land there?
  Rank: additive asked — new remediating-line scenario on the existing live spec listed under Affected; first-breadcrumb SHALL already requires `ip` and `isTrusted`
  Decision: assumed — keep the existing SHALL (first `ServeHTTP` TRACE: stem, `ip`, `isTrusted`). Add one remediating scenario: no `cache` attr; include present mapped scope values. Tests: extend `pkg/bouncer/zzz_debug_attrs_test.go` (1 file, 3 tests today). Do not require `scopes` on the allow/trust breadcrumb.
  By: explore

- Q: Who already owns client address and header-scope identity for this TRACE?
  Rank: additive asked — logging reuses identity already computed; Desired keeps client IP and asks for mapped scope values
  Decision: assumed — `pkg/ip.GetRemoteIP` owns the client address (`clientRequest.remoteIP` after `ipAddr.String()`). `decisionscope.RequestScopeValues` owns header identity. Reuse both outputs. None for Range CIDR (membership does not expose it). Traefik `RemoteAddr` and a second header walk are not owners.
  By: explore

- Q: Drop or rename leftover TRACE `cache=hit`, and fold DEBUG `ServeHTTP:Get` `cache`?
  Rank: additive asked — remove/replace an attr on the remediating TRACE this change edits; Desired "Stop presenting the hit as a cache hit"; DEBUG fold is Out of scope unless this phase folds it
  Decision: assumed — drop `cache` from the remediating `ServeHTTP` TRACE. Keep `remediation` (letter). Leave DEBUG `ServeHTTP:Get` `cache` (lookup error value) unchanged.
  By: explore
