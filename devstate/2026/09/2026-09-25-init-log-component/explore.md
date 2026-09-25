# Explore

## Concepts

Units this change would touch:

- `pkg/logger.NewWithFormat` (`pkg/logger/logger.go`) — sets slog `component` on every logger.
- `ip.NewChecker` (`pkg/ip/checker.go`) — builds a trusted-IP pool; today DEBUG-logs each insert (`IP is trusted` / `IP network is trusted`).
- `validateParamsIPs` (`pkg/configuration/configuration.go`) — constructs `NewChecker` and discards it to reject bad CIDRs for `BouncerForwardedHeadersTrustedIPs` and `BouncerClientTrustedIPs`.
- `bouncer.New` (`pkg/bouncer/bouncer.go`) — builds the hop Checker and the client Checker, then DEBUG `Bouncer initialized` with no network attributes.
- Tests that lock `component=CrowdsecBouncerTraefikPlugin`: `pkg/logger/zzz_logger_test.go`, `zzz_bouncer_logging_test.go`.
- Live specs: `openspec/specs/std_go_logger_slog-output` (`component` presence, not the value), `openspec/specs/std_go_logger_debug-attrs` (construct-time DEBUG stays; request-path TRACE is out of scope), `openspec/specs/core_plugin_ip_radix-lookup` (membership and GetRemoteIP ownership; no insert logging).
- Usage: `knowledge/devdocs/std_go_logger_debug-attrs.md` names construct-time DEBUG `Bouncer initialized` and does not list trusted-network attributes. `knowledge/devdocs/core_plugin_ip.md` owns Trusted-IP Checker / GetRemoteIP language.

```
plugin.New
  ├─ logger.NewWithFormat          → component=CrowdsecBouncerTraefikPlugin
  ├─ ValidateParams
  │    └─ validateParamsIPs ×2     → NewChecker (discard)  [per-entry DEBUG]
  └─ bouncer.New
       ├─ NewChecker(hop pool)     [per-entry DEBUG]
       ├─ NewChecker(client pool)  [per-entry DEBUG]
       └─ Debug "Bouncer initialized"   [no network attrs]
```

Call sites that matter:

- `CrowdsecBouncerTraefikPlugin`: 9 hits in `.go` (1 producer `pkg/logger/logger.go:97`, 6 locks in `pkg/logger/zzz_logger_test.go`, 2 locks in `zzz_bouncer_logging_test.go`). Roots searched: `*.go` and `*.md` under the worktree. Other hits are other tickets' `devstate/ticket/` dumps, not product code. README does not lock the string.
- `NewChecker(`: 26 call sites besides the definition (14 in `pkg/ip/zzz_checker_test.go`, 9 in `pkg/bouncer/zzz_*.go`, 2 in `pkg/bouncer/bouncer.go`, 1 in `pkg/configuration/configuration.go`). Roots searched: those three packages. No test asserts `IP network is trusted` or `IP is trusted`.
- `Bouncer initialized`: 1 site (`pkg/bouncer/bouncer.go:148`).

Reproduce: ran `go test . -run TestBouncerFileLoggingCommonFormat` (DEBUG, hop pool `127.0.0.1`) — pass, 13 common-format lines. Ran a throwaway `NewChecker` capture (deleted after) with the ticket's five CIDRs plus one bare host — 5× `IP network is trusted` and 1× `IP is trusted`. Claim holds.

Outside facts used: in-tree. slog `component` is this package's string; slice attrs are Go slog. No research slug.

Identity (request client address / trust hop): GetRemoteIP already owns the per-request client address (`core_plugin_ip.md`, `core_plugin_ip_radix-lookup`). Checker owns pool membership. This change logs Config slices already in hand at `bouncer.New`; it does not reconstruct hops or client IP.

## Decisions

- Chosen seam: stop insert DEBUG in `NewChecker`; attach the two config slices as slog attributes on the existing `bouncer.New` DEBUG `Bouncer initialized`; change `NewWithFormat` `component` to `CrowdsecBouncer`.
- Rejected: keep per-entry Checker logs and add a summary (would still be many lines). Log once from `NewChecker` (validate plus two pools → up to three lines, not `Bouncer initialized`). Combine both pools into one list (hides which pool). Use `CrowdsecBounder` as the component (misspelling next to the existing `CrowdsecBouncer` type/template). Stop `validateParamsIPs` from constructing `NewChecker` (validation is its job; silence comes from Checker). Rename the HTML template `CrowdsecBouncer` (out of scope).
- Live contract: `std_go_logger_slog-output` (SHALL have a `component` attribute; does not lock the value). `std_go_logger_debug-attrs` (construct-time DEBUG remains; request-path TRACE out of scope). `core_plugin_ip_radix-lookup` (membership / GetRemoteIP; no insert-log requirement). No leaf today for the component value or for trusted-network attrs on `Bouncer initialized`.

## Open questions

- Q: What shorter slog `component` string do we use (`CrowdsecBounder` vs `CrowdsecBouncer`)?
  Rank: bounded asked — 9 `.go` occurrences enumerated (1 producer, 8 test locks); roots `pkg/logger` and module-root `zzz_bouncer_logging_test.go`; Desired names the rename
  Decision: assumed — `CrowdsecBouncer`. The ticket typed `CrowdsecBounder` as an example; the existing type and template name is `CrowdsecBouncer`. Do not invent a third name. Job (shorter component) survives.
  By: explore

- Q: Are forwarded-headers vs client trusted pools two attrs or one combined list, and what are the attr names?
  Rank: additive asked — new fields on the existing `Bouncer initialized` line; Desired prefers attaching ranges to that line
  Decision: assumed — two attrs on that same line: `forwardedHeadersTrustedIPs` and `clientTrustedIPs`. Values are the config slice strings as written (bare hosts stay bare, not rewritten to `/32`/`/128`). One combined list would hide which pool.
  By: explore

- Q: Must `validateParamsIPs` stop constructing `NewChecker`?
  Rank: additive incidental — no criterion names a validate rewrite; Unknown on requirement.md
  Decision: assumed — keep constructing `NewChecker` to reject bad CIDRs. After insert DEBUG is removed, validate no longer emits per-entry lines.
  By: explore

- Q: Must bare-host `IP is trusted` lines fold the same way as CIDR `IP network is trusted`?
  Rank: bounded asked — both Debug calls live in `pkg/ip/checker.go` (lines 32 and 40); Desired "All trusted IP ranges appear on one DEBUG line"
  Decision: assumed — fold both. The sample showed only CIDRs; both enter the same pools.
  By: explore

- Q: Do empty trusted lists still emit `Bouncer initialized` with empty network attrs?
  Rank: additive asked — attrs on the existing construct-time DEBUG line; Desired is that init shows how the bouncer is configured
  Decision: assumed — still emit `Bouncer initialized` with both attrs; nil or empty slices log as empty lists.
  By: explore

- Q: Who already owns client address and trust-hop identity for this change?
  Rank: additive asked — `core_plugin_ip_radix-lookup` names GetRemoteIP as owner; Out of scope leaves those keys unchanged
  Decision: resolved — GetRemoteIP owns the per-request client address; Checker owns pool membership. Log the Config slices already in `bouncer.New`. Do not re-derive hops or client IP.
  By: explore

- Q: Must `NewChecker` drop its `log` parameter once insert DEBUG is gone?
  Rank: bounded incidental — 26 `NewChecker(` call sites enumerated in `pkg/ip`, `pkg/bouncer`, `pkg/configuration`; requirement does not name a signature change
  Decision: assumed — keep the signature; stop the two Debug calls; name the param `_` only if unused-parameter fails. Do not migrate 26 call sites.
  By: explore
