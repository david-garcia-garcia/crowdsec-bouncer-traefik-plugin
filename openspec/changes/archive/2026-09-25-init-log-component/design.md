## Context

See `proposal.md` Why. Dest `NewWithFormat` sets `component=CrowdsecBouncerTraefikPlugin` (`pkg/logger/logger.go:97`). `ip.NewChecker` DEBUG-logs each insert (`IP is trusted` / `IP network is trusted`). `validateParamsIPs` constructs that Checker and discards it for both pools, so those lines also fire during plugin `New` validate. `bouncer.New` then builds the two Checkers again and DEBUG `Bouncer initialized` with no network attributes (`pkg/bouncer/bouncer.go:148`). Explore Decisions are accepted. Identity: GetRemoteIP owns the per-request client address; Checker owns pool membership. This change logs Config slices already in `bouncer.New`.

FindSpecHost:

```
verdicts:
  - { deltaId: component-value, fold: fold, spec-id: std_go_logger_slog-output, confidence: high, candidates: [std_go_logger_slog-output, std_go_logger_debug-attrs, core_plugin_middleware_bouncer] }
  - { deltaId: bouncer-initialized-trusted-attrs, fold: fold, spec-id: std_go_logger_debug-attrs, confidence: medium, candidates: [std_go_logger_debug-attrs, std_go_logger_slog-output, core_plugin_ip_radix-lookup, core_plugin_middleware_bouncer] }
  - { deltaId: drop-newchecker-insert-debug, skip: skip, spec-id: none, confidence: high, candidates: [core_plugin_ip_radix-lookup, std_go_logger_debug-attrs] }
```

Search: `std_go_logger_slog-output` already requires a `component` attribute on JSON `NewWithFormat`; locking the value is a small adjustment (one requirement, both formats). `std_go_logger_debug-attrs` already requires construct-time DEBUG to remain; adding what `Bouncer initialized` contains is a small ADDED section (one–three requirements). Leaf name still says Debug while the unit is Request-path Trace; fold stays; rename is already `note large` on `knowledge/debt/2026-09-24-rename-std-go-logger-debug-attrs.md`. `core_plugin_ip_radix-lookup` owns membership / GetRemoteIP and has no insert-log SHALL — dropping per-entry Checker DEBUG is absence of unspecified logging (`skip`). `core_plugin_middleware_bouncer` is Yaegi New / reclaim / config snapshot.

## Goals / Non-Goals

**Goals:**

- One DEBUG `Bouncer initialized` line carries both trusted-IP config slices as attributes.
- `component` is `CrowdsecBouncer` on every `NewWithFormat` logger.
- Per-entry Checker insert DEBUG is gone, including during validate.
- Tests lock the new component string and the init-line attrs (including empty lists).

**Non-Goals:**

- Changing which CIDRs are trusted or the two config keys.
- Changing default `logLevel`, format, or destination.
- Request-path TRACE ServeHTTP.
- Logging other init config besides trusted networks.
- Renaming the HTML template `CrowdsecBouncer`.
- User-Agent / usage-metrics bouncer identity (`traefik_plugin`).
- Changing the `NewChecker` signature or stopping `validateParamsIPs` from constructing it.
- Writing `knowledge/devdocs` this phase (usage How-to still omits trusted-network attrs; implement / `opd-devdocsimpact` updates that line).

## Decisions

| Topic | Choice | Rationale |
|-------|--------|-----------|
| Seam | Stop insert DEBUG in `NewChecker`; attach both Config slices on `bouncer.New` DEBUG `Bouncer initialized`; set `NewWithFormat` `component` to `CrowdsecBouncer` | Explore chosen seam. One line at init, not per CIDR, not a third Checker summary. |
| Component string | `CrowdsecBouncer` | Existing type and template name. Ticket typed `CrowdsecBounder` as an example. Do not invent a third name. Deviation already taken. |
| Attr names | `forwardedHeadersTrustedIPs` and `clientTrustedIPs` on that same line | Two pools. One combined list would hide which pool. |
| Attr values | Config slice strings as written | Bare hosts stay bare. Do not rewrite to `/32`/`/128`. Do not re-derive from Checker. |
| Empty lists | Still emit `Bouncer initialized` with both attrs as empty lists | Init shows how the bouncer is configured. |
| Validate | Keep constructing `NewChecker` | Validation is its job. Silence comes from dropping Checker insert DEBUG. |
| `NewChecker` signature | Keep; stop the two Debug calls; name the param `_` only if unused-parameter fails | 26 call sites. Requirement does not name a signature change. |
| Identity | Log Config slices already in `bouncer.New` | GetRemoteIP owns per-request client address. Checker owns membership. Do not reconstruct hops. |
| Catalog | Fold `std_go_logger_slog-output` and `std_go_logger_debug-attrs`. Skip NewChecker insert-log absence | Small adjustments. No live spec requires per-entry insert DEBUG. |

**Alternatives rejected:** keep per-entry Checker logs and add a summary; log once from `NewChecker` (validate plus two pools → up to three lines); combine both pools into one list; use `CrowdsecBounder`; stop `validateParamsIPs` from constructing `NewChecker`; rename the HTML template; a new spec family; ADDED "insert DEBUG is absent".

## Risks / Trade-offs

- **Operators grepping `IP network is trusted`** → Accepted. Ticket asked for one `Bouncer initialized` line. Rollback is revert of the PR.
- **slog slice rendering of empty/`nil` `[]string`** → Tests assert both attrs are present. Pass the slice as written; do not stringify by hand.
- **`debug-attrs` leaf still names Debug** → Fold stays. Rename already noted. This run adds construct-time init attrs onto that same leaf.
- **`component` filters in operator dashboards** → Documented on the card. Value moves from `CrowdsecBouncerTraefikPlugin` to `CrowdsecBouncer`.

## Migration Plan

- Deploy. No config rewrite. Operators filter `component=CrowdsecBouncer` and read trusted ranges on `Bouncer initialized`. Rollback is revert of the PR.

## Open Questions

None. Explore rows stay as explore wrote them.
