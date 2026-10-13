# Requirement
IssueKey: 2026-09-25-init-log-component

## Problem
DEBUG emits one line per trusted CIDR (`msg="IP network is trusted"` plus `network=`). Operators need every trusted range on a single DEBUG line. The slog `component` value `CrowdsecBouncerTraefikPlugin` is too long.

## Current (code)
- `NewChecker` logs DEBUG `IP is trusted` (`ip`) for each bare address and DEBUG `IP network is trusted` (`network`) for each CIDR as it inserts: `pkg/ip/checker.go`
- `validateParamsIPs` constructs that Checker (and discards it) for `BouncerForwardedHeadersTrustedIPs` and `BouncerClientTrustedIPs`, so those per-entry lines also fire during plugin `New` validate: `pkg/configuration/configuration.go`, `plugin.go`
- `bouncer.New` builds two Checkers (forwarded-headers pool, client pool) then DEBUG `Bouncer initialized` with no network attributes: `pkg/bouncer/bouncer.go`
- `NewWithFormat` sets `component`=`CrowdsecBouncerTraefikPlugin` on every logger: `pkg/logger/logger.go`
- Tests lock that string: `pkg/logger/zzz_logger_test.go`, `zzz_bouncer_logging_test.go`
- Spec requires a `component` attribute, not this long value: `openspec/specs/std_go_logger_slog-output/spec.md`
- Usage names construct-time DEBUG `Bouncer initialized` and does not list trusted-network attributes: `knowledge/devdocs/std_go_logger_debug-attrs.md`

## Desired
- All trusted IP ranges appear on one DEBUG line, not one line per CIDR.
- Prefer attaching those ranges to DEBUG `Bouncer initialized` so init shows how the bouncer is configured (trusted networks).
- Rename slog `component` from `CrowdsecBouncerTraefikPlugin` to a shorter name (ticket example: CrowdsecBounder).

## Affected
- `pkg/ip/checker.go` — per-CIDR DEBUG
- `pkg/bouncer/bouncer.go` — `Bouncer initialized`
- `pkg/logger/logger.go` — `component` attribute
- `pkg/configuration/configuration.go` — `validateParamsIPs` via `NewChecker`
- `pkg/logger/zzz_logger_test.go`, `zzz_bouncer_logging_test.go` — locked `component` string
- `openspec/specs/std_go_logger_slog-output/spec.md` — `component` presence

## Out of scope
- Changing which CIDRs are trusted or the two config keys.
- Changing default log level, format, or destination.
- Request-path TRACE ServeHTTP (`std_go_logger_debug-attrs`).
- Logging other init config besides trusted networks.
- Renaming the HTML template name `CrowdsecBouncer` in `pkg/bouncer/bouncer.go`.
- User-Agent / usage-metrics bouncer identity (`traefik_plugin`).

## Unknowns
- Attribute names, and whether forwarded-headers vs client pools are two attrs on the same `Bouncer initialized` line or one combined list.
- Whether `validateParamsIPs` must stop constructing `NewChecker` (it currently emits the same per-CIDR DEBUG before `bouncer.New`).
- Exact shorter `component` string (ticket says "like CrowdsecBounder").
- Whether bare-host `IP is trusted` lines must fold the same way (sample only showed CIDR `IP network is trusted`).
- Whether empty trusted lists still emit `Bouncer initialized` with empty network attrs.

## Tensions
- Ticket example shorter name is `CrowdsecBounder` (Bounder). Dest already has template name `CrowdsecBouncer` in `pkg/bouncer/bouncer.go`. The ask is a shorter slog `component`, not that template id.
- Ticket sample is one list of five CIDRs. Dest has two pools (`BouncerForwardedHeadersTrustedIPs` and `BouncerClientTrustedIPs`); validate plus `bouncer.New` each construct Checkers, so the same CIDR can log twice today.
- Ticket: ideally part of `Bouncer initialized`. Dest already emits that line with no network attrs; per-CIDR lines live in `NewChecker`, not on that call.
