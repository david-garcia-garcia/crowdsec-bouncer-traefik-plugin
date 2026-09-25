## Why

DEBUG emits one line per trusted CIDR (`IP network is trusted`) and one per bare host (`IP is trusted`) while `Bouncer initialized` carries no network attributes. Operators need every trusted range on that single construct-time DEBUG line, and the slog `component` value `CrowdsecBouncerTraefikPlugin` is too long to scan.

## What Changes

- Stop insert DEBUG in `ip.NewChecker` (`IP is trusted` / `IP network is trusted`).
- Attach the two config slices as slog attributes on the existing `bouncer.New` DEBUG `Bouncer initialized`: `forwardedHeadersTrustedIPs` and `clientTrustedIPs`. Values are the config strings as written. Empty lists still log both attrs.
- Set `NewWithFormat` slog `component` to `CrowdsecBouncer` (existing type/template name). Not `CrowdsecBounder`. Not a third name.
- Keep `validateParamsIPs` constructing `NewChecker` to reject bad CIDRs. Keep the `NewChecker` signature; stop the two Debug calls.
- Do not re-derive client IP or hops. Log Config slices already in `bouncer.New`.
- **Not BREAKING.** Public config keys and `NewChecker` signature stay.

## Capabilities

### New Capabilities

None.

### Modified Capabilities

- `std_go_logger_slog-output`: every `NewWithFormat` logger SHALL carry `component=CrowdsecBouncer`.
- `std_go_logger_debug-attrs`: construct-time DEBUG `Bouncer initialized` SHALL list both trusted-IP config slices as attributes. Request-path TRACE stays out of scope.

## Impact

- `pkg/logger/logger.go` — `component` string.
- `pkg/ip/checker.go` — drop per-entry insert DEBUG.
- `pkg/bouncer/bouncer.go` — `Bouncer initialized` attrs from Config slices.
- `pkg/logger/zzz_logger_test.go`, `zzz_bouncer_logging_test.go` — locked `component` string; init-line attrs.
- `pkg/configuration/configuration.go` — no validate rewrite; silence comes from Checker.
- Usage `knowledge/devdocs/std_go_logger_debug-attrs.md` still omits trusted-network attrs; implement / `opd-devdocsimpact` updates that line.
- No public config keys. No HTML template rename. No User-Agent / usage-metrics identity.
