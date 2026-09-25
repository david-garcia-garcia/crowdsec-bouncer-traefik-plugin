## 1. slog component

- [ ] 1.1 In `pkg/logger/logger.go`, set `NewWithFormat` `component` to `CrowdsecBouncer`. Do not use `CrowdsecBounder`. Do not invent a third name. Do not rename the HTML template `CrowdsecBouncer`.
- [ ] 1.2 Update every product-test lock of `CrowdsecBouncerTraefikPlugin` to `CrowdsecBouncer`: `pkg/logger/zzz_logger_test.go` (JSON, common, `TestNewWithFormatJSONCaseInsensitive`) and `zzz_bouncer_logging_test.go` (`validateLogEntry`, common-format file lines).

## 2. Trusted IPs on Bouncer initialized

- [ ] 2.1 In `pkg/ip/checker.go`, remove the two insert Debug calls (`IP is trusted`, `IP network is trusted`). Keep the `NewChecker` signature. Name the unused `log` param `_` only if unused-parameter fails. Do not rewrite `validateParamsIPs` to stop constructing `NewChecker`.
- [ ] 2.2 In `pkg/bouncer/bouncer.go`, attach `forwardedHeadersTrustedIPs` and `clientTrustedIPs` on the existing DEBUG `Bouncer initialized`. Pass `config.BouncerForwardedHeadersTrustedIPs` and `config.BouncerClientTrustedIPs` as written. Do not rewrite bare hosts to `/32` or `/128`. Do not re-derive hops or client IP. Do not merge the two slices.

## 3. Tests

- [ ] 3.1 In `pkg/bouncer`, with `newTestLogSink` at DEBUG, construct `bouncer.New` with a forwarded-headers list that mixes CIDRs and a bare host and a distinct client list. Assert one `msg=Bouncer initialized` record whose `forwardedHeadersTrustedIPs` and `clientTrustedIPs` equal those slices as written. Assert no `IP is trusted` or `IP network is trusted` records.
- [ ] 3.2 Same sink: empty forwarded-headers and empty client lists. Assert `Bouncer initialized` still includes both attributes as empty lists.
- [ ] 3.3 In `pkg/ip`, construct `NewChecker` at DEBUG with CIDRs plus a bare host. Assert no `IP is trusted` or `IP network is trusted` records.

## 4. Leave neighbors

- [ ] 4.1 Do not change which CIDRs are trusted, the two public config keys, default `logLevel`, logger file/format, request-path TRACE, User-Agent / usage-metrics identity, or the HTML template name. Do not write `knowledge/devdocs` this apply (usage How-to still omits trusted-network attrs).
- [ ] 4.2 Run `go test ./pkg/logger/ ./pkg/ip/ ./pkg/bouncer/ . -count=1` for the component and init-log tests this change touches.
