# Requirement
IssueKey: 2026-09-06-upstream-358-builtin-traceid

## Problem

Showing a trace/request ID on ban and captcha remediation pages today requires a third-party Traefik plugin plus `TraceHeadersCustomName` to pass an incoming request header through. That forces ID generation on every route and complicates configuration for pages that only the bouncer serves.

## Current (code)

- `pkg/configuration/configuration.go:97` — `TraceHeadersCustomName` only; no `RemediationTraceIDCustomName` (or equivalent built-in knob).
- `pkg/configuration/configuration.go:196` — default `TraceHeadersCustomName` is empty (disabled).
- `pkg/bouncer/bouncer.go:71` — `traceCustomHeader` wired from `TraceHeadersCustomName`.
- `pkg/bouncer/bouncer.go:264-268` — ban template `TraceID` is set only when the configured incoming request header is present and non-empty; plugin does not generate an ID or set a response header.
- `pkg/captcha/captcha.go:110-114` — captcha template data has `SiteKey`, `FrontendJS`, `FrontendKey` only; no `TraceID`.
- `README.md:553-556` — documents `TraceHeadersCustomName` as incoming request header passthrough for ban HTML.
- `examples/custom-ban-page/README.md:57` — documents `{{ .TraceID }}` in ban template (depends on passthrough header today).
- `tests/e2e/mock/scenarios/custom-ban-page/run.sh:24` — asserts ban body contains trace value when client sends `X-Trace`; no built-in generation.
- `tests/e2e/mock/scenarios/custom-ban-page/run.sh` — no captcha TraceID scenario.

## Desired

- Add config knob `RemediationTraceIDCustomName` (mirroring `RemediationHeadersCustomName` ergonomics): when set, plugin generates a CF-Ray–style trace ID per remediation response.
- Set the configured header on the **response** for ban and captcha HTML pages only.
- Expose the same value in ban and captcha templates as `{{ .TraceID }}`.
- Tests covering built-in generation on ban and captcha paths (unit and/or e2e as appropriate).

## Affected

- `pkg/configuration/configuration.go` (new field, defaults, validation, README parity)
- `pkg/bouncer/bouncer.go` (ban response header + template data)
- `pkg/captcha/captcha.go` (captcha response header + template data)
- `README.md`, examples if config/docs updated
- `tests/e2e/mock/scenarios/` and/or package tests

## Out of scope

- Removing or repurposing `TraceHeadersCustomName` (incoming passthrough remains unless explore decides overlap).
- Injecting trace headers on pass-through/upstream responses outside ban/captcha remediation pages.
- Replacing third-party Traefik trace plugins for non-remediation routes.
- Upstream PR submission (fork fix only per assessment).

## Unknowns

- Exact CF-Ray–style ID format (length, charset, entropy source) not specified in ticket.
- Precedence when both `TraceHeadersCustomName` (incoming) and `RemediationTraceIDCustomName` (built-in) are configured.
- Whether captcha redirect/solved path should also carry the trace header (ticket names ban and captcha pages).

## Tensions

- Ticket proposes `RemediationTraceIDCustomName` while existing `TraceHeadersCustomName` already feeds `{{ .TraceID }}` on ban from incoming headers — explore must define coexistence or migration.
- Ticket asks for response-header injection like `RemediationHeadersCustomName`; built-in ID is generated server-side, not read from the client request.
