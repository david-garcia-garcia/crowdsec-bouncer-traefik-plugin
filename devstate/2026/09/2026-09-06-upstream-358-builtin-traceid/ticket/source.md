# upstream#358 — [FEATURE] Implement built-in TraceID header generation

**Source:** https://github.com/maxlerebourg/crowdsec-bouncer-traefik-plugin/issues/358  
**State:** OPEN  
**Recommended action:** fix (implement on fork)

## Problem

Currently, to display the request ID (`.TraceID`) to the user on the ban page, one must add a third-party Traefik plugin and correctly specify the required header in the `TraceHeadersCustomName` parameter.

This creates inconveniences regarding both configuration and usage. The header is needed only on the bouncer plugin's specific pages—such as the ban or CAPTCHA pages. With a third-party plugin, however, the header must be generated and included on every page, which results in excessive log size and unnecessarily long identifiers.

## Desired solution

Implement built-in TraceID header generation and display it in the page template via `{{ .TraceID }}`.

The `RemediationHeadersCustomName` option is currently implemented in a very convenient way. The request ID should be passed in exactly the same way.

One should be able to specify `RemediationTraceIDCustomName: X-Trace-ID` and have that be the entire configuration.

The header would be injected by this plugin; the ID would resemble [CF-Ray](https://developers.cloudflare.com/fundamentals/reference/http-headers/#cf-ray), and the header itself would be transmitted only on ban and captcha pages, becoming available in the template via `{{ .TraceID }}`.

## Assessment (local)

- **Relevant:** yes — fork lacks built-in generation; only incoming-header passthrough exists.
- **Affected files:** `pkg/configuration/configuration.go`, `pkg/bouncer/bouncer.go`, `pkg/captcha/captcha.go`
- **Tests:** `tests/e2e/mock/scenarios/custom-ban-page/run.sh` proves external-header passthrough on ban when client sends `X-Trace`; no built-in generation or captcha TraceID coverage.
