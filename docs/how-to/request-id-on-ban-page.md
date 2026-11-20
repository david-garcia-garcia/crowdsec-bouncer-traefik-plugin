[Documentation](../README.md) › [How-to](README.md) › Put a request id on the ban page

# Put a request id on the ban page

`bouncerTraceHeadersCustomName` copies one request header into the ban page as `{{ .TraceID }}`, so visitors can quote it to support.

```yaml
bouncerTraceHeadersCustomName: X-Request-ID
bouncerBanFilePath: /ban.html
```

Only values made of letters, digits, `_`, `.`, `:`, and `-` (up to 200 characters) are inserted; anything else is left out, so the header cannot inject markup.

The ban template can also use:

- `{{ .ClientIP }}` — the visitor's IP
- `{{ .Domain }}` — the requested host
- `{{ .RemediationReason }}` — `LAPI`, `APPSEC`, or `TECHNICAL_ISSUE`

A sample page is in [examples/custom-ban-page](../../examples/custom-ban-page/README.md). Without `bouncerBanFilePath`, a ban is just the status code with an empty body.
