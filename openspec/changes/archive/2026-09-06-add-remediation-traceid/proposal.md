## Why

On `master`, `{{ .TraceID }}` on ban HTML only appears if a third-party Traefik plugin injects a request header and `TraceHeadersCustomName` copies it. Captcha pages have no TraceID. Operators should get a CF-Ray–style ID on ban and captcha pages from this plugin alone ([upstream#358](https://github.com/maxlerebourg/crowdsec-bouncer-traefik-plugin/issues/358)).

## What Changes

- Add config knob `RemediationTraceIDCustomName` (empty = off), same ergonomics as `RemediationHeadersCustomName`.
- When set, generate a 16-hex ID per ban HTML and captcha HTML response, set that name as a **response** header, and expose the same value as `{{ .TraceID }}`.
- Keep `TraceHeadersCustomName` incoming passthrough for ban when the new knob is empty. When both are set, built-in generation wins.
- Do not inject on pass-through, solved-captcha 302, or AppSec challenge bodies.
- Unit tests and mock e2e on ban and captcha paths.

## Capabilities

### New Capabilities

- `core_plugin_middleware_remediation-traceid`: Built-in remediation TraceID generation, response header, and template field on ban and captcha HTML.

### Modified Capabilities

None.

## Impact

- `pkg/configuration` (new field, default empty, README)
- `pkg/bouncer` (generate ID, ban response header + template; pass ID into captcha)
- `pkg/captcha` (response header + `TraceID` on captcha HTML)
- `README.md` / examples if the new key is documented
- `pkg/bouncer` and `pkg/captcha` unit tests; mock e2e `custom-ban-page` and `captcha`
