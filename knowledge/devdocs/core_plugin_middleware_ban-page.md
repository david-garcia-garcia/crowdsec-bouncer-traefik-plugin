# Ban page

## Language

**Ban page**:
The operator remediation HTTP response `handleBanServeHTTP` writes: `remediationStatusCode`, `Content-Type` from the ban template, optional template body. Not AppSec envelope relay and not captcha `ServeHTTP`.
_Avoid_: AppSec `user_body_content`, captcha challenge HTML

## Overview

Ban kind (and captcha fallbacks that ban) share one writer. Pass `headerReason` at each call site. Set response headers before `WriteHeader`. Head and a nil template skip the body and still carry those headers.

## How to use

- Set `Cache-Control: no-cache, no-store` next to `Content-Type` and before `WriteHeader`.
- HEAD and nil-template bans inherit that Set the same way `Content-Type` already does.
- Do not add extra directives (`private`, `max-age`, `must-revalidate`, `Pragma`).
- Do not emit Cache-Control from AppSec relay; copy `user_headers` as they arrive (`core_plugin_appsec`).
- Pass an explicit `headerReason` into `handleBanServeHTTP` next to template `reason` and metrics `origin`. When `remediationCustomHeader` is set, write `formatRemediationHeader("ban", headerReason, origin)`. Closed reasons never take a third field; `lapi` plus a non-empty origin appends the encoded origin. Do not infer captcha-downgrade / `appsec` / `appsec-challenge-empty` from origin alone.
- Do not share a helper package with captcha `ServeHTTP`. Captcha does not import the closed table; the bouncer formats the challenge-page value.

## Pattern snippet

```go
if b.remediationCustomHeader != "" {
	if value := formatRemediationHeader(headerKindBan, headerReason, origin); value != "" {
		rw.Header().Set(b.remediationCustomHeader, value)
	}
}
rw.Header().Set("Content-Type", b.banTemplateContentType)
rw.Header().Set("Cache-Control", "no-cache, no-store")
rw.WriteHeader(b.remediationStatusCode)
```

## Key files

- `pkg/bouncer/bouncer.go` (`handleBanServeHTTP`)
- `pkg/bouncer/remediation_header.go`

## Gotchas

- All ban call sites inherit the one Set on `handleBanServeHTTP`. Each site passes its own `headerReason`.
- Challenge HTML Cache-Control lives on `core_plugin_middleware_captcha-widget`, not here.
