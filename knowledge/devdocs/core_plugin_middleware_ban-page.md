# Ban page

## Language

**Ban page**:
The operator remediation HTTP response `handleBanServeHTTP` writes: `remediationStatusCode`, `Content-Type` from the ban template, optional template body. Not AppSec envelope relay and not captcha `ServeHTTP`.
_Avoid_: AppSec `user_body_content`, captcha challenge HTML

## Overview

Ban kind (and captcha fallbacks that ban) share one writer. Set response headers before `WriteHeader`. Head and a nil template skip the body and still carry those headers.

## How to use

- Set `Cache-Control: no-cache, no-store` next to `Content-Type` and before `WriteHeader`.
- HEAD and nil-template bans inherit that Set the same way `Content-Type` already does.
- Do not add extra directives (`private`, `max-age`, `must-revalidate`, `Pragma`).
- Do not emit this header from AppSec relay; copy `user_headers` as they arrive (`core_plugin_appsec`).
- Do not share a helper package or Traefik Config field with captcha `ServeHTTP`; each writer Sets the same literal.

## Pattern snippet

```go
rw.Header().Set("Content-Type", b.banTemplateContentType)
rw.Header().Set("Cache-Control", "no-cache, no-store")
rw.WriteHeader(b.remediationStatusCode)
```

## Key files

- `pkg/bouncer/bouncer.go` (`handleBanServeHTTP`)

## Gotchas

- All ban call sites inherit the one Set on `handleBanServeHTTP`.
- Challenge HTML Cache-Control lives on `core_plugin_middleware_captcha-widget`, not here.
