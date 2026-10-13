## Why

A CDN in front of Traefik stored this plugin's captcha HTML (HTTP 200 on the original URL, Content-Type only, no Set-Cookie). After the captcha decision was cleared, the CDN kept serving that stored page. The two writers this plugin owns — captcha challenge HTML and the operator ban page — do not set `Cache-Control`.

## What Changes

- Set `Cache-Control: no-cache, no-store` on the captcha challenge response written by `Client.ServeHTTP` (non-`Pass` 200 path), next to `Content-Type` and before `WriteHeader`.
- Set the same header on the ban page written by `handleBanServeHTTP`, next to `Content-Type` and before `WriteHeader` (HEAD and nil-template bans included).
- Match the header CrowdSec already uses on HAProxy SPOA captcha/ban returns and on the AppSec challenge protocol example (`no-cache, no-store`).
- Assert that header on the existing challenge 200 and ban header tests. Do not add a new test file.

## Capabilities

### New Capabilities

None.

### Modified Capabilities

- `core_plugin_middleware_captcha-widget`: challenge HTML at 200 SHALL set `Cache-Control: no-cache, no-store`. Pass 302 stays unchanged.
- `core_plugin_middleware_bouncer`: `handleBanServeHTTP` SHALL set `Cache-Control: no-cache, no-store` on the ban response.

## Impact

- `pkg/captcha/captcha.go` `Client.ServeHTTP` (challenge HTML path only).
- `pkg/bouncer/bouncer.go` `handleBanServeHTTP` (all call sites inherit one Set).
- Tests that already assert headers on those writers: `pkg/captcha/zzz_servehttp_test.go`, `pkg/bouncer/zzz_bouncer_test.go` (`TestHandleBanServeHTTP*` / `TestHandleBanServeHTTPContentType`).
- Live catalog folds only. Neighbors stay as-is: `core_plugin_middleware_captcha-routing`, `core_plugin_appsec_bot-detection`, Pass 302 / `WriteSolvedRedirect`.
- AppSec envelope relay already copies `user_headers`; leave it and its `no-store` mock fixtures unchanged.
- Usage packets stay for implement / `opd-devdocsimpact`.
