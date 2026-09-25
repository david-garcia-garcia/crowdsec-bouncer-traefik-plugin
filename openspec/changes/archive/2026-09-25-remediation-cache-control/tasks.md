## 1. Challenge HTML Cache-Control

- [x] 1.1 In `pkg/captcha/captcha.go` `Client.ServeHTTP`, on the non-`Pass` challenge path, `Header().Set("Cache-Control", "no-cache, no-store")` next to `Content-Type` and before `WriteHeader(200)`. Do not set this header on the Pass 302.
- [x] 1.2 In `pkg/captcha/zzz_servehttp_test.go`, assert `Cache-Control` is `no-cache, no-store` on the existing challenge 200 body case. Assert the Pass 302 still has empty `Cache-Control`. Do not add a new `zzz_` file.

## 2. Ban page Cache-Control

- [x] 2.1 In `pkg/bouncer/bouncer.go` `handleBanServeHTTP`, `Header().Set("Cache-Control", "no-cache, no-store")` next to `Content-Type` and before `WriteHeader`. HEAD and nil-template returns inherit that Set.
- [x] 2.2 In `pkg/bouncer/zzz_bouncer_test.go`, assert `Cache-Control` is `no-cache, no-store` on `TestHandleBanServeHTTPContentType` (including the nil-template case) and on the `TestHandleBanServeHTTPWithDifferentMethods` table (HEAD included). Do not add a new `zzz_` file.

## 3. Leave neighbors

- [x] 3.1 Do not change `handleAppsecResponseServeHTTP` or its `no-store` mock fixtures. Do not set `Cache-Control` on `WriteSolvedRedirect` or the Pass 302. Do not add a Config field or shared helper package. Do not write `knowledge/devdocs` this apply.
- [x] 3.2 Run `go test ./pkg/captcha/ ./pkg/bouncer/ -count=1` for the ServeHTTP and ban-header tests this change touches.
