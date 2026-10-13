## 1. Terminate challenge prefix

- [ ] 1.1 Add `appsecChallengePathPrefix` (`/crowdsec-internal/challenge/`) in `bouncer.go`
- [ ] 1.2 In `handleNextServeHTTP`, after a nil `appsecQuery` while `appsecEnabled`, `http.NotFound` when `req.URL.Path` has that prefix and do not call `next`

## 2. Tests

- [ ] 2.1 AppSec HTTP 200 on `/crowdsec-internal/challenge/custom.js` is 404 and `next` is not called
- [ ] 2.2 A normal path that AppSec allows still calls `next`

## 3. Docs

- [ ] 3.1 README: the plugin 404s `/crowdsec-internal/challenge/*` when AppSec does not serve it; covering the host with middleware is not enough without that 404

## 4. Verify

- [ ] 4.1 `go test -mod=vendor -count=1 .` on this machine
