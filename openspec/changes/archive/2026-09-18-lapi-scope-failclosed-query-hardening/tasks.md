## 1. Deliverable 1 — header-scope failures fail closed

- [x] 1.1 `mergeLiveScope` returns `(string, time.Duration, error)`; return the caller's verdict unchanged plus the query error and log it at `Warn`
- [x] 1.2 `handleNoStreamCache` keeps the first scope error, checks `IsActiveRemediation(chosen)` first, and returns `("", scopeErr)` with no negative cache write when the verdict is non-active
- [x] 1.3 Document the overloaded return contract on `LiveLookup`
- [x] 1.4 One test per matrix row: clean/all clean, clean/one errors, clean/one bans, active ban/one errors, IP errors, clean/two scopes one errors one bans
- [x] 1.5 Extend the `CrowdsecLapiFailureAction` description in `README.md` and name `passthrough` as the way back to permissive

## 2. Deliverable 2 — release the stream lease on a failed poll

- [x] 2.1 Extract the fetch+apply body of `handleStreamCache` into `fetchAndApplyStreamDecisions`
- [x] 2.2 Delete `cacheTimeoutKey` on any error from that call; leave `Acquire`, the TTL floor, and the `!won` branch alone
- [x] 2.3 Tests: failed GET frees the lease, the next tick re-polls, a successful poll keeps the lease; keep the three existing lease tests green

## 3. Deliverables 3-5 — `crowdsecQuery` hardening

- [x] 3.1 `crowdsecQuery` delegates to `sendQuery(url, data, mayRenewToken)`; the replay passes `false` and `getToken` passes `false`
- [x] 3.2 Replay the original method and body on the alone-mode 401
- [x] 3.3 Add `drainResponse` to `pkg/lapi` and defer it right after the transport-error check; move the `isReverseProxyError` check below it
- [x] 3.4 Split the two messages: `%w` for a transport error, `statusCode:%d` for a reverse-proxy status
- [x] 3.5 Tests: POST replayed as POST, second 401 does not loop, 502/503/504 reuse one connection, `503` message contains the status and no `%!w(<nil>)`

## 4. Verify

- [x] 4.1 `go build ./...`, `go vet ./...`, `go test ./pkg/... -count=1`, `go test . -count=1`, `golangci-lint run ./...`
- [x] 4.2 Docker `go test -race -count=1 ./pkg/...` on `golang:1.22.12`
- [x] 4.3 Merge `origin/master` into the branch and re-run every gate on the merged tree
