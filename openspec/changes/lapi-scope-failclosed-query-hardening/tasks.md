## 1. Deliverable 1 — header-scope failures fail closed

- [ ] 1.1 `mergeLiveScope` returns `(string, time.Duration, error)`; return the caller's verdict unchanged plus the query error and log it at `Warn`
- [ ] 1.2 `handleNoStreamCache` keeps the first scope error, checks `IsActiveRemediation(chosen)` first, and returns `("", scopeErr)` with no negative cache write when the verdict is non-active
- [ ] 1.3 Document the overloaded return contract on `LiveLookup`
- [ ] 1.4 One test per matrix row: clean/all clean, clean/one errors, clean/one bans, active ban/one errors, IP errors, clean/two scopes one errors one bans
- [ ] 1.5 Extend the `CrowdsecLapiFailureAction` description in `README.md` and name `passthrough` as the way back to permissive

## 2. Deliverable 2 — release the stream lease on a failed poll

- [ ] 2.1 Extract the fetch+apply body of `handleStreamCache` into `fetchAndApplyStreamDecisions`
- [ ] 2.2 Delete `cacheTimeoutKey` on any error from that call; leave `Acquire`, the TTL floor, and the `!won` branch alone
- [ ] 2.3 Tests: failed GET frees the lease, the next tick re-polls, a successful poll keeps the lease; keep the three existing lease tests green

## 3. Deliverables 3-5 — `crowdsecQuery` hardening

- [ ] 3.1 `crowdsecQuery` delegates to `sendQuery(url, data, mayRenewToken)`; the replay passes `false` and `getToken` passes `false`
- [ ] 3.2 Replay the original method and body on the alone-mode 401
- [ ] 3.3 Add `drainResponse` to `pkg/lapi` and defer it right after the transport-error check; move the `isReverseProxyError` check below it
- [ ] 3.4 Split the two messages: `%w` for a transport error, `statusCode:%d` for a reverse-proxy status
- [ ] 3.5 Tests: POST replayed as POST, second 401 does not loop, 502/503/504 reuse one connection, `503` message contains the status and no `%!w(<nil>)`

## 4. Verify

- [ ] 4.1 `go build ./...`, `go vet ./...`, `go test ./pkg/... -count=1`, `go test . -count=1`, `golangci-lint run ./...`
- [ ] 4.2 Docker `go test -race -count=1 ./pkg/...` on `golang:1.22.12`
- [ ] 4.3 Merge `origin/master` into the branch and re-run every gate on the merged tree
