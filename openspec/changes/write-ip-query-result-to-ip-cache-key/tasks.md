## 1. Live IP-slot write

- [x] 1.1 In `handleNoStreamCache`, keep the `?ip=` result and its duration before the header loop mutates `chosen`
- [x] 1.2 After the loop, write that IP query result to the client-address key when live caching is on: active IP result always (existing `liveCacheTTL` on the IP duration); clean IP result only when there is no header-scope query error (`defaultDecisionSeconds`)
- [x] 1.3 Leave `cacheLiveScope` as the header-slot owner. Do not parse `RemoteAddr` or re-read headers in `pkg/lapi`

## 2. Regression

- [ ] 2.1 Add `TestLiveLookup_IPSlotKeepsIPQueryResult` next to `TestLiveLookup_ScopeBanWins`: after a clean IP plus Country ban `FR`, the IP key is `NoBannedValue`, the Country header key is the ban, and `LookupCachedRemediation` for the same IP plus Country `DE` does not inherit the `FR` ban
- [ ] 2.2 Keep `TestLiveLookup_ScopeBanWins` and `TestLiveLookup_ScopeErrorFailsClosed` green (first-call return and no negative IP-key write on scope error)

## 3. Verify

- [ ] 3.1 `go build ./...`, `go vet ./...`, `go test ./pkg/lapi/ ./pkg/decisionscope/ -count=1`, `golangci-lint run ./pkg/lapi/ ./pkg/decisionscope/`
