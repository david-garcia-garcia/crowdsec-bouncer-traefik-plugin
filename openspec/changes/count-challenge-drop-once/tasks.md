## 1. Relay and skip

- [ ] 1.1 Parse AppSec JSON `action` in `appsecQuery` and return a structured challenge envelope with a nil error
- [ ] 1.2 Write that envelope to the client from `handleNextServeHTTP` without calling `next`
- [ ] 1.3 Increment `blockedRequests` on that write only when the path is not under `/crowdsec-internal/challenge/`

## 2. Regression

- [ ] 2.1 Test: challenge envelope on `/protected` increments dropped by 1
- [ ] 2.2 Test: the same envelope on `/crowdsec-internal/challenge/submit` does not increment
- [ ] 2.3 Run the package tests on this machine
