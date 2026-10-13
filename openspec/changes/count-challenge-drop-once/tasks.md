## 1. Relay and skip

- [x] 1.1 Parse AppSec JSON `action` in `appsecQuery` and return a structured challenge envelope with a nil error
- [x] 1.2 Write that envelope to the client from `handleNextServeHTTP` without calling `next`
- [x] 1.3 Increment `blockedRequests` on that write only when the path is not under `/crowdsec-internal/challenge/`

## 2. Regression

- [x] 2.1 Test: challenge envelope on `/protected` increments dropped by 1
- [x] 2.2 Test: the same envelope on `/crowdsec-internal/challenge/submit` does not increment
- [x] 2.3 Run the package tests on this machine
