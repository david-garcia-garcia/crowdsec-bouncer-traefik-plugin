# Test coverage

1. [hard] Edge case untested — `pkg/appsec/client_http.go:86` — `AdoptTransport` idle-closes the previous `*http.Client` after Swap; no test fails if that `closeIdle` branch is reverted
   → Assert a timeout- or TLS-only `Open` reuse calls `CloseIdleConnections` on the replaced client
   Status: done
   Argument: TestOpen_TimeoutOnlyClosesPreviousIdle spies CloseIdleConnections on the replaced client; closeIdle accepts idleCloser so *http.Transport and the spy both work (`dd9e678`).
