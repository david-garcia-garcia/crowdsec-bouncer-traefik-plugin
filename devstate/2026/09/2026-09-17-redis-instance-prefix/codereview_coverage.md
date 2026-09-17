# Test coverage

1. [hard] Edge case untested — `pkg/lapi/instance.go:26` — hostname failure sets `unknown-instance` and logs Warn; no test failed on revert
   → Add test with injectable hostname and slog capture
   Status: done
   Argument: TestResolveCacheInstanceIdentity_HostnameFailure + readProcessHostname seam.
