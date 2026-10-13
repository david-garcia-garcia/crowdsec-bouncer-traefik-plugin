# Standards

1. [hard] Bound the ask — `pkg/lapi/zzz_ipcachekey_test.go:177` — `closedTestReaderAddr` is a dest dead-reader flake fix this pin did not need
   Fix: Drop the helper and restore `127.0.0.1:1` in `splitStoreOnDeadReader`
   Status: skipped
   Argument: applying Fix fails TestApplyRangeBatch_UnreachableReadKeepsSharedIndex (127.0.0.1:1 returns redis:unsupported-reply, not ErrUnreachable).
   Quote:
      ```
      // closedTestReaderAddr is a local TCP address with no listener. Dest used 127.0.0.1:1, which
      // can be LISTEN on a workstation and then GET returns redis:unsupported-reply, not unreachable.
      func closedTestReaderAddr(t *testing.T) string {
      ```
