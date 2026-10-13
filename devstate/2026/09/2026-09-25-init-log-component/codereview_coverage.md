# Test coverage

1. [hard] Tombstone absence — `pkg/ip/zzz_checker_test.go:509` — `TestNewCheckerDoesNotLogInsert` asserts deleted `IP is trusted` / `IP network is trusted` DEBUG never appears
   Quote:
      ```
      log.Debug("IP is trusted", "ip", ipAddr)
      log.Debug("IP network is trusted", "network", ipMask)
      Test: TestNewCheckerDoesNotLogInsert strings.Contains `"msg":"IP is trusted"` / `"msg":"IP network is trusted"`
      ```
   Fix: Delete `TestNewCheckerDoesNotLogInsert` and the `bytes`/`strings` imports it added; the NewChecker deletion hunk is the trail
   Status: done
   Argument: Deleted `TestNewCheckerDoesNotLogInsert` and the `bytes`/`strings` imports it added in `pkg/ip/zzz_checker_test.go`.
2. [hard] Tombstone absence — `pkg/bouncer/zzz_bouncer_initialized_test.go:100` — `assertNoInsertTrustedLogs` asserts the same deleted insert DEBUG is absent on `bouncer.New`
   Quote:
      ```
      log.Debug("IP is trusted", "ip", ipAddr)
      log.Debug("IP network is trusted", "network", ipMask)
      Test: assertNoInsertTrustedLogs in TestNew_BouncerInitializedTrustedIPs and TestNew_BouncerInitializedEmptyTrustedIPs
      ```
   Fix: Delete `assertNoInsertTrustedLogs` and its calls; keep the `Bouncer initialized` attr assertions
   Status: done
   Argument: Deleted `assertNoInsertTrustedLogs` and its calls; kept `Bouncer initialized` attr assertions.
