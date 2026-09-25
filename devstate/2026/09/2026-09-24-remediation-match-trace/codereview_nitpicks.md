# Nitpicks

1. [hard] Symmetry and consistency — `pkg/bouncer/zzz_debug_attrs_test.go:293` — LiveLookup remediating TRACE pick uses `var record` / break / empty check; stream tests in this file ask `remediatingServeHTTPTrace` (fatal inside the helper)
   Quote:
      ```
      func remediatingServeHTTPTrace(t *testing.T, logged string) string {
      	t.Helper()
      	for _, line := range jsonLinesWithMsg(logged, "ServeHTTP") {
      		if strings.Contains(line, `"remediation":`) {
      			return line
      		}
      	}
      	t.Fatalf("want remediating ServeHTTP TRACE, got %s", logged)
      	return ""
      }

      var record string
      for _, line := range jsonLinesWithMsg(sink.String(), "ServeHTTP:LiveLookup") {
      	if strings.Contains(line, `"isBanned"`) {
      		record = line
      		break
      	}
      }
      if record == "" {
      	t.Fatalf("want ServeHTTP:LiveLookup TRACE, got %s", sink.String())
      }
      ```
   Fix: Match the stream tests — a helper that fatals and returns the LiveLookup remediating line (same pick-and-fatal shape as `remediatingServeHTTPTrace`)
   Status: done
   Argument: Added `remediatingLiveLookupTrace`; LiveLookup test uses it.
2. [hard] Name for the scope — `pkg/bouncer/zzz_debug_attrs_test.go:247` — `client` is the LAPI client this body binds (`lapi.New` / `lapiBound.Store`); the name drops LAPI and sits next to httptest `srv`
   Quote:
      ```
      client, err := lapi.New(&configuration.Config{
      	LapiHTTPTimeoutSeconds:           10,
      	LapiHost:                         parsed.Host,
      	LapiKey:                          "test-key",
      	LapiMetricsUpdateIntervalSeconds: 0,
      	LapiMode:                         configuration.LiveMode,
      	LapiPath:                         "/",
      	LapiScheme:                       parsed.Scheme,
      	LapiTLSInsecureVerify:            true,
      }, log, "test", store, "live-trace", "live-trace")
      if err != nil {
      	t.Fatal(err)
      }
      t.Cleanup(client.Close)
      ...
      b.lapiBound.Store(client)
      ```
   Fix: Rename to `lapiClient` — the role this body uses (same identifier as `testStreamBanBouncer`)
   Status: done
   Argument: Renamed `client` to `lapiClient` in the LiveLookup test.
