# Standards

1. [hard] std_go_test_log-sink — `pkg/bouncer/zzz_debug_attrs_test.go:293` — `TestHunt_ServeHTTPLiveLookupTraceIncludesScopes` builds a real `lapi.Client` then reads the sink while Close is only a Cleanup
   Fix: Close the client after ServeHTTP, then read `sink.String()`
   Status: done
   Argument: Close `lapiClient` after ServeHTTP then read the sink.
   Quote:
      ```
	t.Cleanup(client.Close)
	...
	for _, line := range jsonLinesWithMsg(sink.String(), "ServeHTTP:LiveLookup") {
      ```
