# Standards

1. [hard] Symmetry and consistency — `plugin_test.go:139` — sibling User-Agent assertions in `pkg/lapi/metrics_test.go:138` and `pkg/appsec/query_test.go:196` name the expected header `wantUA`; this test names the same role `want` beside `gotUA`
   → Rename `want` to `wantUA`
   Status: done
   Argument: Renamed `want` to `wantUA` in TestNew_LAPIUserAgentUsesVersionGo.

2. [judgement] Duplicated Code — `pkg/lapi/metrics_test.go:95-141` — `TestReportMetricsPluginVersion` near-copies `newUsageMetricsClient` (`httptest` handler, `Client` literal, cleanup) and differs only by User-Agent capture and `pluginVersion: wantVersion`
   → Extend `newUsageMetricsClient` to accept the plugin version and capture User-Agent instead of inlining the fixture
   Status: skipped
   Argument: Judgement — Bound the ask; the shared helper stays for tests that do not capture User-Agent.
