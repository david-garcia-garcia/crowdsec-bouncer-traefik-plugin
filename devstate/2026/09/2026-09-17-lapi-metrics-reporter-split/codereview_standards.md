# Standards

1. [hard] Symmetry and consistency — `pkg/lapi/zzz_metrics_test.go:192` — `started` and `newMetricsReporter`'s `startedAt` name the same envelope stamp
   → Rename the helper parameter to `startedAt`
   Status: done
   Argument: renamed attachTestMetricsReporter parameter to startedAt to match newMetricsReporter.
2. [judgement] Mysterious Name — `pkg/lapi/zzz_metrics_test.go:391` — `adopted` hides that this is the next LAPI `*configuration.Config`
   → Rename to `nextConfig`
   Status: skipped
   Argument: judgement; call-site name is local to the test and not a hard finding.
