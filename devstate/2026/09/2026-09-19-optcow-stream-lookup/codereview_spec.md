# Spec

1. [wrong] `openspec/changes/2026-09-19-optcow-stream-lookup/specs/core_plugin_lapi_usage-metrics/spec.md` Requirement: Active-decision slots store intern id and family — `pkg/lapi/client_metrics.go:184` — overflow still copies the origin string into `activeDecisionSlot.leftover`; spec says intern id 0 and empty `OriginName`, not a second copy of the origin string
   → Drop `leftover`; on `OriginID` overflow leave `originID` 0 so `slotMetricKey` posts an empty origin
   Status: done
   Argument: f92c8573 dropped leftover; overflow leaves originID 0 so slotMetricKey posts empty origin. TestReportMetricsOfficialLabels attaches intern store.
