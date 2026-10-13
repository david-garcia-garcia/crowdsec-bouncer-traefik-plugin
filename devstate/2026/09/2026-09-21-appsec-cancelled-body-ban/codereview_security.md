# Security

none

Reviewed pinned diff (OpenSpec/knowledge docs, `pkg/appsec/query.go`, `pkg/appsec/zzz_query_test.go`). No new secrets, egress, injection sinks, sensitive headers, or client-facing error leaks. Client-gone body read errors route through existing `resultForFailureActionErr` / `FailureAction` (spec scenarios for passthrough and ban); unclassified `io.ReadAll` failures still return `appsecQuery:GetBody` and follow today’s ban wiring in `applyAppsecServeHTTP`. Passthrough allow on disconnect is operator-configured and spec-backed, not an undocumented allow-on-error path.
