# Split MetricsReporter off Client

IssueKey: 2026-09-17-lapi-transport-router-policy
Size: large
Action: note

## Why this follow-up
Usage-metrics counters and the POST ticker still live on `lapi.Client`. A MetricsReporter type would own that window without riding the HTTP transport.

## Why it was not taken
Out of scope. Ticket forbids a MetricsReporter split in this apply.

## Risks
Metrics keep using the replaceable transport; a reporter split later must not re-introduce a write-once HTTP client field.
