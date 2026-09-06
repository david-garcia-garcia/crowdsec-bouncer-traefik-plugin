# Spec FindSpecHost verdicts
IssueKey: 2026-09-06-lapi-client-correctness
Change: lapi-client-correctness

```
verdicts:
  - deltaId: core_plugin_lapi_stream-poll
    verdict: new
    spec-id: core_plugin_lapi_stream-poll
    confidence: high
    candidates:
      - core_plugin_lapi_connection (file layout only; no poll behavior)
      - core_plugin_lapi_failure-action (UpdateMaxFailure semantics; not poll serialization)
      - core_plugin_lapi_stream-poll (new leaf)
  - deltaId: core_plugin_lapi_http-query
    verdict: new
    spec-id: core_plugin_lapi_http-query
    confidence: high
    candidates:
      - core_plugin_lapi_connection (names client_http.go; no HTTP error contract)
      - core_plugin_lapi_http-query (new leaf)
  - deltaId: core_plugin_lapi_failure-action
    verdict: fold
    spec-id: core_plugin_lapi_failure-action
    confidence: high
    candidates:
      - core_plugin_lapi_failure-action (extends Live LAPI error requirement)
      - core_plugin_lapi_connection (no failure-action semantics)
```

## Summary

| Spec id | Verdict | Delta path |
| --- | --- | --- |
| `core_plugin_lapi_stream-poll` | new | `openspec/changes/lapi-client-correctness/specs/core_plugin_lapi_stream-poll/spec.md` |
| `core_plugin_lapi_http-query` | new | `openspec/changes/lapi-client-correctness/specs/core_plugin_lapi_http-query/spec.md` |
| `core_plugin_lapi_failure-action` | fold | `openspec/changes/lapi-client-correctness/specs/core_plugin_lapi_failure-action/spec.md` |
