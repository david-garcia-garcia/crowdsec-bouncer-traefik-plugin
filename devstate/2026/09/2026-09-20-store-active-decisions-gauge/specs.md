# Specs
change: store-owned-active-decisions-gauge
- modified core_plugin_lapi_usage-metrics
- modified core_plugin_decisionstore_store

FindSpecHost (conductor main thread; propose did not invent a third leaf):

```
verdicts:
  - { deltaId: usage-metrics-snapshot, fold, spec-id: core_plugin_lapi_usage-metrics, confidence: high, candidates: [core_plugin_lapi_usage-metrics, core_plugin_lapi_stream-apply] }
  - { deltaId: store-groupby, fold, spec-id: core_plugin_decisionstore_store, confidence: high, candidates: [core_plugin_decisionstore_store] }
```

Stream-apply remember/forget removal is implementation of usage-metrics. Dest `core_plugin_lapi_stream-apply` does not require remember. No stream-apply spec folder. No silent-rename of `core_plugin_decisionstore.md`.
