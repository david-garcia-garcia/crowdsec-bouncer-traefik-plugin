# Specs
IssueKey: 2026-09-20-elapsedsec-liveslot

change: compact-liveslot-elapsedsec

FindSpecHost (before `specs/core_plugin_decisionstore_store/`):

| deltaId | verdict | spec-id | confidence | candidates |
| --- | --- | --- | --- | --- |
| memory LiveSlot elapsed expiry + PublishTick clock | fold | core_plugin_decisionstore_store | high | core_plugin_decisionstore_store, core_plugin_lapi_stream-apply |

- modified `core_plugin_decisionstore_store` (fold) — memory slot int32 elapsed encoding, elapsed PublishTick `now`, origin at package init.
