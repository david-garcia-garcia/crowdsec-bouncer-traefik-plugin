# Issues

- [x] take large  `openspec/specs/core_plugin_middleware_instance-reclaim` → `core_plugin_lapi_reclaim-key` + `core_plugin_middleware_bouncer` (fold concurrent AdoptTransport into `core_plugin_lapi_connection`; drop failure-action dups)
  Why: leaf `instance-reclaim` hides session prefix, settings hash, transport adopt, and Bouncer policy. Human approved. Explore split; propose writes those ids.
  Taken: live dump folder deleted; new leaves and connection fold landed; debt file `knowledge/debt/2026-09-17-rename-core-plugin-middleware-instance-reclaim.md` deleted.
