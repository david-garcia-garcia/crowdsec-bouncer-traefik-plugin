# Issues

- [ ] take large  `openspec/specs/core_plugin_middleware_instance-reclaim` → `core_plugin_lapi_reclaim-key` + `core_plugin_middleware_bouncer` (fold concurrent AdoptTransport into `core_plugin_lapi_connection`; drop failure-action dups)
  Why: leaf `instance-reclaim` hides session prefix, settings hash, transport adopt, and Bouncer policy. Human approved. Explore split; propose writes those ids.
