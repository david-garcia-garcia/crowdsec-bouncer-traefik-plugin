## REMOVED Requirements

### Requirement: Yaegi constructors stay on the module-root package
**Reason**: Remaining middleware unit after the split is `New` / Bouncer, not `instance-reclaim`.
**Migration**: `core_plugin_middleware_bouncer`.

### Requirement: Stream session is LAPI URL plus bouncer key
**Reason**: Session prefix and first-wins settings hash are the LAPI Open-key job, not the Bouncer.
**Migration**: `core_plugin_lapi_reclaim-key`.

### Requirement: Snapshot change while sleeping opens a new reclaim key
**Reason**: Sleep-snapshot new key is part of the Open-key job.
**Migration**: `core_plugin_lapi_reclaim-key`.

### Requirement: Unreclaimed connection is closed after grace
**Reason**: LAPI `ProcessGrace` 30s belongs with the Open-key leaf. AppSec same-table stays on the existing AppSec leaf.
**Migration**: `core_plugin_lapi_reclaim-key` for `lapi.Client`. Do not copy a SHALL into `core_plugin_appsec_*`.

### Requirement: Bouncer does not own the stream
**Reason**: Per-router Bouncer / `New` is the remaining middleware unit. Failure-action-per-router scenarios already live on `core_plugin_lapi_failure-action`.
**Migration**: `core_plugin_middleware_bouncer`. Drop duplicate failure-action scenarios; do not rewrite that owner.

### Requirement: Last New wins LAPI transport
**Reason**: Replaceable LAPI HTTP+auth is already owned by `core_plugin_lapi_connection`. The dump-only concurrent last-write scenario folds there.
**Migration**: `core_plugin_lapi_connection`.
