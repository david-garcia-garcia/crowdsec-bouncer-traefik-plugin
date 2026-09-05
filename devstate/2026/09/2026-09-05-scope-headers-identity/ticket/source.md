# Isolation hole: decisionScopeHeaders omitted from reclaim identity

Isolation hole: DecisionScopeHeaders stored on Bouncer and CrowdsecConnection, omitted from identity. Desired: one owner; two middlewares with the same LAPI but different decisionScopeHeaders must not share stream ingest/cache. Tests: two New() with same LAPI host and different maps must not SameConnection.

Fact-ownership: `decisionScopeHeaders` is copied onto both `Bouncer` and `CrowdsecConnection` and is **not** in the reclaim identity (`pkg/crowdsecconnection/identity.go`). Two routers with the same LAPI and different maps share one stream/cache; the first `New` wins.

Fix ownership. Preferred shape (explore may refine with a Decision): put the normalized map on the reclaim identity so different maps are different CrowdsecConnections; Bouncer should not keep a second copy — use the connection’s map (or pass request headers through without storing a duplicate). Model: AppSec drop flags are per-route on Bouncer; AppSec client/host stay on the connection. Header-mapped scopes affect stream `scopes=` and ingest, so they belong on the connection identity, unlike AppSec FailureBlock.

Do not file-split connection.go. Do not move cache remediation constants. Do not change Prepare/CAPI mutation except as needed for identity hashing of the new field.

Sibling tickets that must not be taken: 2026-09-05-split-connection-files, 2026-09-05-split-configuration-files, 2026-09-05-split-ip-trust, 2026-09-05-remediation-codes-owner, 2026-09-05-decisionscope-mode-bool, 2026-09-05-config-prepare-snapshot.
