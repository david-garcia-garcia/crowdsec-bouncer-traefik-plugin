# 2026-09-05-config-prepare-snapshot

Fact ownership: Config is mutated during New before IdentityHex. Desired: identity and CrowdsecConnection.New see one prepared snapshot; Traefik’s original Config pointer is not a process-wide scratchpad. Behavior of CAPI alone-mode rewrite and secret file loading stays the same; only mutation locality changes. Tests that inspect config after New should use the snapshot/prepared value.

Bound the ask: `crowdsecconnection.Prepare` and `plugin.go` mutate `configuration.Config` in place (CAPI host/path/scheme, LAPI/AppSec/Redis keys, deprecated BanHTMLFilePath/CaptchaHTMLFilePath aliases, LogLevel ToUpper). Identity hashes whatever is left. The DTO is a scratchpad, not a snapshot.

Desired: prepare produces an immutable (or copy-on-write) snapshot used for Key/New/Bouncer; do not leave Traefik’s live Config as a mutated shared document, OR copy before mutate so identity and construction share one prepared value without surprising the caller. Deprecated path aliases and log-level normalize still happen, but on the snapshot. Explore must Decision: copy-then-mutate vs new Prepared type — assumed is copy-then-mutate unless a Prepared type is clearly smaller.

Do not file-split configuration.go except as required by a new type in that package. Do not move TLS builder (sibling). Do not change DecisionScopeHeaders identity (sibling).

Sibling tickets not in this change: 2026-09-05-split-connection-files, 2026-09-05-split-configuration-files, 2026-09-05-split-ip-trust, 2026-09-05-scope-headers-identity, 2026-09-05-remediation-codes-owner, 2026-09-05-decisionscope-mode-bool.
