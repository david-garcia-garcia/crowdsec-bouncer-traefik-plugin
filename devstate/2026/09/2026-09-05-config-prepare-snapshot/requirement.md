# Requirement
IssueKey: 2026-09-05-config-prepare-snapshot

## Problem
Traefik’s `New` constructor receives `*configuration.Config` and mutates that same pointer before `IdentityHex` / `crowdsecconnection.New`. Yaegi keeps the CreateConfig pointer and passes it into `New` (`knowledge/research/ext_traefik_plugins_yaegi-constructor/notes.md`). Identity therefore hashes a rewritten DTO, and the host’s live Config is a process-wide scratchpad.

## Current (code)
- `plugin.go` `New` writes `LogLevel` ToUpper, copies deprecated `BanHTMLFilePath` / `CaptchaHTMLFilePath` into `BanFilePath` / `CaptchaFilePath`, then `ValidateParams`, then `crowdsecconnection.Prepare` on the same `*Config` Traefik passed in.
- `pkg/crowdsecconnection/connection.go` `Prepare` rewrites CAPI alone-mode host/path/scheme/interval and loads LAPI/AppSec/Redis secret files via `configuration.GetVariable` into the same struct.
- `pkg/crowdsecconnection/identity.go` `IdentityHex` / `Key` marshal `identityFrom(cfg)` from whatever fields remain after Prepare. `plugin.go` then `reclaim.Open(..., Key(config), ..., New(config, ...))` and `bouncer.New(..., config, ...)`.
- `pkg/bouncer/bouncer.go` `New` also writes `CaptchaSiteKey` / `CaptchaSecretKey` from `GetVariable` onto that same pointer (not named in the ticket’s Prepare/plugin.go list).
- `pkg/configuration/configuration.go` `GetVariable` reads `*File` or inline value and does not copy Config. `GetTLSConfigCrowdsec` reads Config; not moved this ticket.
- Tests: `plugin_test.go` `TestServeHTTP` calls `New` with `CreateConfig()` and does not assert post-New fields on that pointer. `pkg/configuration/configuration_test.go` covers `GetVariable` and LogLevel validate, not snapshot locality.

## Desired
Identity and `CrowdsecConnection.New` (and Bouncer) see one prepared snapshot. Traefik’s original Config pointer is not mutated. CAPI alone-mode rewrite, secret file loading, deprecated path aliases, and LogLevel ToUpper still happen, on the snapshot only. Explore decides copy-then-mutate vs a new Prepared type (assumed copy-then-mutate unless Prepared is clearly smaller). Tests that inspect config after `New` use the snapshot/prepared value.

## Affected
- `plugin.go` (`New`)
- `pkg/crowdsecconnection/connection.go` (`Prepare`, `New` call sites)
- `pkg/crowdsecconnection/identity.go` (`Key` / `IdentityHex` input)
- `pkg/bouncer/bouncer.go` (receives prepared Config; captcha secret load)
- Tests that pass Config into `New` and later read that pointer

## Out of scope
- File-split of `configuration.go` except as required by a new type in that package
- Moving `GetTLSConfigCrowdsec` / TLS builder (sibling)
- Changing DecisionScopeHeaders identity (sibling `2026-09-05-scope-headers-identity`)
- Sibling tickets: `2026-09-05-split-connection-files`, `2026-09-05-split-configuration-files`, `2026-09-05-split-ip-trust`, `2026-09-05-remediation-codes-owner`, `2026-09-05-decisionscope-mode-bool`

## Unknowns
- Copy-then-mutate of `configuration.Config` vs a distinct Prepared type (explore Decision; assumed copy-then-mutate).
- Whether `bouncer.New` captcha key writes stay on the snapshot (same pointer after copy) or must move into Prepare.
- Deep vs shallow copy of slice/map fields (`DecisionScopeHeaders`, trusted IPs, Redis read hosts).

## Tensions
- Ticket lists Prepare + plugin.go mutations; `bouncer.New` also mutates captcha keys on the Traefik pointer after reclaim. Copy-before-mutate in `plugin.go` would cover those writes if Bouncer still receives the snapshot. A Prepared type would need an explicit field or a second copy.
- Identity currently hashes post-Prepare secrets (file contents inlined). Snapshot must keep that order: mutate/load, then Key/New. Do not hash the unprepared Traefik DTO.
