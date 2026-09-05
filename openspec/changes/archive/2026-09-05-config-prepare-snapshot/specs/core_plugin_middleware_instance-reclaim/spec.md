## ADDED Requirements

### Requirement: New prepares a Config snapshot without mutating Traefik’s pointer
`New` SHALL copy the Config pointer Traefik passed in before any write. Log-level normalize, deprecated ban/captcha path aliases, secret file inlining, and CAPI alone-mode host/path/scheme rewrite SHALL run on that snapshot only. Reclaim `Key` / identity, Crowdsec connection construction, and the per-router bouncer SHALL use the snapshot. Traefik’s original Config pointer MUST keep the decoded operator values (including mixed-case log level, uninlined `*File` secrets, and operator LAPI host when not already rewritten).

#### Scenario: Caller Config is unchanged after New
- **WHEN** Traefik (or a test) calls `New` with a Config that has mixed-case `LogLevel` and a deprecated ban HTML path
- **THEN** that same pointer still has the mixed-case log level and empty `BanFilePath` after `New` returns
- **AND** the bouncer still serves the aliased ban template from the snapshot

#### Scenario: Identity hashes the prepared snapshot
- **WHEN** two `New` calls use the same connection fields after secret file inlining and CAPI alone-mode rewrite
- **THEN** both reclaim the same Crowdsec connection
- **AND** identity is computed from the snapshot, not from the unprepared Traefik pointer
