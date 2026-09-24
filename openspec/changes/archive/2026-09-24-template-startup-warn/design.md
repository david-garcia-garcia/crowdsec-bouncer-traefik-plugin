## Context

See proposal.md Why. Dest fails `ValidateParams` and `Client.New` when the captcha file is empty or not loadable, and `ValidateParams` fails when a set ban path is unloadable. `bouncer.New` already discards the ban `GetTemplate` error and serves status-only when `banTemplate` is nil. `handleRemediationServeHTTP` already bans when the captcha client is nil or `!Valid`. Bounce-only never `captcha.Open`s, so unused default `/captcha.html` is never read. Explore Decisions are accepted: each owner warns at its constructor; `Client.New` succeeds and leaves `Valid` false; `bouncer.New` warns only about the ban file.

## Goals / Non-Goals

**Goals:**

- Constructor warn-and-succeed for both templates. Captcha remediations fall back to the existing `!Valid` ban. Ban stays a status with an empty body.
- One WARN per owner at that constructor. Tests through `newTestLogSink` (`std_go_test_log-sink`).
- Flip the three dest pins that require a hard fail.

**Non-Goals:**

- Embedding `ban.html` / `captcha.html`.
- Changing the remediation status code.
- Relaxing site key, secret, or gate secret checks.
- A per-request template-missing WARN.
- A second template-missing flag beside `Valid`.
- Warning from `bouncer.New` about `CaptchaFilePath`.
- Changing HEAD bodyless-when-template-loaded.
- Writing `knowledge/devdocs` this phase.

## Decisions

| Topic | Choice | Rationale |
|-------|--------|-----------|
| Captcha seam | `Client.New` / `Open` warns, returns nil, `Valid` false | Owner of the captcha file. Existing `handleRemediationServeHTTP` `!Valid` ban fires. Bounce-only never Opens. |
| Ban seam | `bouncer.New` warns, keeps `banTemplate` nil | Owner of the ban file. Dest already serves empty body when nil. |
| ValidateParams | Stop `GetTemplate` fail-closed for captcha and ban | Desired: do not fail `New`. Credentials and gate stay required. |
| Stems | `crowdsec captcha template unavailable` / `crowdsec bouncer ban template unavailable`; `reason` `empty`\|`unloadable` | One-line WARN that names empty vs unloadable. Sibling stems stay short; fallback is the existing ban / empty-body path. |
| Catalog | Fold `core_plugin_middleware_config-validation` only | Small adjustment to the live template-fail blocks plus empty/unloadable ban warn. Neighbors already ban on `!Valid`. |

**Alternatives rejected:** Warn from `bouncer.New` about `CaptchaFilePath` (false warn on bounce-only unused `/captcha.html`). Warn from both (duplicate, and the bouncer half still false-warns). Keep `Valid` true and add a second flag. Embed sample HTML. Per-request template-missing WARN. Relax site/secret/gate checks.

## Risks / Trade-offs

- **Missing captcha file no longer fails before LAPI Open** → Desired. `New` proceeds; captcha remediations ban. Tests that expected `nil, err` without LAPI Open must flip.
- **Published `!Valid` client does not 503 under startup-block** → Startup-block is unpublished (typed nil). A published invalid client is published. Captcha kind still bans. Do not treat template-missing as unpublished.
- **Every `bouncer.New` with empty `BouncerBanFilePath` now WARNs** → Desired. Default ban path is empty. Operators who never set a ban file will see the startup line once.

## Migration Plan

- Deploy. No config rewrite. Rollback is revert of the PR.

## Open Questions

None. Explore rows stay as explore wrote them except the warning-text row, which propose resolved.
