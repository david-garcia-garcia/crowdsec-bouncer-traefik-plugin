## Context

See proposal.md — Why. Config still declares `BanHTMLFilePath` / `CaptchaHTMLFilePath`. `plugin.New` copies ban when `BanFilePath` is empty and overwrites captcha whenever the old key is set. Template load already reads only `BanFilePath` / `CaptchaFilePath`. Traefik v3.7.11 `createConfig` does not set mapstructure `ErrorUnused`; leftover keys never reach `New` (`knowledge/research/ext_traefik_plugins_config-decode/`).

## Goals / Non-Goals

**Goals:**
- Remove both Deprecated fields and both `New` copies so Traefik’s decode of `banFilePath` / `captchaFilePath` is the only owner.
- Retarget every live leftover, including HTML-cased README/examples, so suites and docs use the current keys.
- Keep the existing snapshot and bindCtx. Delete only the two copy blocks before `ValidateParams`.

**Non-Goals:**
- A quieter empty-guard or any compatibility alias (declined PR #85).
- A remain-map, warn hook, or leftover-key reject in `New`.
- Template-load defaults, Content-Type inference, catalog version, CHANGELOG.
- Rewriting archived OpenSpec history.
- `sync.Once`, package globals, or reclaim / identity changes.

## Decisions

1. Delete the fields and the copies. Do not keep struct tags so `New` can warn. Alternative: empty-guard alias (PR #85) — rejected; owner wants the keys gone. Traefik drops unused keys; operators who only set the old keys get defaults.
2. Fold the live custom-ban WHEN into `build_e2e_pester_crowdsec-stack`. FindSpecHost: no Config-surface leaf names the Deprecated fields; do not add an alias SHALL and do not create a new leaf for field deletion.
3. Prove current keys by retargeting existing real-stack custom-ban and mock captcha YAML. Do not add `TestNew_CaptchaFilePathWinsOverDeprecatedHTMLPath` or any empty-guard alias test.
4. Leave `openspec/changes/archive/2026-09-05-add-real-e2e/` as historical.

## Risks / Trade-offs

- [Operators who only set the old keys silently get defaults] → intended. State it on the PR Operators line. Do not keep fields to catch leftovers.
- [Real/mock e2e still name the old keys] → retarget those YAML files in the same change so CI keeps proving serve.

## Migration Plan

Operators switch deploy labels/YAML to `banFilePath` / `captchaFilePath`. Rollback is revert of this change. No CHANGELOG file on dest; catalog bump is a release job.

## Open Questions

None — ticket decisions stand on `explore.md`.
