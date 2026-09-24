## Context

See proposal.md Why. The seventeen owner-read captcha knobs still use the `BouncerCaptcha` / `bouncerCaptcha*` stem on `configuration.Config`. Traefik v3.7.11 mapstructure-decodes by field name (`knowledge/research/ext_traefik_plugins_config-decode/`). Explore Decisions are accepted: rename at `Config`, no aliases, fold the five live leaves, leftover owner-read captcha knobs stay non-E2.

## Goals / Non-Goals

**Goals:**

- One mechanical rename of the seventeen public captcha fields and the strings that name them.
- Reorder `Config` so `Captcha*` sits with `CaptchaEnabled` / `CaptchaInstanceName` (alphabetical by json tag).
- Keep `pkg/captcha` locals (`siteKey`, `secretKey`, `gateSecret`) and ownership JSON as they are.

**Non-Goals:**

- Old-key aliases or a nested `captcha:` map.
- Renaming bounce-decision fields or `CaptchaEnabled` / `CaptchaInstanceName`.
- Reconstructing client address, user, tenant, Host, or trust hop (gate bind still reads `clientRequest.remoteIP` from ServeHTTP).
- Migrating `openspec/changes/archive` or other runs' `devstate`.
- Writing `knowledge/devdocs` packets in this phase (implement / `opd-devdocsimpact` fold them).
- Changing leftover-secret classification: captcha E2 stays `captchaInstanceName` only.

## Decisions

| Topic | Choice | Rationale |
|-------|--------|-----------|
| Public surface | Go `Captcha*` + JSON `captcha*`; no aliases | Explore seam. Traefik matches the field name; a json-only alias would not decode. |
| Struct order | Move the seventeen fields next to `CaptchaEnabled` / `CaptchaInstanceName` | Existing “alphabetical by json tag” rule on `Config`. |
| Package boundary | Prefix stays on `Config`. `pkg/captcha` keeps local arg names. `GetVariable` strings become `CaptchaSiteKey` / `CaptchaSecretKey` / `CaptchaGateSecret` | One job, one owner. Do not grow a `bouncer` field on captcha. |
| Leftover E2 | `validateOpenVsSubscribe` still passes `secretPresent=false` for captcha | Explore assumed. Leftover owner-read `captcha*` is not a secret. Dropped `bouncerCaptcha*` never reaches `New`. |
| Pre-prefix revival | Accept that leftover `captchaFilePath` binds `CaptchaFilePath` again | Field-name match, not an alias. README BREAKING names it. |
| Catalog | Fold the five explore leaves; no new family | Live promises already live there. |
| Identity | None. Do not reconstruct remote IP in configuration or captcha Open | Explore Decision. Gate bind still uses ServeHTTP’s `clientRequest.remoteIP`. |

**Alternatives rejected:** old-key aliases; keep Go names and change only JSON tags; nest a `captcha:` map; rewrite archived OpenSpec folders; a new spec family.

## Risks / Trade-offs

- **Every in-tree operator file that still spells `bouncerCaptcha*` breaks until renamed** → Implement walks the explore inventory (34 current-contract files). No alias.
- **Outside-tree operator YAML cannot be enumerated** → README BREAKING names the stem move. Operators rename labels/YAML.
- **Pre-prefix `captchaFilePath` leftovers start mapping again** → Call it out in README BREAKING. Do not add a drop or alias to suppress it.
- **Stale usage packets** → Enough to call the subsystems. Implement / `opd-devdocsimpact` fold them.

## Migration Plan

- Operators rewrite plugin YAML/labels from `bouncerCaptcha*` to `captcha*`. No compatibility window.
- README, examples, and e2e ship the new names in the same change.
- Rollback is revert of the PR; old `bouncerCaptcha*` keys do not work on the new binary.

## Open Questions

None. Explore rows stay as explore wrote them.
