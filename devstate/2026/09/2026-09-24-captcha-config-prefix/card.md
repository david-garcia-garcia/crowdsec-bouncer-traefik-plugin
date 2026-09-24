## Motivation
After the domain-prefix rename, `configuration.Config` keys start with the piece that reads them. Own-axis captcha already uses `captchaEnabled` / `captchaInstanceName`. Bounce-decision fields stay on the bouncer stem even when a value is the word `captcha`.

The seventeen owner-read captcha knobs still sit on `BouncerCaptcha*` / `bouncerCaptcha*`: provider, site and secret keys (and files), gate secret (and file), gate bind, template path, custom widget URLs and validate body, grace seconds, and siteverify timeout. `pkg/captcha` is the piece that reads them — `ownershipFrom` and `newOwnerClient` look up `GetVariable("BouncerCaptchaSiteKey")`, `BouncerCaptchaSecretKey`, and `BouncerCaptchaGateSecret`. The live config-validation spec froze that spelling as the current contract.

Left alone, the prefix rule lies about ownership. Operators and the catalog keep teaching captcha knobs as bouncer knobs. Every new owner-read captcha setting keeps the stale syllable, and the live SHALL keeps that freeze.

Priority: P3 — spec and public-key naming, no current user or operator harm

## Implementation
Rename the seventeen `Config` Go fields `BouncerCaptcha*` → `Captcha*` and JSON tags `bouncerCaptcha*` → `captcha*`. Reorder the struct so the new block sits with `CaptchaEnabled` / `CaptchaInstanceName` (alphabetical by json tag). No old-key aliases. Leave bounce-decision `Bouncer*` fields and the two own-axis captcha keys.

`GetVariable` production strings and `ValidateParams` error text use the new Go names (`CaptchaSiteKey`, `CaptchaSecretKey`, `CaptchaGateSecret`, `CaptchaFilePath`, `CaptchaCustomValidateBody`, `CaptchaProvider`). Leftover owner-read `captcha*` stays non-E2; leftover `captchaInstanceName` stays E2. Dropped `bouncerCaptcha*` never reaches `New`. A leftover pre-prefix `captchaFilePath` binds `CaptchaFilePath` again (field-name match, not an alias).

`pkg/captcha` `ownershipFrom` and `newOwnerClient` read the new `GetVariable` strings and `cfg.Captcha*` knobs. Local argument names stay `siteKey` / `secretKey` / `gateSecret`. Defaults stay the same: template `/captcha.html`, gate bind true, grace 1800, siteverify timeout 10.

README BREAKING names the stem move and the `captchaFilePath` revival. Examples, compose labels, mock and real e2e, unit tests, and the five change-folder spec leaves ship the new names in the same apply.

## What this changes
**Operators.** Rewrite plugin YAML and Traefik labels from `bouncerCaptcha*` to `captcha*` (`captchaProvider`, `captchaSiteKey`, `captchaSecretKey`, `captchaGateSecret`, `captchaFilePath`, and the other twelve); leftover `bouncerCaptcha*` is dropped, and a leftover pre-prefix `captchaFilePath` binds again.

**Admin users.** None.

**Developers.** `configuration.Config` fields and JSON tags are `Captcha*` / `captcha*`; `GetVariable` takes `CaptchaSiteKey`, `CaptchaSecretKey`, and `CaptchaGateSecret`; validation errors name those fields.

**End users.** None.

## Merge readiness
In progress. 0 items remain.

Priority: P3 — spec and public-key naming, no current user or operator harm
Reviewed head: 656bca4a
Owner decision: None.

## Review scores
| Measure | Result | What it means |
| --- | --- | --- |
| Overall readiness | 1/6 | Not ready |
| CI proof | 1/6 | not seen |
| Local tests proof | N/A | remote PR — CI proof covers this |
| Review resolution | 6/6 | no open PR comments |

## Verification
| Check | Result | Evidence |
| --- | --- | --- |
| Branch | 2026-09-24-captcha-config-prefix pushed | `git` |
| OpenSpec | captcha-config-prefix | `openspec/` |
| Pull request | https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pull/142 | pr-host |
| CI | not seen | caller omitted CI snapshot |
| Local tests | passed | handoff.yaml localTests |
| PR comments | no comments | devstate/comments.md |

## Specs
Worktree:
- [build_e2e_pester_crowdsec-stack](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-09-24-captcha-config-prefix/openspec/changes/archive/2026-09-24-captcha-config-prefix/proposal.md) — modified
- [core_plugin_lapi_reclaim-key](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-09-24-captcha-config-prefix/openspec/changes/archive/2026-09-24-captcha-config-prefix/proposal.md) — modified
- [core_plugin_middleware_bouncer](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-09-24-captcha-config-prefix/openspec/changes/archive/2026-09-24-captcha-config-prefix/proposal.md) — modified
- [core_plugin_middleware_captcha-gate](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-09-24-captcha-config-prefix/openspec/changes/archive/2026-09-24-captcha-config-prefix/proposal.md) — modified
- [core_plugin_middleware_config-validation](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-09-24-captcha-config-prefix/openspec/changes/archive/2026-09-24-captcha-config-prefix/proposal.md) — modified

Completed:
- [build_e2e_pester_crowdsec-stack](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-09-24-captcha-config-prefix/openspec/specs/build_e2e_pester_crowdsec-stack/spec.md) — modified
- [core_plugin_lapi_reclaim-key](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-09-24-captcha-config-prefix/openspec/specs/core_plugin_lapi_reclaim-key/spec.md) — modified
- [core_plugin_middleware_bouncer](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-09-24-captcha-config-prefix/openspec/specs/core_plugin_middleware_bouncer/spec.md) — modified
- [core_plugin_middleware_captcha-gate](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-09-24-captcha-config-prefix/openspec/specs/core_plugin_middleware_captcha-gate/spec.md) — modified
- [core_plugin_middleware_config-validation](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-09-24-captcha-config-prefix/openspec/specs/core_plugin_middleware_config-validation/spec.md) — modified


## Deviations from the ask
None.

## Follow-up issues
None.

## How this fits together
Ticket 2026-09-24-captcha-config-prefix on branch 2026-09-24-captcha-config-prefix targeting master; PR https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pull/142; CI not seen.

## Explore Decisions
None.

## Findings
None.

## Axis review
[Standards](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-09-24-captcha-config-prefix/devstate/2026/09/2026-09-24-captcha-config-prefix/codereview_standards.md) — 0 total, 0 pending, 0 completed
[Nitpicks](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-09-24-captcha-config-prefix/devstate/2026/09/2026-09-24-captcha-config-prefix/codereview_nitpicks.md) — 0 total, 0 pending, 0 completed
[Spec](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-09-24-captcha-config-prefix/devstate/2026/09/2026-09-24-captcha-config-prefix/codereview_spec.md) — 0 total, 0 pending, 0 completed
[Scope](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-09-24-captcha-config-prefix/devstate/2026/09/2026-09-24-captcha-config-prefix/codereview_scope.md) — 0 total, 0 pending, 0 completed
[Security](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-09-24-captcha-config-prefix/devstate/2026/09/2026-09-24-captcha-config-prefix/codereview_security.md) — 0 total, 0 pending, 0 completed
[Performance](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-09-24-captcha-config-prefix/devstate/2026/09/2026-09-24-captcha-config-prefix/codereview_performance.md) — 0 total, 0 pending, 0 completed
[Dead](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-09-24-captcha-config-prefix/devstate/2026/09/2026-09-24-captcha-config-prefix/codereview_dead.md) — 0 total, 0 pending, 0 completed
[Test coverage](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-09-24-captcha-config-prefix/devstate/2026/09/2026-09-24-captcha-config-prefix/codereview_coverage.md) — 0 total, 0 pending, 0 completed


## Agent review details

### Review metrics
| Metric | Value | Why it matters |
| --- | --- | --- |
| Specs in this PR | 0 added / 10 modified | Same list as ## Specs |
| Open reviewer comments walked | 0 FIX / 0 ANSWER / 0 open | Unanswered review is merge risk |
| Reviewed head | 656bca4a498a5485aca2ef05582bf5962f66f548 | Card must match the branch you measured |

### Stored data model
None.
