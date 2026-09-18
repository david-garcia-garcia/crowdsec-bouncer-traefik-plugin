Developer review: ready for review — 2026-09-18T17:44:52Z

## What this changes
**Operators.** Set `banFilePath` and `captchaFilePath` only. YAML or labels that still set `banHtmlFilePath` / `captchaHtmlFilePath` (or the HTML-cased twins) are ignored by Traefik and are not copied onto the current fields; those deploys get CreateConfig defaults (`banFilePath` empty, `captchaFilePath` `/captcha.html`).

**Admin users.** None.

**Developers.** `Config` no longer has `BanHTMLFilePath` or `CaptchaHTMLFilePath`. `plugin.New` snapshots Traefik’s decode and does not read the old keys. Live e2e, examples, README, and `build_e2e_pester_crowdsec-stack` name `banFilePath` / `captchaFilePath`.

**End users.** None.

## Motivation
Operators still have two names for the ban and captcha template paths on `master`. The current keys are `banFilePath` and `captchaFilePath`. The old `banHtmlFilePath` and `captchaHtmlFilePath` keys remain on Config as Deprecated fields, and `plugin.New` copies them onto the current fields.

On `master`, ban copies the old key only when `banFilePath` is empty. Captcha copies whenever `captchaHtmlFilePath` is non-empty and overwrites `captchaFilePath`. Real e2e labels, including the custom-ban route’s `banhtmlfilepath`, and the mock captcha scenario still set the old keys.

Not merging leaves the captcha overwrite, the extra public keys, and in-tree YAML that silently falls back to defaults once the fields are gone. Closed PR #85’s empty-guard alias is not the fix: the owner wants the keys deleted.

```mermaid
flowchart TD
  New[plugin.New]
  New --> Ban{BanFilePath empty and BanHTMLFilePath set?}
  Ban -->|yes| CopyBan[Copy onto BanFilePath]
  Ban -->|no| KeepBan[Keep BanFilePath]
  New --> Cap{CaptchaHTMLFilePath non-empty?}
  Cap -->|yes| Overwrite[Overwrite CaptchaFilePath]
  Cap -->|no| KeepCap[Keep CaptchaFilePath]
```

## Merge readiness
Implement landed and CI succeeded. 0 items remain.

Priority: P2 — leftover deprecated captcha key silently replaces the named template; workaround is unset the old key
Reviewed head: 6701999
Owner decision: Required. See Decision needed.

## Review scores
| Measure | Result | What it means |
| --- | --- | --- |
| Overall readiness | 6/6 | CI succeeded; no open PR comments |
| CI proof | 6/6 | All four required checks succeeded on 6701999 |
| Local tests proof | N/A | Remote PR; CI proof covers this |
| Review resolution | 6/6 | OPEN PR #100; no reviewer comments |

## Verification
| Check | Result | Evidence |
| --- | --- | --- |
| Branch | 2026-09-18-remove-html-filepath-deprecations pushed | `git` `origin/2026-09-18-remove-html-filepath-deprecations` at `6701999` |
| OpenSpec | remove-html-filepath-deprecations | `openspec/changes/remove-html-filepath-deprecations/` |
| Pull request | https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pull/100 | pr-host |
| CI | Race detector success https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/actions/runs/35375827428/job/105700151672 ; Main Process success https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/actions/runs/35375827428/job/105700150692 ; e2e (binary + mock LAPI) success https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/actions/runs/35375827429/job/105700150954 ; e2e (docker + pester) success https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/actions/runs/35375827429/job/105700150666 | pr-host CI |
| Local tests | passed | handoff.yaml localTests; `go test -v -cover ./...` and `golangci-lint run` |
| PR comments | no comments | no `comments.md` |

## Specs
- [build_e2e_pester_crowdsec-stack](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-09-18-remove-html-filepath-deprecations/openspec/changes/remove-html-filepath-deprecations/proposal.md) — modified

## Follow-up issues
None.

## How this fits together
Local ticket `2026-09-18-remove-html-filepath-deprecations` runs on that branch as PR #100. Implement deleted the Deprecated fields and retargeted live leftovers; CI on `6701999` succeeded.

## Decision needed
| Question | Decision | By |
| --- | --- | --- |
| Does this ticket need a CHANGELOG entry or catalog version bump? | assumed — no CHANGELOG file on dest; do not invent one. Catalog version is a release job, not this change. Breaking for operators who still set only the old keys; state that on the PR Operators line. | explore |

## Before merge
- [x] [P2] Delete `BanHTMLFilePath` and `CaptchaHTMLFilePath` from Config and both `plugin.New` alias blocks.
- [x] [P2] Retarget live leftovers (real e2e including custom-ban `banhtmlfilepath`, mock captcha, README sample, captcha / custom-captcha examples, live `build_e2e_pester_crowdsec-stack` WHEN) to `banFilePath` / `captchaFilePath`.

## Findings
None.

## Axis review
None.

## Agent review details

### Review metrics
| Metric | Value | Why it matters |
| --- | --- | --- |
| Specs in this PR | 0 added / 1 modified | Same list as ## Specs |
| Open reviewer comments walked | 0 FIX / 0 ANSWER / 0 open | Unanswered review is merge risk |
| Reviewed head | 6701999ea232cb47c4c5b4c3969be284cc077eab | Card must match the branch you measured |

### Stored data model
None.

### Technical review
Best possible solution: Delete both Deprecated fields and both `New` copies. Dest still ships them. Do not reuse declined PR #85 empty-guard.

Do we have a high-confidence way to reproduce? Yes. Dest `plugin.go` copies captcha whenever the old key is set and ban only when the new key is empty. After this apply, leftover `banhtmlfilepath` on the custom-ban e2e was ignored and the suite failed until that label was retargeted to `banFilePath`.

Is this the best way to solve the issue? Yes versus dest. The constraint that matters is deleting both settings with no alias.

### Evidence
What I checked:
- `BanHTMLFilePath` / `CaptchaHTMLFilePath` removed from `pkg/configuration/configuration.go`; both `plugin.New` copies removed (`6701999`)
- Live leftovers retargeted; archive `openspec/changes/archive/2026-09-05-add-real-e2e/` unchanged
- Local `go test -v -cover ./...` passed; `golangci-lint run` passed
- First CI on `9ad009e`: e2e (docker + pester) failed on custom-ban marker; leftover `banhtmlfilepath` retargeted
- CI on reviewed head `6701999`: Race detector, Main Process, e2e (binary + mock LAPI), e2e (docker + pester) success
- OPEN PR #100; comment inventory empty

### Rank-up moves
None.
