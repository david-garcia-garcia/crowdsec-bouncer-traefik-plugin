Developer review: in progress — 2026-09-18T14:24:30Z

## What this changes
**Operators.** None.

**Admin users.** None.

**Developers.** Records RFC 9110 media-type case rules in `knowledge/research/ext_http_media-types/`. Siteverify `Validate` still matches `Content-Type` with a lowercase `application/json` prefix.

**End users.** None.

## Motivation
After a captcha solve, this plugin POSTs the token to the provider siteverify URL and only mints `crowdsec_captcha_gate` when that response is treated as JSON with `success:true`. On `master`, that JSON check is `strings.HasPrefix(Content-Type, "application/json")`.

A provider that sends `Application/JSON` plus `{"success":true}` is classified as non-JSON (`responseType:noJson`). `ServeHTTP` then writes the 200 challenge page and skips the gate cookie and 302. RFC 9110 type and subtype tokens are case-insensitive, so that header is JSON.

If this does not land, a successful solve against a provider (or proxy) that capitalizes the media type never clears captcha: the visitor is challenged again with no cookie.

```mermaid
sequenceDiagram
  participant Solver
  participant Validate
  participant Siteverify
  Solver->>Validate: POST provider token
  Validate->>Siteverify: form POST
  Siteverify-->>Validate: Application/JSON plus success true
  Validate->>Validate: prefix application/json misses
  Validate-->>Solver: 200 challenge, no crowdsec_captcha_gate
```

## Merge readiness
Prepare stub only; siteverify match is unchanged. 1 item remains.

Priority: P2 — real solver pain when the provider capitalizes Content-Type, limited to that header match
Reviewed head: c928480
Owner decision: None.

## Review scores
| Measure | Result | What it means |
| --- | --- | --- |
| Overall readiness | 3/6 | CI is still queued; no product fix on the branch |
| CI proof | 3/6 | Checks queued on [35355934547](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/actions/runs/35355934547) and [35355934583](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/actions/runs/35355934583) |
| Local tests proof | N/A | `localTests: none`; remote CI is the proof axis |
| Review resolution | 6/6 | No OPEN PR comments |

## Verification
| Check | Result | Evidence |
| --- | --- | --- |
| Branch | 2026-09-18-captcha-siteverify-content-type-case pushed | `git` `c928480` |
| OpenSpec | none | `openspec/` |
| Pull request | https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pull/94 | GitHub PR 94 |
| CI | build 35355934547 queued https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/actions/runs/35355934547 ; build 35355934583 queued https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/actions/runs/35355934583 | GitHub check runs |
| Local tests | none | handoff.yaml localTests |
| PR comments | no comments | no comments.md |

## Specs
None.

## Follow-up issues
None.

## How this fits together
Local dump grounded on `master`; branch `2026-09-18-captcha-siteverify-content-type-case` opened stub PR 94. CI is queued on that head.

## Decision needed
None.

## Before merge
- [ ] Treat siteverify as JSON when the media type before parameters equals `application/json` case-insensitively; `success:true` must set the gate cookie and 302; add a regression [P2]
- [x] Stub PR opened

## Findings
None.

## Axis review
None.

## Agent review details

### Review metrics
| Metric | Value | Why it matters |
| --- | --- | --- |
| Specs in this PR | none | Same list as ## Specs; do not paste diff --stat |
| Open reviewer comments walked | 0 FIX / 0 ANSWER / 0 open | Unanswered review is merge risk |
| Reviewed head | c9284803ce06743fdf4cb02bd611f8d7eb30df6a | Card must match the branch you measured |

### Stored data model
None.

### Technical review
Best possible solution: DestBranch still does the case-sensitive prefix check; this PR only records the RFC rule implement should follow.

Do we have a high-confidence way to reproduce? Yes, `Application/JSON` + `{"success":true}` on `Client.Validate` / `ServeHTTP` (hunt proof `TestHunt_siteverifyJSONContentTypeIsCaseInsensitive`, not on dest).

Is this the best way to solve the issue? Not solved yet versus DestBranch; the required match is media type before parameters, case-insensitive.

### Evidence
What I checked:
- `Validate` Content-Type prefix and `(false, nil)` → 200 challenge (`pkg/captcha/captcha.go`, `origin/master` `fad36a1`)
- Existing solve stub uses lowercase `application/json` (`pkg/captcha/zzz_servehttp_test.go`, `fad36a1`)
- RFC 9110 § 8.3.1 type/subtype case-insensitive (`knowledge/research/ext_http_media-types/notes.md`, `c928480`)
- PR 94 OPEN, comments empty, checks queued (`c928480`)

### Rank-up moves
None.
