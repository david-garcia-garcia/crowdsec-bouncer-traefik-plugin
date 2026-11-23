## Motivation
Not yet.

## Implementation
Not yet.

## What this changes
**Operators.** None.

**Admin users.** None.

**Developers.** None.

**End users.** None.

## Merge readiness
Ready for review. 1 items remain.

Priority: unknown — motivation not written
Reviewed head: eee4fd0d
Owner decision: Required. See Explore Decisions.

## Review scores
| Measure | Result | What it means |
| --- | --- | --- |
| Overall readiness | 6/6 | Ready |
| CI proof | 6/6 | succeeded https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/actions/runs/45254425324 |
| Local tests proof | N/A | remote PR — CI proof covers this |
| Review resolution | 6/6 | no open PR comments |

## Verification
| Check | Result | Evidence |
| --- | --- | --- |
| Branch | 2026-11-23-waf-unknown-length-body pushed | `git` |
| OpenSpec | waf-inspect-unknown-length-body | `openspec/` |
| Pull request | https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pull/237 | pr-host |
| CI | build 45254425324 succeeded https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/actions/runs/45254425324 | https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/actions/runs/45254425324 |
| Local tests | passed | handoff.yaml localTests |
| PR comments | no comments | devstate/comments.md |

## Specs
Worktree:
- [core_plugin_appsec_client](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-11-23-waf-unknown-length-body/openspec/changes/waf-inspect-unknown-length-body/proposal.md) — modified
- [core_plugin_appsec_failure-action](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-11-23-waf-unknown-length-body/openspec/changes/waf-inspect-unknown-length-body/proposal.md) — modified
- [core_plugin_middleware_bouncer](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-11-23-waf-unknown-length-body/openspec/changes/waf-inspect-unknown-length-body/proposal.md) — modified
- [core_plugin_middleware_config-validation](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-11-23-waf-unknown-length-body/openspec/changes/waf-inspect-unknown-length-body/proposal.md) — modified
- [core_plugin_modsecurity_client](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-11-23-waf-unknown-length-body/openspec/changes/waf-inspect-unknown-length-body/proposal.md) — modified
- [core_plugin_modsecurity_inspect](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-11-23-waf-unknown-length-body/openspec/changes/waf-inspect-unknown-length-body/proposal.md) — modified
- [core_plugin_wafhop_shared-request](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-11-23-waf-unknown-length-body/openspec/changes/waf-inspect-unknown-length-body/proposal.md) — modified


## Deviations from the ask
- taken: a total read deadline on bodies of unknown length, implemented once in `pkg/wafhop` for both legs, that blocks independently of the failure action (decisions 1 and 2); no criterion names a signature change. → `appsec.Client.Query(req, pol, dl)` gains a third parameter and `modsecurity.Client.Inspect(req, dl)` replaces its `failureAction` parameter (used only by the removed drop branch). `dl` is a narrow `wafhop.ReadDeadliner` the bouncer builds from `rw` with `http.NewResponseController`. Call sites migrated here: `Query` 1 production + 69 test, `Inspect` 1 production + 5 test (explore.md, Call sites). — `pkg/bouncer (sole owner of rw); pkg/wafhop/body.go (ReadBody, owner of the read and the deadline)` — the response writer is the only handle that sets a read deadline on HTTP/1.1 (`Body.Close` cannot cut it, #204 measurement); the bouncer owns it and the shared read owns the cut. Rank `bounded incidental` (explore.md, open question on how the control reaches `pkg/wafhop`).. Requester: not asked.


## Follow-up issues
- [ ] [AppSec call is not canceled when the client leaves](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-11-23-waf-unknown-length-body/knowledge/debt/2026-11-23-appsec-call-ignores-inbound-cancel.md) — the AppSec listener request does not carry the inbound context, so a client that leaves keeps the call open until `appsecHttpTimeoutSeconds` (pre-existing; found by the 180 s `Test_appsecQuery_hopCancelDoesNotTripGate`).


## How this fits together
Ticket 2026-11-23-waf-unknown-length-body on branch 2026-11-23-waf-unknown-length-body targeting master; PR https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pull/237; CI build 45254425324 succeeded https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/actions/runs/45254425324.

## Explore Decisions
| Question | Rank | Decision | By |
| --- | --- | --- | --- |
| One deadline key per leg or one shared key; name, default, validation, and does it enter each leg's reclaim identity? | additive asked — two new public keys and two identity fields; decision 1 "Whether there is one key per leg (`appsecBodyReadTimeoutSeconds` / `modsecBodyReadTimeoutSeconds`, consistent with per-leg settings and shared leg instances) or one shared key: explore decides and records why" | assumed — one key per leg: `appsecBodyReadTimeoutSeconds` (Go `AppsecBodyReadTimeoutSeconds`) and `modsecBodyReadTimeoutSeconds` (Go `ModsecBodyReadTimeoutSeconds`), `int64`, `omitempty`, default `30` each, in `requiredInt1` next to the `*HTTPTimeoutSeconds` siblings (`< 1` → `<Name>: cannot be less than 1`); no `0 = disabled` mode (it would reopen the hang decision 1 closes). Why per leg: leg instances are shared by owner (`appsecInstanceName` / `modsecInstanceName`, owner Open + alias), and a router may run AppSec owned by one middleware and ModSec owned by another; each leg's knobs live on its own Client and reclaim key (`pkg/appsec/session.go:18-31`, `pkg/modsecurity/session.go:20-26`), so a shared key would have no owner. Each key joins its leg's identity (a change Opens a new Client, spec "reclaimed by listener/sidecar identity"). Default 30 s: below Traefik's default `readTimeout` of 60 s (`traefik/traefik@v3.7.19:pkg/config/static/static_config.go:51`), so with Traefik defaults the plugin's logged block fires first; enough for 10 MiB on roughly 2.8 Mbit/s. Inside each package the stored field drops the leg prefix (`bodyReadTimeout`). | explore |


## Findings
None.

## Axis review
None.

## Agent review details

### Review metrics
| Metric | Value | Why it matters |
| --- | --- | --- |
| Specs in this PR | 0 added / 7 modified | Same list as ## Specs |
| Open reviewer comments walked | 0 FIX / 0 ANSWER / 0 open | Unanswered review is merge risk |
| Reviewed head | eee4fd0db93102bbc29decd6aa8b0ba47d01de7f | Card must match the branch you measured |

### Stored data model
None.
