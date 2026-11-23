# WAF legs (AppSec and ModSec): inspect request bodies of unknown length instead of dropping them

Supersedes PR #204 (https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pull/204, branch `2026-11-14-appsec-unknown-length-body`), which fixed this for AppSec only on a base that predates the leg split (#219, #221), the shared `pkg/wafhop` package, and the ModSec leg (#190). #204 is now in conflict with `master` in 19 files. This ticket redoes the fix on current `master` and covers **both** WAF legs.

Upstream issue: https://github.com/maxlerebourg/crowdsec-bouncer-traefik-plugin/issues/405
("Silent 403 on HTTP/2 requests with an empty body (restic repo creation) — crowdsecAppsecUnreadableBodyBlock defaults to true").
Upstream candidate fixes, both OPEN and not merged:
- https://github.com/maxlerebourg/crowdsec-bouncer-traefik-plugin/pull/407
- https://github.com/maxlerebourg/crowdsec-bouncer-traefik-plugin/pull/434

The delivery card and the PR MUST reference upstream issue #405 by URL and say that this PR supersedes #204.

## Reference material (reuse, do not copy blindly)

PR #204's run bus is on `origin/2026-11-14-appsec-unknown-length-body` under `devstate/2026/11/2026-11-14-appsec-unknown-length-body/` (`explore.md`, `requirement.md`, `deviations.md`, `card.md`) and its code/specs/README/tests are on that branch. Its explore decisions (key name `appsecBodyReadTimeoutSeconds`, default 30, min 1; timer + `http.ResponseController.SetReadDeadline` with `Body.Close` fallback and no goroutine/select/atomic for Yaegi; timer flag `!timer.Stop()` classifies the deadline before the client-gone check; ban path with header `ban:appsec-body-timeout` and metrics origin `plugin:appsec_body_timeout`; debounced WARN naming `bypassAppsec`; `EffectiveAppsecBodyLimit`; why not upstream #407/#434) are the starting point. Re-measure them against current `master`: the code they cite has moved (`pkg/wafhop/body.go`, `pkg/appsec/query.go`, `pkg/modsecurity/inspect.go`, `pkg/bouncer/*` split per leg), master now has `wafhop.ErrClientBodyRead` (answered 400 without a ban), and Traefik in e2e moved from v3.7.11 to v3.7.19 (re-measure the HTTP/1.1 deadline-cut limitation #204 recorded).

## Problem (on master)

1. `pkg/wafhop/body.go` `IsBodyUnreadable` classifies any HTTP/2 or HTTP/3 request with a body and `ContentLength < 0` (no `Content-Length` header) as unreadable without trying to read it.
   - AppSec (`pkg/appsec/query.go` `newAppsecBodyRequest`): POST/PUT/PATCH → `errUnreadableBody` → `bouncerAppsecFailureAction` (default `ban` → 403, AppSec never queried). With `passthrough`, headers-only to AppSec and the body reaches origin uninspected.
   - ModSec (`pkg/modsecurity/inspect.go` `Inspect`): same rule with `bouncerModsecFailureAction`, whose default is `passthrough` — so on ModSec the bypass is the **default**: any client that omits `Content-Length` on HTTP/2/3 gets its body past ModSec uninspected.
   - Real-world victim: `restic init` against `rest-server` sends `POST <repo>/?create=true` over HTTP/2 with an empty body and no `Content-Length` → silent 403 with AppSec defaults.
2. The classification depends only on a client-controlled signal (`Content-Length` is optional in HTTP/2/3). A client-controlled signal reduces inspection.
3. DELETE without `Content-Length` (HTTP/2/3) goes headers-only on both legs regardless of the failure action, while a DELETE with the header has its body inspected.
4. One failure action covers both "the WAF failed" and "the client sent no length", so an operator cannot let restic through without also failing open on WAF outages.

## Decisions (made by the human; carried over from #204, extended to ModSec; do not re-litigate)

1. Bodies of unknown length are read and inspected like any other body on **both** WAF legs, capped at the leg's body limit, with a **total read deadline** (time to receive the body, not an idle timeout), configurable through public config (not hardcoded). Implement the read and deadline **once in `pkg/wafhop`** so both legs share it; a body already buffered by the first leg is reused by the second (existing `bufferedBody` reuse). Whether there is one key per leg (`appsecBodyReadTimeoutSeconds` / `modsecBodyReadTimeoutSeconds`, consistent with per-leg settings and shared leg instances) or one shared key: explore decides and records why.
2. When the deadline expires the request is blocked, **independently of the leg's failure action** (fail-closed; otherwise `passthrough` + a slowly dripped body is a bypass again). Status/remediation: explore decides and records why, considering #204's ban path and master's newer `wafhop.ErrClientBodyRead` → 400 contract.
3. gRPC and Connect get **no special case** (no Content-Type classification). Unary calls end and are inspected; client/bidirectional streams hit the deadline and are blocked. Operators exclude genuine streaming routes with `bouncerActionRules` + `bypassAppsec` (and the ModSec equivalent, if one exists on master; if none exists, explore reports it).
4. `appsecBodyLimit` values `<= 0` become 10 MiB (10485760). This removes "0 = unlimited" and replaces today's validation error for negative values. `modsecBodyLimit` keeps its current validation (`>= 1`) and its `RejectOverLimit` (413) semantics.
5. Bodies larger than the AppSec limit: unchanged (first N bytes inspected, remainder forwarded uninspected). ModSec over-limit: unchanged (413).
6. Consequence of 1: a DELETE body without `Content-Length` is inspected like one with it, on both legs.
7. Each leg's failure action goes back to meaning only "the WAF failed" (unreachable, 5xx, unexpected status, response read error). Do NOT reintroduce `crowdsecAppsecUnreadableBodyBlock` or any bool that lets an unreadable body pass. Remove `IsBodyUnreadable` / `IsMethodWithBody` and their drop paths.
8. The deadline block is logged above Debug (Warn), debounced, with a message that tells the operator to exclude streaming routes with `bypassAppsec`.
9. Out of this ticket: the per-leg BackOffAction / default changes being worked in `2026-11-23-backoff-action-per-leg` (do not change any FailureAction default or gate behaviour here).

Principle: a client-controlled signal may only lead to more inspection or to a block, never to less inspection.

## Deliverables

- Code + tests: unit (wafhop, appsec, modsecurity, bouncer), a Yaegi run of the deadline path, and the e2e scenarios that assert today's drop (mock AppSec `tests/e2e/mock/scenarios/appsec/run.sh`; real e2e for ModSec if it has an HTTP/2-without-length case). Add e2e coverage for restic-shape requests (HTTP/2, no `Content-Length`) through ModSec.
- OpenSpec change updating the failure-action specs of both legs, the body forwarding/limit specs, and the wafhop spec if one exists.
- Docs (README was split into `docs/` by #225 — put each item where that tree says): the new deadline key(s); `appsecBodyLimit <= 0` now means 10 MiB; a section on configuring applications with streaming request bodies (gRPC client/bidi streaming, Connect streaming, long uploads) via `bouncerActionRules` `bypassAppsec`, YAML examples, and the trade-off; that stripping `Content-Length` no longer skips inspection on either leg; failure-modes tables updated.
- PR in **English** to `master`. Title MUST start with `[NOMERGE] ` (the owner wants to review before merging), followed by the usual gitmoji title. The description MUST explain why not upstream #407 / #434 / the "set `crowdsecAppsecUnreadableBodyBlock: false`" fallback (re-use #204's verified analysis), and that it supersedes #204.

## Out of scope

- Partial inspection of bodies over the AppSec limit (decision 5).
- GET/HEAD body forwarding policy.
- FailureAction / BackOffAction defaults and gate behaviour (decision 9).
- Closing PR #204 (the owner decides after review).
