# Requirement
IssueKey: 2026-11-23-waf-unknown-length-body

The caller spec below is copied in full from `ticket/source.md` (issueHost local). The grounded sections after it were added by prepare against `origin/master` @ `aa6d0be3`.

---

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

---

## Current (code)

Grounded on `origin/master` @ `aa6d0be3`. Line numbers are at that commit.

Problem 1–3 (classification and drop paths):
- Unknown-length classifier: `pkg/wafhop/body.go:44-48` `IsBodyUnreadable` = `HasBody && ProtoMajor >= 2 && ContentLength < 0`. HTTP/1.1 chunked (`ContentLength < 0`, `ProtoMajor` 1) is not in this class and is read today with no plugin deadline.
- Drop method set: `pkg/wafhop/body.go:50-59` `IsMethodWithBody` (POST, PUT, PATCH; DELETE deliberately absent).
- AppSec drop: `pkg/appsec/query.go:262-268` `newAppsecBodyRequest` returns `errUnreadableBody` unless the effective failure action is `passthrough`; with `passthrough` (or DELETE) it sends a headers-only GET.
- AppSec drop dispatch: `pkg/appsec/query.go:118-126` `Query` (check at `:120`) turns `errUnreadableBody` into `ErrGateSkip` while the gate backs off, else `resultForFailureAction(..., "appsecQuery:unreadableBody dropped")`.
- AppSec forward set (includes DELETE): `pkg/appsec/query.go:102-113` `isMethodWithForwardableBody`.
- ModSec drop: `pkg/modsecurity/inspect.go:46-55` `Inspect` returns `ErrUnavailable` ("streamed %s body without a length") unless the effective ModSec failure action is `passthrough`, `ErrGateSkip` while backing off; with `passthrough` the sidecar gets headers only.
- AppSec failure-action default `ban`: `pkg/configuration/configuration.go:223-229` (`EffectiveFailureAction`), `:262` (`CreateConfig`).
- ModSec failure-action default `passthrough`: `pkg/configuration/configuration.go:231-238` (`EffectiveModsecFailureAction`), `:271` (`CreateConfig`).
- AppSec failure → ban response: `pkg/bouncer/bouncer_serve_appsec.go:85-108` `answerAppsecQueryError` / `banAppsecFailure`.
- ModSec failure → failure action: `pkg/bouncer/bouncer_serve_modsec.go:55-73` `applyModsecFailureAction`.

Decision 1 (shared read, deadline, reuse):
- Shared read: `pkg/wafhop/body.go:87-103` `ReadBody` (`TruncateAtLimit` / `RejectOverLimit`); no deadline of any kind.
- Reuse of a body the first leg buffered: `pkg/wafhop/body.go:108-110` (`bufferedBody`, `complete && !touched`).
- Deadline config key (`appsecBodyReadTimeoutSeconds` / `modsecBodyReadTimeoutSeconds` or shared): not found. Sibling timeout keys: `pkg/configuration/configuration.go:78` `AppsecHTTPTimeoutSeconds`, `:170` `ModsecHTTPTimeoutSeconds`.
- `http.ResponseController` / `SetReadDeadline`: not found in `pkg/`.
- Leg entry points that would receive the deadline: `pkg/appsec/query.go:269-277` (AppSec `ReadBody` call), `pkg/modsecurity/inspect.go:56-61` (ModSec `ReadBody` call).

Decision 2 (deadline block):
- Client-gone classification: `pkg/wafhop/body.go:61-71` `IsClientGone` treats `context.DeadlineExceeded` and `io.ErrUnexpectedEOF` (and a canceled request context) as a disconnect → `ErrClientDisconnected`.
- Body read failure contract: `pkg/wafhop/body.go:21-24` `ErrClientBodyRead`; answered 400 with header `error:client-body-read`, no ban, no failure action, at `pkg/bouncer/bouncer_serve_waf.go:23-27`; dispatched from `pkg/bouncer/bouncer_serve_appsec.go:97-99` and `pkg/bouncer/bouncer_serve_modsec.go:51-53`.
- Deadline ban path / header `ban:appsec-body-timeout` / metrics origin `plugin:appsec_body_timeout`: not found (exists only on #204's branch).

Decision 3 (streaming exclusions):
- `bypassAppsec`: `pkg/httprule/action.go:16`.
- ModSec equivalent: exists — `bypassModsec` at `pkg/httprule/action.go:19` (`SkipModsec` `:204`).
- `bypassAppsec` never skips AppSec on `/crowdsec-internal/challenge/`: `pkg/bouncer/bouncer.go:202-212`.
- gRPC / Connect Content-Type classification: not found (none today).

Decisions 4–5 (body limits):
- `appsecBodyLimit` default 10485760: `pkg/configuration/configuration.go:252`; `< 0` rejected: `:959-961`; `0` = no cap: `pkg/wafhop/body.go:80-81` and comment `pkg/appsec/query.go:271`.
- `modsecBodyLimit` default 8 MiB: `pkg/configuration/configuration.go:64-65,317`; `< 1` rejected: `:984-986`; over-limit 413: `pkg/bouncer/bouncer_serve_modsec.go:44-47`.
- AppSec over-limit truncation (first N bytes, rest to origin): `pkg/wafhop/body.go:96-102` (`TruncateAtLimit`).

Decision 8 (logging):
- Debounced logger: `pkg/logger/debounce.go:24` `Debounced`.
- Current drop logging: Debug only — `pkg/bouncer/bouncer_serve_appsec.go:103`, `pkg/bouncer/bouncer_serve_modsec.go:55`.

Specs that state today's rule:
- `openspec/specs/core_plugin_wafhop_shared-request/spec.md:8` (both legs; unreadable → failure action unless passthrough; gate skip while backing off).
- `openspec/specs/core_plugin_appsec_failure-action/spec.md:22-23` ("One action covers 500, unreachable, and unreadable body"), `:154` (unreadable body while backing off is a skip).
- `openspec/specs/core_plugin_modsecurity_inspect/spec.md:31` (`ErrUnavailable` covers a streamed body without a length).
- `openspec/specs/core_plugin_appsec_client/spec.md:67-70` (`appsecBodyLimit` 0 = unlimited), `:106`, `:117` (DELETE not in the drop set).
- `openspec/specs/core_plugin_middleware_config-validation/spec.md:425` (`modsecBodyLimit` ≥ 1).

Docs (README split into `docs/`):
- Unreadable-body rule: `docs/failure-modes.md:142`, `docs/how-it-works.md:121`, `docs/modsecurity.md:35`, `docs/configuration.md:410` (`bouncerModsecFailureAction`).
- `appsecBodyLimit` "0 means no limit": `docs/configuration.md:622-626`, `docs/concepts.md:84`.
- Failure-modes table row on body limits: `docs/failure-modes.md:140`.
- Section on streaming request bodies (gRPC / Connect / long uploads): not found.

Tests:
- Unit tests referencing the unreadable class: `pkg/wafhop/zzz_body_test.go`, `pkg/appsec/zzz_query_test.go`, `pkg/appsec/zzz_gate_test.go`, `pkg/modsecurity/zzz_inspect_test.go`.
- Mock e2e asserting today's drop: `tests/e2e/mock/scenarios/appsec/run.sh:48-52` (HTTP/2, no `Content-Length`, body `test` → 403; both lines are POSTs since `curl -d` implies POST).
- Real e2e ModSec HTTP/2-without-length case: not found (`tests/e2e/real/modsec.Tests.ps1`, `tests/e2e/real/waf_dual.Tests.ps1` have no HTTP/2 case).
- Yaegi harness: `pkg/yaegitest/interpreter.go` (pattern: `pkg/bouncer/zzz_yaegi_leg_binding_test.go`).
- Traefik in e2e: `v3.7.19` in `tests/e2e/real/config/docker-compose.test.yml:5` and `tests/e2e/mock/lib/common.sh:17` (`tests/e2e/mock/README.md:30` still says `v3.7.1`).

## Out of scope

From the ticket (§ Out of scope, decision 9):
- Partial inspection of bodies over the AppSec limit.
- GET/HEAD body forwarding policy.
- FailureAction / BackOffAction defaults and gate behaviour (`2026-11-23-backoff-action-per-leg`).
- Closing PR #204.

Inferred extras, listed and not taken:
- A plugin deadline on bodies **with** a declared `Content-Length` (slow uploads). The ticket names bodies of unknown length only.
- Fixing the stale Traefik version in `tests/e2e/mock/README.md:30`.
- Any change to upstream (`maxlerebourg/...`) or a comment on issue #405.

## Unknowns

Explore owns these.
- Whether the deadline also bounds HTTP/1.1 chunked bodies (`ContentLength < 0`, `ProtoMajor` 1). "Bodies of unknown length" covers them literally; today they are read with no deadline (`pkg/wafhop/body.go:44-48` excludes them from the unreadable class). #204 decided yes.
- Whether `http.ResponseController.SetReadDeadline` reaches the HTTP/1.1 connection through Traefik v3.7.19's writer chain. #204 measured "no" on v3.7.11; not re-measured.
- HTTP/3 behaviour of the deadline cut (not measured by #204).
- How a deadline-cut read surfaces through `wafhop.IsClientGone` (`pkg/wafhop/body.go:61-71`): if the cut error is `context.DeadlineExceeded` or the request context is canceled, today's code classifies it as a disconnect (no response). #204 used a timer flag checked first.
- One key per leg vs one shared key, and how the key enters each leg's reclaim identity (`pkg/appsec/session.go`, `pkg/modsecurity/session.go`).
- Status/remediation of the deadline block: #204's ban path vs master's `ErrClientBodyRead` → 400 contract; whether the ModSec deadline needs its own header reason / metrics origin.
- Which deadline and limit govern the shared read when both legs run on one request with different limits (AppSec truncates at 10 MiB, ModSec rejects over 8 MiB by default) and the body has unknown length.
- Yaegi v0.16.1 support for the chosen deadline mechanism (`time.AfterFunc`, `http.ResponseController`) in `pkg/wafhop`.
- How the restic shape (HTTP/2, empty body, no `Content-Length`) is produced in the real e2e for ModSec (curl vs a Go client).
- External claims carried from the ticket, not re-measured here: upstream #405 / #407 / #434 state and diffs; "#204 conflicts with `master` in 19 files" (GitHub reports #204 open with `mergeable_state: dirty`; the file count was not measured).

## Tensions

- Decision 7 removes `IsBodyUnreadable` / `IsMethodWithBody` and their drop paths; with them goes the spec rule "an unreadable body while the gate is backing off is a skip" (`openspec/specs/core_plugin_appsec_failure-action/spec.md:154`, `openspec/specs/core_plugin_wafhop_shared-request/spec.md:8`). Decision 9 says do not change gate behaviour. Removing the class is the ask; that gate-skip sentence disappears as a consequence, not as a gate change.
- Decision 2 (block on deadline, fail-closed) vs master's `ErrClientBodyRead` contract (400, no ban, no failure action — `pkg/bouncer/bouncer_serve_waf.go:23-27`). A deadline cut is a body read failure; the ticket requires it to block independently of the failure action. Explore decides whether that is the 400 path or a ban path.
- Decision 3 asks for "the ModSec equivalent [of `bypassAppsec`], if one exists": it exists (`bypassModsec`, `pkg/httprule/action.go:19`), so the streaming-route docs need both actions (or `bypass`). The deliverable text names `bypassAppsec` only.
- Decision 4 changes `appsecBodyLimit <= 0` to 10 MiB, contradicting current docs (`docs/configuration.md:622-626`, `docs/concepts.md:84`) and spec (`openspec/specs/core_plugin_appsec_client/spec.md:67-70`), which say `0` sends the whole body. Intended by the ticket; docs and spec move with it.
- `wafhop.ReadBody` documents "limit 0 or less means no cap" (`pkg/wafhop/body.go:80-81`); after decision 4 AppSec never passes `<= 0`, and ModSec never could. Whether the shared function keeps an uncapped mode is a design question for explore.
- The ticket cites #204's decisions as "the starting point" while saying the code they cite has moved; #204's `Query` signature change (third `*http.ResponseController` argument) targets `pkg/appsec` only, while decision 1 puts the read and deadline in `pkg/wafhop` for both legs.
