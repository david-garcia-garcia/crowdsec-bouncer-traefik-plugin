# Requirement
IssueKey: 2026-11-14-appsec-unknown-length-body
Source: caller spec (issueHost local), copied verbatim below from `ticket/source.md`. Grounded sections (`## Current (code)`, `## Out of scope` additions, `## Unknowns`, `## Tensions`) follow it under `# Grounding`.

---

# AppSec: inspect request bodies of unknown length instead of dropping them

Upstream issue: https://github.com/maxlerebourg/crowdsec-bouncer-traefik-plugin/issues/405
("Silent 403 on HTTP/2 requests with an empty body (restic repo creation) — crowdsecAppsecUnreadableBodyBlock defaults to true").
Upstream candidate fixes, both OPEN and not merged:
- https://github.com/maxlerebourg/crowdsec-bouncer-traefik-plugin/pull/407 ("inspect an unreadable body that ends in time instead of dropping it")
- https://github.com/maxlerebourg/crowdsec-bouncer-traefik-plugin/pull/434 ("buffer non-streaming HTTP/2+ request bodies without Content-Length")

The delivery card and the PR MUST reference upstream issue #405 by URL.

## Problem (verified in this fork on master)

1. `pkg/appsec/query.go` `isBodyUnreadable` classifies any HTTP/2 or HTTP/3 request with a body and `ContentLength < 0` (no `Content-Length` header) as "unreadable" without trying to read it. `newAppsecBodyRequest` then returns `appsecQuery:unreadableBody dropped` for POST, PUT and PATCH unless `bouncerAppsecFailureAction` is `passthrough`. With the default `ban` the client gets a 403 and AppSec is never queried. `pkg/bouncer/bouncer.go` `applyAppsecServeHTTP` logs it at Debug only. Real-world victim: `restic init` against `rest-server` sends `POST <repo>/?create=true` over HTTP/2 with an empty body and no `Content-Length`.
2. The classification depends only on a client-controlled signal (a missing header; `Content-Length` is optional in HTTP/2/3). With `passthrough`, any client can strip `Content-Length` and the body reaches the backend without inspection: a WAF bypass. Upstream's suggested workaround (`crowdsecAppsecUnreadableBodyBlock: false`) is exactly that bypass.
3. DELETE: `isMethodWithForwardableBody` inspects a DELETE body when `Content-Length` is present, but an HTTP/2/3 DELETE without `Content-Length` is classified unreadable, is not a drop candidate (`isMethodWithBody` excludes DELETE), and is sent to AppSec headers-only even with `ban`. The body reaches the backend uninspected. `Test_appsecQuery_unreadableBodyDeleteNotDropped` locks this in. (Inferred from code and test; not reproduced end-to-end.)
4. Because one `bouncerAppsecFailureAction` covers AppSec outages/500s and the unreadable body, an operator cannot let restic through without also failing open when AppSec is down.

## Decisions (made by the human in chat; do not re-litigate)

1. Bodies of unknown length are read and inspected like any other body, capped at `appsecBodyLimit`, with a **total read deadline** (time to receive the body, not an idle timeout). The deadline MUST be configurable through a new public config key (not hardcoded). Name and default value: explore decides, following existing config naming (`appsecHttpTimeoutSeconds` style) and `skill:opd-commandments`.
2. When the deadline expires the request is blocked, **independently of `bouncerAppsecFailureAction`** (fail-closed; otherwise `passthrough` + a slowly dripped body is a bypass again). Status/remediation (403 ban path vs 408): explore decides and records why.
3. gRPC and Connect get **no special case** (no Content-Type classification). Unary calls end and are inspected; client/bidirectional streams hit the deadline and are blocked. Operators exclude genuine streaming routes explicitly with `bouncerActionRules` + `bypassAppsec`.
4. `appsecBodyLimit` values `<= 0` become 10 MiB (10485760). This removes "0 = unlimited" and replaces today's validation error for negative values.
5. Bodies larger than `appsecBodyLimit`: unchanged (first N bytes inspected, remainder forwarded uninspected).
6. Consequence of 1: a DELETE body without `Content-Length` is inspected like one with it. Removing `Content-Length` no longer reduces inspection for any method we inspect.
7. `bouncerAppsecFailureAction` goes back to meaning only "AppSec failed" (unreachable, 500, unexpected status, response read error). Do NOT reintroduce `crowdsecAppsecUnreadableBodyBlock` or any bool that lets an unreadable body pass.
8. The deadline block is logged above Debug (Info or Warn), with a message that tells the operator to exclude streaming routes with `bypassAppsec`.

Principle behind all of the above: a client-controlled signal may only lead to more inspection or to a block, never to less inspection.

## Deliverables

- Code + tests (unit, and the existing e2e/mock AppSec scenarios where they assert today's drop).
- OpenSpec change updating `core_plugin_appsec_failure-action` (unreadable body no longer under the failure action) and whatever spec owns body forwarding/limits.
- README: (a) the new deadline key; (b) `appsecBodyLimit <= 0` now means 10 MiB; (c) a section explaining **how to configure applications that need streaming request bodies** (gRPC client/bidirectional streaming, Connect streaming, other long-lived uploads): `bouncerActionRules` with `bypassAppsec` scoped by host/path/method/headers (e.g. `Content-Type: ^application/grpc`), with YAML examples, and the trade-off (that route is not WAF-inspected); (d) that stripping `Content-Length` no longer skips inspection.
- PR in **English** to `master`. The PR description MUST explain the problems of the upstream proposals:
  - #407: total wait hardcoded to 1 s (slow legitimate uploads without `Content-Length` are dropped; not configurable); `appsecBodyLimit <= 0` is an immediate drop (restic breaks again for operators with 0); keeps `crowdsecAppsecUnreadableBodyBlock: false` as headers-only forwarding, i.e. a client-triggerable WAF bypass; DELETE without `Content-Length` still goes headers-only; the timed-out read runs in a goroutine that is not cancelled (verify against the diff before stating).
  - #434: the path is chosen by the client-controlled `Content-Type`; with `false` (its README's advice for gRPC) any request that claims `application/grpc` skips body inspection; no plugin-side deadline, so non-gRPC streams hang until Traefik's `readTimeout` (60 s default; forever if 0), as its own README admits; gRPC unary calls are blocked by default; HTTP/2/3 DELETE/GET without `Content-Length` become headers-only.
  - Upstream maintainer's fallback ("set crowdsecAppsecUnreadableBodyBlock: false") is the bypass in Problem 2.

## Out of scope

- Partial inspection of bodies over `appsecBodyLimit` (decision 5).
- GET/HEAD body forwarding policy (`isMethodWithForwardableBody` excludes them today; unchanged).

---

# Grounding

Grounded against `origin/master` @ `db2204d0` (worktree HEAD at ground). Paths are repo-relative.

## Current (code)

- Problem 1, classification: `pkg/appsec/query.go` `isBodyUnreadable` (line 97) returns true when `Body` is non-nil, not `http.NoBody`, `ProtoMajor >= 2`, and `ContentLength < 0`. No read is attempted.
- Problem 1, drop: `pkg/appsec/query.go` `newAppsecBodyRequest` (line 255) returns `resultForFailureActionErr(pol.FailureAction, "appsecQuery:unreadableBody dropped")` when `isMethodWithBody` (POST, PUT, PATCH; line 109) holds and the effective failure action is not `passthrough`; otherwise it sends a bodyless GET to AppSec.
- Problem 1, logging: `pkg/bouncer/bouncer.go` `applyAppsecServeHTTP` (line 441) logs a non-disconnect, non-captcha `Query` error at Debug (line 467), then bans with `ReasonAPPSEC` / `headerReasonAppsecFailure` / `OriginPluginAppsecFailure`.
- Problem 2, passthrough bypass: `pkg/appsec/query.go` line 259 — with `passthrough`, an unreadable POST/PUT/PATCH body goes to AppSec as a bodyless GET; the body reaches origin uninspected.
- Problem 3, DELETE: `pkg/appsec/query.go` `isMethodWithForwardableBody` (line 121) includes DELETE for readable bodies; the unreadable branch (line 255) runs first and sends DELETE headers-only regardless of failure action. Locked by `pkg/appsec/zzz_query_test.go` `Test_appsecQuery_unreadableBodyDeleteNotDropped` (line 366).
- Problem 4, one action for two causes: `openspec/specs/core_plugin_appsec_failure-action/spec.md` Requirement "One action covers 500, unreachable, and unreadable body" (line 22) and scenarios "Unreadable body passthrough still queries AppSec" (line 42), "Unreadable body ban" (line 46), "Unreadable DELETE is not dropped" (line 58).
- Decision 1, readable-body path (cap, buffer, restore): `pkg/appsec/query.go` lines 261–279 (`io.LimitReader` only when `appsecBodyLimit > 0`, `io.ReadAll`, `io.MultiReader` restore). No read deadline exists on this path.
- Decision 1, existing timeout key naming: `pkg/configuration/configuration.go` `AppsecHTTPTimeoutSeconds` (`appsecHttpTimeoutSeconds`, line 68; default 10 at line 206).
- Decision 1, new deadline config key: not found (to be added).
- Decision 2, deadline block independent of failure action: not found (no deadline exists).
- Decision 2, client-gone classification a deadline could collide with: `pkg/appsec/query.go` `isClientGoneBodyReadErr` (line 102) maps `context.Canceled`, `context.DeadlineExceeded`, and `io.ErrUnexpectedEOF` to `ErrClientDisconnected`, which `pkg/bouncer/bouncer.go` `applyAppsecServeHTTP` routes to `handleClientDisconnectedServeHTTP` (no ban, no FailureAction).
- Decision 3, gRPC/Connect special case: not found (no Content-Type classification in `pkg/appsec/query.go`).
- Decision 3, operator escape hatch: `pkg/httprule/action.go` `ActionBypassAppsec` (line 14); spec `openspec/specs/core_plugin_middleware_bouncer/spec.md`; README `bouncerActionRules` description (README.md lines 659–670).
- Decision 4, `appsecBodyLimit` default: `pkg/configuration/configuration.go` line 203 (`10485760`).
- Decision 4, negative-value validation error: `pkg/configuration/configuration.go` line 819 (`AppsecBodyLimit: cannot be less than 0`).
- Decision 4, "0 = unlimited": `pkg/appsec/query.go` line 265 (cap only when `> 0`); spec `openspec/specs/core_plugin_appsec_client/spec.md` Requirement "Zero body limit forwards the full body" (line 62).
- Decision 4, wiring of the limit into the client: `pkg/appsec/client.go` line 84; `pkg/appsec/session.go` line 42 (`BodyLimit` in the reclaim session identity).
- Decision 5, oversize bodies (first N bytes inspected, remainder forwarded uninspected): `pkg/appsec/query.go` lines 265–275 (`LimitReader` + `MultiReader` restore).
- Decision 6, DELETE parity: `pkg/appsec/query.go` line 121 (forward set) vs line 109 (drop set); spec `openspec/specs/core_plugin_appsec_client/spec.md` line 102 ("DELETE is in the forward set and MUST NOT enter the drop set").
- Decision 7, `bouncerAppsecFailureAction`: `pkg/configuration/configuration.go` line 82; removal of the old bools recorded at `openspec/specs/core_plugin_appsec_failure-action/spec.md` line 125 (`crowdsecAppsecUnreadableBodyBlock` is already gone from the config struct).
- Decision 8, log level: `pkg/bouncer/bouncer.go` line 467 (Debug today).
- Deliverable, unit tests asserting today's drop/classification: `pkg/appsec/zzz_query_test.go` `Test_isBodyUnreadable` (line 43), `Test_appsecQuery_dropUnreadableBody` (line 96), `Test_appsecQuery_unreadableBodyGetNotDropped` (line 120), `Test_appsecQuery_unreadableBodyDeleteNotDropped` (line 366).
- Deliverable, e2e mock scenarios for HTTP/2 without Content-Length: `tests/e2e/mock/scenarios/appsec/run.sh` lines 41–46 (GET and POST with `--http2-prior-knowledge -H "Content-Length:"`, both assert 403).
- Deliverable, OpenSpec owners: `openspec/specs/core_plugin_appsec_failure-action/spec.md` (failure action); `openspec/specs/core_plugin_appsec_client/spec.md` (body forwarding and limits: "Zero body limit forwards the full body" line 62, "Readable body forwards only on body-bearing methods" line 101).
- Deliverable, README: `AppsecBodyLimit` variable text README.md lines 619–620 ("`0` means no limit"); bot-detection paragraph README.md line 155 ("`0` means no limit"); 10 MB warning README.md line 530; failure-action section README.md lines 494–500; `appsecHttpTimeoutSeconds` README.md line 629; section on streaming request bodies: not found.
- Devdocs describing today's behavior: `knowledge/devdocs/core_plugin_appsec.md` lines 33, 69–71 (unreadable drop; "Do not collapse" the two method predicates).
- Upstream PR #407 / #434 diffs: not found in this tree (external).

## Out of scope

- Everything under the spec's own `## Out of scope` above.
- Inferred extras, not taken: changing `appsecHttpTimeoutSeconds` semantics; a per-route deadline override (operators use `bypassAppsec`); a Content-Type allow/deny list; the AppSec response-body cap (`appsecResponseBodyLimit`); the LAPI failure action; changes to the readable-body client-disconnect contract beyond what the deadline needs.
- Reintroducing `crowdsecAppsecUnreadableBodyBlock` or any bool that lets an unreadable body pass (forbidden by decision 7).

## Unknowns

- Name and default of the new deadline key (explore decides; decision 1).
- Status/remediation on deadline expiry: 403 ban path vs 408 (explore decides and records why; decision 2).
- Whether the deadline bounds only unknown-length bodies or every forwarded body (a slowly dripped body with a `Content-Length` header). The spec scopes decision 1 to "bodies of unknown length"; the principle line suggests the same fail-closed rule, but it is not stated.
- How the deadline is enforced without leaving a blocked read goroutine (request context, `http.ResponseController` read deadline, or a reader wrapper), and how that behaves under Traefik/Yaegi. Not measured.
- Whether a deadline-driven read error would surface as `context.DeadlineExceeded` and be classified by `isClientGoneBodyReadErr` as a client disconnect (silent non-block, contradicting decision 2). Inferred from code, not reproduced.
- Whether the new key belongs in the AppSec reclaim identity (`pkg/appsec/session.go`; `openspec/specs/core_plugin_appsec_client/spec.md` "AppSec is reclaimed by listener identity" lists body limit and timeout).
- Fate of `isBodyUnreadable` / `isMethodWithBody` after the change (removed vs repurposed) and the matching devdocs.
- What the mock AppSec behind `tests/e2e/mock/scenarios/appsec/run.sh` answers once the HTTP/2 POST body `test` is actually forwarded (today's 403 is the plugin's drop, not necessarily an AppSec verdict). The GET case stays headers-only.
- Whether `tests/e2e/real` or `tests/e2e/go` assert the drop (a search for `unreadable` / `Content-Length` matched only the mock scenario).
- The PR-description claims about upstream #407 / #434 (hardcoded 1 s, uncancelled goroutine, `application/grpc` path, README admissions) must be checked against their diffs before they are stated; the spec itself flags the #407 goroutine claim as "verify against the diff".
- Go's HTTP/2 server behavior for restic's `POST ?create=true` (empty body, END_STREAM, no `Content-Length`): assumed to read EOF immediately; not reproduced here.

## Tensions

- Spec vs live contract: decision 7 contradicts `openspec/specs/core_plugin_appsec_failure-action/spec.md` "One action covers 500, unreachable, and unreadable body" and its three unreadable scenarios. Expected; the deliverable OpenSpec change rewrites them.
- Spec vs live contract: decision 4 contradicts `openspec/specs/core_plugin_appsec_client/spec.md` "Zero body limit forwards the full body", README.md lines 155 and 619–620 ("`0` means no limit"), and the validation error at `pkg/configuration/configuration.go` line 819.
- Spec vs live contract: decision 6 makes the "distinct drop set" sentence in `openspec/specs/core_plugin_appsec_client/spec.md` line 102 and the "Do not collapse them" rule in `knowledge/devdocs/core_plugin_appsec.md` line 69 obsolete.
- Spec vs tests: `Test_appsecQuery_unreadableBodyDeleteNotDropped` and `Test_appsecQuery_dropUnreadableBody` lock in the behavior the spec removes.
- Decision 2 vs code: `isClientGoneBodyReadErr` already maps `context.DeadlineExceeded` to "client disconnected" (no block); a context-deadline implementation that reuses it would fail open.
- Decision 4 vs existing operators: `appsecBodyLimit: 0` (full body today) becomes a 10 MiB cap after upgrade; the README has to say so.
- PR comments: none (PR #204 has no conversation or review comments), so no `RETHINK` rows.
