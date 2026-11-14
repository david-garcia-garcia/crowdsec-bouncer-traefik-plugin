# Explore

IssueKey: 2026-11-14-appsec-unknown-length-body
Grounded on worktree HEAD `fcdf5e51` (dest `master` @ `db2204d0`). Unattended run; every open question is `assumed` or `resolved`.

## Concepts

### Units this change touches

| Unit | Path | Job today |
|------|------|-----------|
| `newAppsecBodyRequest` | `pkg/appsec/query.go:253` | Chooses headers-only GET or body-copy POST toward AppSec; drops an "unreadable" POST/PUT/PATCH (`:255-258`); caps a readable body only when `appsecBodyLimit > 0` (`:265`). |
| `isBodyUnreadable` | `pkg/appsec/query.go:97` | HTTP/2+ body with `ContentLength < 0` → unreadable. Classification only, no read. |
| `isMethodWithBody` | `pkg/appsec/query.go:109` | Drop set (POST/PUT/PATCH) for unreadable bodies. |
| `isMethodWithForwardableBody` | `pkg/appsec/query.go:121` | Forward set (POST/PUT/PATCH/DELETE) for readable bodies. Stays. |
| `isClientGoneBodyReadErr` / `ErrClientDisconnected` | `pkg/appsec/query.go:102`, `:57` | `context.Canceled`, `context.DeadlineExceeded`, `io.ErrUnexpectedEOF` → client disconnected (no ban, no FailureAction). |
| `Client.Query` | `pkg/appsec/query.go:144` | AppSec round-trip; signature `Query(req clientrequest.Request, pol Policy)`. |
| `appsec.Prepare` / `appsec.New` / `identityFrom` | `pkg/appsec/client.go:44,67`, `pkg/appsec/session.go:32` | Fill AppSec defaults on the snapshot; store knobs on the Client; reclaim ownership key (includes `BodyLimit`, `HTTPTimeoutSeconds`). |
| `applyAppsecServeHTTP` | `pkg/bouncer/bouncer.go:441` | Maps `Query` result to relay / ban / captcha / disconnect; any other error → Debug log + `ban:appsec-failure` (`:466-470`). Only owner of `rw`. |
| Remediation header + metrics origin | `pkg/bouncer/remediation_header.go:10-27,55`, `pkg/lapi/client_metrics.go:22-30` | Closed header reason tokens and plugin drop origins. |
| Config | `pkg/configuration/configuration.go:65-68` (fields), `:203,206` (defaults), `:783-805` (`requiredInt0` / `requiredInt1`), `:819` (duplicate `AppsecBodyLimit < 0`) | Public keys, defaults, validation. |
| Mock AppSec e2e | `tests/e2e/mock/scenarios/appsec/{run.sh,dynamic.yml}`, mock at `tests/e2e/mock/mocklapi/main.go:218-245` | Real Traefik binary + plugin under Yaegi; mock AppSec answers 403 when the forwarded body contains `a=0`, else 200. `appsecBodyLimit: 4`. |

### How they connect

```
Traefik entrypoint (http.Server: readTimeout, h1 / h2 / h3)
   │ rw, *http.Request (Body = net/http body | h2 pipe | quic stream)
   ▼
bouncer.ServeHTTP ─► serveAppSec ─► applyAppsecServeHTTP(rw, req, match)      [pkg/bouncer]
                                       │ Query(req, pol [+ read-deadline control from rw])
                                       ▼
                        appsec.Client.Query ─► newAppsecForwardRequest ─► newAppsecBodyRequest   [pkg/appsec]
                                                         │
             today:  unreadable? ──yes──► drop (FailureAction) or headers-only GET
                          │no
                          ▼
                     forwardable method? ─► ReadAll(LimitReader if limit>0) ─► POST copy; MultiReader restore
             after:  forwardable method? ─► ReadAll(LimitReader(limit)) [+ deadline when ContentLength < 0]
                                              ├─ timer fired      ─► ErrBodyReadTimeout ─► bouncer ban (new reason/origin, WARN)
                                              ├─ client gone      ─► ErrClientDisconnected (unchanged)
                                              └─ ok               ─► POST copy; MultiReader restore
```

### Call sites (enumerated; roots `pkg/**`, `plugin.go`, root `zzz_*_test.go`, `tests/e2e/**`)

- `Client.Query`: 1 production call (`pkg/bouncer/bouncer.go:458`); 43 test calls in `pkg/appsec` (`zzz_failure_action_test.go` 17, `zzz_query_test.go` 20, `zzz_nil_transport_test.go` 3, `zzz_test_helpers.go` 2, `zzz_timeout_test.go` 1). Pattern `\.Query\(` excluding `URL.Query`.
- `isBodyUnreadable`: 1 production (`query.go:255`), 1 test (`zzz_query_test.go:65`). `isMethodWithBody`: 1 production (`query.go:256`), 1 test (`zzz_query_test.go:548`).
- `AppsecBodyLimit` readers: `pkg/appsec/client.go:84`, `pkg/appsec/session.go:42`, `pkg/configuration/configuration.go:203,784,819`; tests `pkg/appsec/zzz_query_test.go:321` (zero-limit test), `pkg/appsec/zzz_session_test.go:49`, `zzz_traefikemulator_test.go:304`.
- Unit tests that lock today's drop: `Test_isBodyUnreadable` (`zzz_query_test.go:43`), `Test_appsecQuery_dropUnreadableBody` (`:96`), `Test_appsecQuery_unreadableBodyGetNotDropped` (`:120`), `Test_appsecQuery_unreadableBodyDeleteNotDropped` (`:366`), `Test_appsecQuery_zeroBodyLimitForwardsPost` (`:307`). Real-stack Pester (`tests/e2e/real/*.Tests.ps1`) has no unknown-length assertion (searched `http2|chunk|content-length|stream|body`).

### Reproduce

- Unit: `go test ./pkg/appsec/ -run nreadable -v` → `Test_isBodyUnreadable`, `Test_appsecQuery_dropUnreadableBody`, `Test_appsecQuery_unreadableBodyGetNotDropped`, `Test_appsecQuery_unreadableBodyDeleteNotDropped` PASS on HEAD, i.e. today's drop / headers-only behaviour is what the tree asserts.
- Restic request shape (Go net/http probe, Go 1.25.6, unencrypted HTTP/2, client body = pipe closed with no data): server sees `ContentLength -1`, `Body != http.NoBody`, and `io.ReadAll` returns 0 bytes, nil error, immediately. That is exactly the input `isBodyUnreadable` classifies as unreadable and `newAppsecBodyRequest` drops with the default `ban`; reading it costs nothing. Probe: scratch `probe/main.go` (not in tree); results recorded in `knowledge/research/std_go_net-http_body-read-deadline/`.
- End-to-end restic against Traefik: **not reproduced** here (no Traefik run in this phase); the mock e2e scenario `run.sh:41-46` already asserts 403 for HTTP/2 POST without `Content-Length`.

### Measured: how a body read can be cut at a deadline (Go 1.25.6 net/http)

Probe deadline 300 ms, client body never ends (`knowledge/research/std_go_net-http_body-read-deadline/`):

| Mechanism | HTTP/2 | HTTP/1.1 chunked | Error the read returns |
|-----------|--------|------------------|------------------------|
| `time.AfterFunc` → `req.Body.Close()` | read returns at 300 ms | **not cut**: `body.Close` waits on the mutex held by `Read` (`transfer.go` `body.Read`/`Close`); read returned only when the client ended the body (3 s) | h2: `body closed by handler` |
| `time.AfterFunc` → `http.NewResponseController(rw).SetReadDeadline(time.Now())` | 300 ms | 300 ms | wrapped `os.ErrDeadlineExceeded` (`i/o timeout`); `errors.Is(err, context.DeadlineExceeded)` = false |
| Traefik-style `http.Server.ReadTimeout` (no plugin deadline) | at ReadTimeout | at ReadTimeout | wrapped `os.ErrDeadlineExceeded`; not `context.DeadlineExceeded` → today `appsecQuery:GetBody` → ban |
| Read in a goroutine, handler gives up (upstream #407 shape) | background read ends when the handler returns and the stream is closed | handler returns at 300 ms but the 403 reaches the client only at 3 s (background `Read` holds the body mutex the server needs) | h2: `stream error ... NO_ERROR` |

Not measured: HTTP/3 (quic-go), Traefik's own `ResponseWriter` wrappers (whether `http.ResponseController` reaches `SetReadDeadline` through them), Yaegi v0.16.1. Open question rows below carry these.

### Outside facts used

- `knowledge/research/std_go_net-http_body-read-deadline/` (created this run, delegated) — per-protocol abort mechanism and error types.
- `knowledge/research/std_go_net-http_body-read-errors/` (corrected this run: server read deadlines are `os.ErrDeadlineExceeded`, not `context.DeadlineExceeded`).
- `knowledge/research/std_go_io_limit-reader/` — `LimitReader(r, n<=0)` is immediate EOF (why `<= 0` must be normalized before the cap).
- `knowledge/research/ext_yaegi_interp_select-cases/` — Yaegi v0.16.1 shares a `select` case list across goroutines: no `select` on the request path. In-tree Yaegi rules: `pkg/appsec/client.go:32` (`atomic.Value`, not `atomic.Pointer[T]`), `pkg/lapi/client.go:71` (no `atomic.Bool`/`atomic.Int64`), `pkg/reclaim/default.go:40` (`AfterFunc` chosen because of the `_select` hang).
- Upstream PRs #407 / #434 diffs and issue #405 comments via GitHub MCP (below). Ticket-scoped evidence; kept here, not in `knowledge/research/`.

### Upstream proposals — verified against their diffs

Fetched 2026-11-14 with `pull_request_read get_diff`. Both PRs are **open** (`search_pull_requests`). Heads: #407 `45deb7f4` (fix commit `64a8a475`), #434 `6a211c47`. Upstream base context visible in the #407 diff: the readable branch is `case bouncer.appsecBodyLimit > 0 && httpReq.Body != nil:` (any method, so upstream forwards GET and DELETE bodies that carry `Content-Length`; limit `0` means no body is forwarded).

**#407 "inspect an unreadable body that ends in time instead of dropping it"**

1. Hardcoded total wait — **confirmed**. `unreadableBodyWait = time.Second` (const in `bouncer.go`); README: "waits up to 1 second". Not configurable; a legitimate upload without `Content-Length` slower than 1 s to reach the end (or the limit) is dropped.
2. `appsecBodyLimit <= 0` is an immediate drop — **confirmed**. `readBodyWithin`: `if limit <= 0 { return nil, errUnreadableBody }`; with the default block the request is dropped without reading, so restic breaks again for operators with `0`.
3. `crowdsecAppsecUnreadableBodyBlock: false` keeps headers-only forwarding — **confirmed**. `if !bouncer.appsecUnreadableBodyBlock || !isMethodWithBody(httpReq.Method) { req = GET headers-only }`. Any client that omits `Content-Length` on HTTP/2/3 skips body inspection when the operator set `false`.
4. DELETE without `Content-Length` still headers-only — **confirmed** (same line: `!isMethodWithBody` covers DELETE; the bounded read only runs for POST/PUT/PATCH). Upstream forwards a DELETE body that has `Content-Length`, so stripping the header reduces inspection.
5. Timed-out read goroutine not cancelled — **confirmed, with a correction on duration**. The goroutine runs `io.ReadAll(io.LimitReader(body, limit))`; on timeout nothing closes the body or cancels the read. Measured on Go's HTTP/2 server: that read returns as soon as the handler returns and the server closes the stream (it ends together with the 403), so it is not a long-lived leak there. It still reads concurrently with nothing owning its result, and the bytes it already read are discarded. HTTP/3 not measured. #407 never uses this path on HTTP/1.1 (`isBodyUnreadable` needs `ProtoMajor >= 2`); the probe shows the same shape on HTTP/1.1 would hold the response until the client finishes the body. Do not claim "left running indefinitely".

**#434 "buffer non-streaming HTTP/2+ request bodies without Content-Length"**

1. Path chosen by client-controlled `Content-Type` — **confirmed**. `isStreamingContentType`: `application/grpc`, `application/grpc+*`, `application/grpc-*`, `application/connect+*`.
2. With `false`, any request claiming `application/grpc` skips body inspection — **confirmed**. Those requests stay "unreadable" and go headers-only when the flag is `false`; the README tells gRPC users to set `false`.
3. No plugin-side deadline — **confirmed**. Other bodies without `Content-Length` are read until EOF or the limit; its README: "the plugin waits for a body that never ends, and the request fails after Traefik's `readTimeout` (60 seconds by default), whatever this option". "Forever if 0" follows from Go `http.Server.ReadTimeout` ("A zero or negative value means there will be no timeout", `net/http/server.go`); that Traefik passes its `readTimeout` into that field is inference, not read in Traefik source.
4. gRPC unary blocked by default — **confirmed** (README: "gRPC, unary calls included: blocked with the default `true`").
5. HTTP/2/3 DELETE/GET without `Content-Length` become headers-only — **confirmed**. `isBodyUnreadable` returns true for `!isMethodWithBody(method)`, and only POST/PUT/PATCH are drop candidates, so those go headers-only regardless of the flag, while upstream forwards the same bodies when `Content-Length` is present.

**Upstream fallback "set `crowdsecAppsecUnreadableBodyBlock: false`"** — **confirmed, attribution corrected**: posted on #405 by collaborator `mathieuHa` (2026-10-18), not by the repository owner. That setting is the bypass in Problem 2.

## Decisions

### Chosen seam / approach

- One read path: `newAppsecBodyRequest` reads every POST/PUT/PATCH/DELETE body (`isMethodWithForwardableBody`) through `io.LimitReader(body, appsecBodyLimit)`; the "unreadable" branch, `isBodyUnreadable` and `isMethodWithBody` are removed (decisions 1, 6, 7).
- A body of unknown length (`ContentLength < 0`: HTTP/1.1 chunked, HTTP/2/3 without `Content-Length`) gets a total read deadline from new key `appsecBodyReadTimeoutSeconds` (default `30`, `< 1` rejected). Bodies with a declared length keep today's behaviour (bounded by Traefik `readTimeout`, fail-closed).
- Deadline mechanism: `time.AfterFunc` armed before the capped read; on fire it calls `SetReadDeadline(time.Now())` on the per-request `http.ResponseController` built by the bouncer from `rw`, and closes the request body when the controller returns an error. After the read, `!timer.Stop()` is the "deadline fired" flag, checked **before** `isClientGoneBodyReadErr`. No goroutine, no `select`, no `sync/atomic` type (Yaegi v0.16.1 rules).
- Deadline outcome: new exported sentinel in `pkg/appsec` (proposed `ErrBodyReadTimeout`), not under `bouncerAppsecFailureAction`; bouncer serves the ban path (`bouncerRemediationStatusCode`, default 403, ban template, `ReasonAPPSEC`), header `ban:appsec-body-timeout`, usage-metrics origin `plugin:appsec_body_timeout`; WARN through `logger.Debounced` (5 s) naming `bypassAppsec`.
- `appsecBodyLimit <= 0` → `10485760`, normalized once in `appsec.Prepare` from a named default constant shared with `CreateConfig`; both `< 0` validation sites removed.
- The deadline knob lives on the AppSec `Client` and in its reclaim identity, next to `BodyLimit` and `HTTPTimeoutSeconds`.

### Rejected alternatives

- Read in a goroutine and stop waiting (upstream #407): leaves an unowned read; on HTTP/1.1 the 403 is held until the client ends the body (measured).
- `Body.Close()` alone as the abort: does not cut an HTTP/1.1 read (measured).
- `SetReadDeadline(now + d)` before the read, then clear it: clearing drops Traefik's own `readTimeout` deadline for the rest of an oversize body (`h2_bundle.go` `SetReadDeadline` zero → `st.readDeadline = nil`).
- `context.WithTimeout` on the request: a context does not unblock a body `Read`, and the classifier already maps `context.DeadlineExceeded` to client-gone.
- Content-Type classification (upstream #434): client-controlled; forbidden by decision 3.
- Deadline on bodies with a declared `Content-Length`: no bypass exists there today; it would add a new failure mode for slow legitimate uploads not asked for.
- HTTP 408 on expiry: invites automatic client retries of a request the plugin will block again, and bypasses the operator's ban status code, template, remediation header and metrics.
- Reusing `ban:appsec-failure` / `plugin:appsec_failure`: decision 7 reserves those for "AppSec failed".

### Live contract

Live. Specs that change: `core_plugin_appsec_failure-action` (drop the unreadable-body clauses and three scenarios), `core_plugin_appsec_client` (unknown-length read + deadline, body-limit default replaces "Zero body limit forwards the full body", drop-set sentence in "Readable body forwards only on body-bearing methods", identity key list), `core_plugin_middleware_bouncer` (serve the deadline block; header table row), `core_plugin_lapi_usage-metrics` (new plugin origin), `core_plugin_middleware_config-validation` (new key validation; `appsecBodyLimit` negative no longer rejected). Propose confirms placement with `skill:opd-speclibrarian`.

## Open questions

- Q: Does the deadline also bound HTTP/1.1 chunked bodies and slow bodies with a declared `Content-Length`?
  Rank: bounded asked — changes existing `newAppsecBodyRequest` (1 caller, `newAppsecForwardRequest`; roots `pkg/**`); decision 1 "Bodies of unknown length are read and inspected like any other body, capped at `appsecBodyLimit`, with a total read deadline"
  Decision: assumed — the deadline applies to every forwarded body whose length is unknown (`ContentLength < 0`), on every protocol, HTTP/1.1 chunked included: the protocol a client picks must not change how long the plugin waits (principle line). It does not apply to bodies with a declared `Content-Length`: there the client signal cannot reduce inspection today — a stalled body ends at Traefik `readTimeout` with `os.ErrDeadlineExceeded` → `appsecQuery:GetBody` → ban (measured error type), or the client disconnects (no origin call) — so a deadline there would only add failures for slow legitimate uploads. The deadline covers reading up to `appsecBodyLimit` bytes; once the limit is reached the read stops and the rest streams on uninspected (decision 5) with no plugin deadline.
  By: explore

- Q: How is the deadline told apart from a real client disconnect, given `isClientGoneBodyReadErr` maps `context.DeadlineExceeded` to client-gone, and how does it work under Yaegi?
  Rank: bounded incidental — widens `appsec.Client.Query` (1 production call `pkg/bouncer/bouncer.go:458` + 43 test calls in `pkg/appsec`, enumerated above) to receive the per-request read-deadline control; no criterion names that signature change, it is a means to decision 2
  Decision: assumed — classify by the plugin's own timer, not by error type: `fired := !timer.Stop()` after the capped `io.ReadAll`; `fired` → deadline sentinel regardless of the read error or success, checked before `isClientGoneBodyReadErr` (which stays unchanged). The timer callback calls `http.ResponseController.SetReadDeadline(time.Now())` (cuts HTTP/1.1 and HTTP/2, measured) and falls back to `Body.Close()` when the controller returns an error (cuts HTTP/2, measured; HTTP/3 assumed). The success path never touches the read deadline, so Traefik's `readTimeout` still bounds the remainder of an oversize body. Yaegi: only native `time.AfterFunc`, `Timer.Stop` and `net/http` calls; no goroutine of our own, no `select` (`ext_yaegi_interp_select-cases`), no `atomic.Bool`/`atomic.Pointer` (`pkg/lapi/client.go:71`). Measured errors on cut reads (`i/o timeout`, `body closed by handler`) are not `context.DeadlineExceeded`, so they could not have collided anyway; the timer flag makes the outcome explicit. Deviations row appended.
  By: explore

- Q: Does `http.ResponseController` reach `SetReadDeadline` through Traefik's `ResponseWriter` wrappers when the plugin runs under Yaegi v0.16.1, and does `Body.Close` cut an HTTP/3 read?
  Rank: additive incidental — fallback branch inside the new deadline helper; no criterion names it
  Decision: resolved — measured by implement. Yaegi v0.16.1 (`pkg/appsec/zzz_yaegi_body_read_timeout_test.go`): the deadline path runs and `SetReadDeadline` cuts an HTTP/1.1 chunked read at 1 s on a plain `net/http` server. Traefik v3.7.11 binary, plugin under Yaegi (mock e2e `tests/e2e/mock/scenarios/appsec/run.sh`, with and without access log): HTTP/2 without `Content-Length` is answered 403 at the deadline (access log 2002 ms for a 2 s timeout); an HTTP/1.1 chunked read is **not** cut, so the controller does not reach Traefik's HTTP/1.1 connection and `Body.Close` cannot cut it. The request is still blocked (`ErrBodyReadTimeout` from the fired timer, WARN, `ban:appsec-body-timeout`) once the client ends or abandons its body, or at Traefik's `readTimeout`. The e2e asserts that measured behaviour (HTTP/1.1 body ending at 4 s → 403; HTTP/2 → 403 within 3 s in the access log); README `appsecBodyReadTimeoutSeconds` and the streaming section say so. Which Traefik wrapper hides `Unwrap` was not determined. HTTP/3 stays unmeasured (no h3 e2e).
  By: implement

- Q: Name, default, and validation of the new deadline key?
  Rank: additive asked — new public key; decision 1 "The deadline MUST be configurable through a new public config key … Name and default value: explore decides"
  Decision: assumed — `appsecBodyReadTimeoutSeconds` (Go field `AppsecBodyReadTimeoutSeconds`, `int64`, `json:"appsecBodyReadTimeoutSeconds,omitempty"`, sorted after `AppsecBodyLimit`). "ReadTimeout" matches Traefik's own total-read `readTimeout` vocabulary and the `appsecHttpTimeoutSeconds` / `*TimeoutSeconds` siblings. Default `30`: below Traefik's default `readTimeout` of 60 s (per #434's README; not read in Traefik source), so with Traefik defaults the plugin's own logged block fires first; delivers the first 10 MiB on uplinks of roughly 2.8 Mbit/s or more; a stream waits at most 30 s before its 403. Validation: `requiredInt1` (`< 1` fails `ValidateParams` with `AppsecBodyReadTimeoutSeconds: cannot be less than 1`), same as the other `*TimeoutSeconds` keys; no `0 = disabled` mode (it would reopen the hang decision 1 closes). Inside `pkg/appsec` the stored field drops the prefix (`bodyReadTimeoutSeconds`, Config domain prefix rule).
  By: explore

- Q: Status and remediation when the deadline expires: 403 ban path or 408? Log level and message?
  Rank: additive asked — adds a header reason token and a metrics origin to closed lists; decision 2 "Status/remediation (403 ban path vs 408): explore decides and records why", decision 8 "logged above Debug (Info or Warn)"
  Decision: assumed — ban path, independent of `bouncerAppsecFailureAction`: `handleBanServeHTTP` with `ReasonAPPSEC`, `bouncerRemediationStatusCode` (default 403) and the ban template; header reason `appsec-body-timeout` (`ban:appsec-body-timeout`); usage-metrics origin `plugin:appsec_body_timeout` ("drops that are not a CrowdSec decision", `pkg/lapi/client_metrics.go:20`); `warnCaptchaSuperseded` like the other AppSec bans. Not 408: RFC 9110 §15.5.9 lets the client repeat the request, so a stream would retry into the same block; 408 would also skip the operator's status code, template, remediation header and drop metrics. Log: WARN via `logger.Debounced` (5 s, house pattern for per-request WARNs, `pkg/appsec/query.go:186`), message along the lines of "AppSec request body not received within appsecBodyReadTimeoutSeconds; request blocked. Exclude streaming routes with a bouncerActionRules bypassAppsec rule", attrs `ip` (`req.IPAddrString()`), `method`, `host`, `path`, `timeoutSeconds`. Propose: the WARN is emitted in `pkg/appsec` where `ErrBodyReadTimeout` is produced (owner of the knob and of the read; same place as the 401 / unexpected-status WARNs), with the exact text fixed in spec `core_plugin_appsec_body-read-timeout`; the bouncer only serves the ban.
  By: propose

- Q: Which unit owns the client address written on the deadline log line and the drop metric?
  Rank: additive incidental — reads an existing owner; no new identity derivation
  Decision: resolved — `clientrequest.Request` (`req.IPAddrString()`, `req.IPType()`), whose address comes from `pkg/ip.GetRemoteIP`. Reuse it; do not read `RemoteAddr` or forwarded headers again.
  By: explore

- Q: Where does `appsecBodyLimit <= 0` → 10 MiB land, and what else changes with it?
  Rank: bounded asked — changes existing validation and the cap branch; 5 production readers enumerated (`pkg/appsec/client.go:84`, `pkg/appsec/session.go:42`, `pkg/configuration/configuration.go:203,784,819`; roots `pkg/**`, `plugin.go`); decision 4 "`appsecBodyLimit` values `<= 0` become 10 MiB (10485760)"
  Decision: assumed — normalize in `appsec.Prepare` (existing "fill AppSec defaults on the snapshot before Open" owner, `pkg/appsec/client.go:44`) from a named default constant that `CreateConfig` also uses, so `Client.appsecBodyLimit` and the reclaim identity both see 10485760; remove `AppsecBodyLimit` from `requiredInt0` (`configuration.go:784`) and the duplicate check at `:819`; `newAppsecBodyRequest` always applies `io.LimitReader` (drop the `> 0` branch). Docs and tests that move: spec `core_plugin_appsec_client` "Zero body limit forwards the full body" (replaced by a non-positive-is-default requirement), README lines 155 and 619–620 ("`0` means no limit") plus an upgrade note that `0` now caps at 10 MiB, `knowledge/devdocs/core_plugin_appsec.md:34` (devdocs impact), `Test_appsecQuery_zeroBodyLimitForwardsPost` (rewrite to "0 and negative cap at 10 MiB") plus a `Prepare`/identity test. README line 530 warning stays true. Propose: the `<= 0` rule is one function, `configuration.EffectiveAppsecBodyLimit` (same pattern as `EffectiveFailureAction`), called by `appsec.Prepare` (snapshot, so the identity sees 10485760) and by `appsec.New` (so a Client built without `Prepare`, e.g. tests, never holds a non-positive cap); `DefaultAppsecBodyLimit` is the named constant `New()` and `NewTestClient` use.
  By: propose

- Q: What happens to `isBodyUnreadable` and `isMethodWithBody`?
  Rank: bounded asked — removes two existing predicates (1 production + 1 test call each, enumerated); decision 1 "Bodies of unknown length are read and inspected like any other body" and decision 6
  Decision: assumed — remove both and their tests (`Test_isBodyUnreadable`, the drop-set half of the predicate test at `zzz_query_test.go:548`); `isMethodWithForwardableBody` is the only method predicate. A named predicate for "length unknown" (`ContentLength < 0`) gates only the deadline. Update the "Do not collapse them" gotcha in `knowledge/devdocs/core_plugin_appsec.md:69` at devdocs impact.
  By: explore

- Q: Does the new key belong in the AppSec reclaim identity?
  Rank: additive incidental — adds a field to `identity` (`pkg/appsec/session.go:18`); no criterion names it
  Decision: assumed — yes. The deadline is stored on the shared `Client` like `BodyLimit` and `HTTPTimeoutSeconds`, so a change must open a new Client (spec "AppSec is reclaimed by listener identity": "A change to any keyed AppSec knob SHALL Open a new Client"). Add a `zzz_session_test.go` mutation row.
  By: explore

- Q: What should `tests/e2e/mock/scenarios/appsec/run.sh` assert after the change?
  Rank: additive asked — edits and adds e2e assertions; Deliverables "the existing e2e/mock AppSec scenarios where they assert today's drop"
  Decision: assumed — the mock AppSec returns 403 only when the forwarded body contains `a=0`, else 200 (`mocklapi/main.go:234-244`); with `appsecBodyLimit: 4` a forwarded `test` is allowed. Both existing lines at `run.sh:41-46` are POSTs (`curl -d` implies POST; the "GET" label is wrong) and become 200 (body inspected, allowed). Add: HTTP/2 POST without `Content-Length` and body `a=0&` → 403 (AppSec verdict on the inspected body); HTTP/2 DELETE without `Content-Length` and body `a=0&` → 403 (decision 6); HTTP/1.1 chunked POST `a=0&` → 403; a stream case per protocol — `appsecBodyReadTimeoutSeconds: 1` (or 2) in `dynamic.yml`, `(sleep 6) | curl -T - --max-time 4 …` with `--http2-prior-knowledge -H "Content-Length:"` and, separately, HTTP/1.1 `Transfer-Encoding: chunked` → 403 before the client's body ends. Keep the existing `GET` without body → 200. The restic shape (HTTP/2, empty body, no END_STREAM on HEADERS) is easier to pin in a Go test than with curl; implement chooses, but at least the unit tests cover `ContentLength -1` + immediately-empty body → AppSec queried, request allowed.
  By: explore

- Q: Are the requirement's claims about upstream #407 and #434 accurate enough to state in the PR description?
  Rank: additive asked — PR text only; Deliverables "The PR description MUST explain the problems of the upstream proposals"
  Decision: resolved — every claim confirmed against the diffs (Concepts › Upstream proposals) with two corrections: #407's un-cancelled read goroutine ends when Go's HTTP/2 server closes the stream after the handler returns (measured), so the PR must not say it runs indefinitely; the `false` fallback on #405 came from collaborator `mathieuHa`, not the repository owner. "Forever if `readTimeout` is 0" rests on Go's `ReadTimeout` doc plus the inference that Traefik maps its `readTimeout` onto it.
  By: explore
