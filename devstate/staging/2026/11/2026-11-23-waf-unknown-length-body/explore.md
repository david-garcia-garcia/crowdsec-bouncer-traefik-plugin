# Explore

IssueKey: 2026-11-23-waf-unknown-length-body
Grounded on worktree HEAD `f8a7a4ad` (dest `master` @ `aa6d0be3`). Unattended run: every open question is `assumed` or `resolved`. Reference: superseded PR #204 bus (`origin/2026-11-14-appsec-unknown-length-body:devstate/2026/11/2026-11-14-appsec-unknown-length-body/explore.md`), re-grounded below against current `master`.

## Concepts

### Units this change touches

| Unit | Path | Job today |
|------|------|-----------|
| `IsBodyUnreadable`, `IsMethodWithBody` | `pkg/wafhop/body.go:44-59` | Classify an HTTP/2+ body with `ContentLength < 0` as unreadable (no read); drop set POST/PUT/PATCH. Removed by this change. |
| `IsClientGone` | `pkg/wafhop/body.go:65-70` | Canceled request context, `context.Canceled`, `context.DeadlineExceeded`, `io.ErrUnexpectedEOF` → client gone. Stays; the deadline must be classified before it (measured below). |
| `ReadBody` / `bufferBody` / `bufferedBody` | `pkg/wafhop/body.go:87-157` | Shared buffer under a leg's limit (`TruncateAtLimit` / `RejectOverLimit`), restore body for `next`, reuse a whole body an earlier leg buffered. No deadline; `limit <= 0` = no cap. Gains the deadline. |
| `ErrClientDisconnected` / `ErrClientBodyRead` / `ErrBodyTooLarge` | `pkg/wafhop/body.go:17-27` | Client-side outcomes the bouncer answers (no response / 400 / 413). A deadline sentinel joins them. |
| AppSec `Client.Query`, `newAppsecBodyRequest`, `errUnreadableBody` | `pkg/appsec/query.go:68-70,118-139,262-283` | Unreadable POST/PUT/PATCH → failure action (or `ErrGateSkip` while backing off); passthrough/DELETE → headers-only GET; readable forwardable body → `ReadBody(appsecBodyLimit, TruncateAtLimit)` before admission. |
| ModSec `Client.Inspect` | `pkg/modsecurity/inspect.go:45-62` | Same unreadable rule under `bouncerModsecFailureAction` (its only use of `failureAction`); readable body on any method → `ReadBody(modsecBodyLimit, RejectOverLimit)` before admission. |
| Bouncer WAF answers | `pkg/bouncer/bouncer_serve_waf.go:13-27`, `bouncer_serve_appsec.go:63,89-107`, `bouncer_serve_modsec.go:32-57` | Only owner of `rw`. Maps leg errors: client gone (header only), `ErrClientBodyRead` → 400 `error:client-body-read`, ModSec `ErrBodyTooLarge` → 413, else failure action. |
| Remediation header reasons | `pkg/bouncer/remediation_header.go:11-34` | Closed token list (`client-body-read`, `client-disconnected`, …). Gains `body-read-timeout`. |
| Config | `pkg/configuration/configuration.go:75,168` (fields), `:252,317` (defaults), `:917-941` (`requiredInt0` / `requiredInt1`), `:959-961` (duplicate `AppsecBodyLimit < 0`), `:984` (`ModsecBodyLimit < 1`) | Public keys, defaults, validation. Gains two keys; `appsecBodyLimit <= 0` stops being rejected. |
| Leg identities | `pkg/appsec/session.go:18-51`, `pkg/modsecurity/session.go:20-36` | Reclaim keys of the shared leg instances (owner Open + alias). Each gains its leg's deadline. |
| AppSec `Prepare` / `New` | `pkg/appsec/client.go:54-75,77-102` | Fill AppSec defaults on the snapshot; store `appsecBodyLimit` on the Client. Owner of the `<= 0` → 10 MiB normalization. |
| Action rules | `pkg/httprule/action.go:14-21,198-206` | `bypassAppsec` (`SkipAppsec`), `bypassModsec` (`SkipModsec`), `bypass` (LAPI+AppSec+ModSec). Unchanged; documented for streaming routes. |
| Debounced logger | `pkg/logger/debounce.go:24` | One window per message text. Used for the deadline WARN. |
| Mock AppSec e2e | `tests/e2e/mock/scenarios/appsec/run.sh:40-50`, `dynamic.yml` (`appsecBodyLimit: 4`) | Real Traefik v3.7.19 + plugin under Yaegi; asserts today's HTTP/2 drop (403). |
| Real ModSec e2e | `tests/e2e/real/modsec.Tests.ps1`, `tests/e2e/real/waf_dual.Tests.ps1` | Pester via HTTP/1.1 helpers; no HTTP/2 or no-length case today. |

### How they connect

```
Traefik entrypoint (conn read deadline = accept + readTimeout 60s default; h1 / h2 / h2c / h3)
  │ rw (Traefik writer chain, all wrappers Unwrap in v3.7.19), *http.Request
  ▼
bouncer.ServeHTTP ─► serveLAPI ─► serveRateLimit ─► serveAppSec ─► serveModSec ─► next     [pkg/bouncer]
                                        │ Query(req, pol, dl)        │ Inspect(req, dl)
                                        ▼                            ▼
                     newAppsecBodyRequest (POST/PUT/PATCH/DELETE)   any method with a body
                                        │                            │
                                        └──────► wafhop.ReadBody(req, limit, mode, dl, timeout) ◄──┘
                                                   │ prior bufferedBody complete? → reuse (no read, no timer)
                                                   │ ContentLength < 0 → arm time.AfterFunc(timeout):
                                                   │        dl.SetReadDeadline(now) ; on error Body.Close()
                                                   │ read limit+1 bytes
                                                   │ fired := !timer.Stop()
                                                   ├─ fired                 → ErrBodyReadTimeout  (checked first)
                                                   ├─ IsClientGone          → ErrClientDisconnected
                                                   ├─ other error           → ErrClientBodyRead
                                                   └─ ok → limit/mode check (truncate | ErrBodyTooLarge)
   bouncer: ErrBodyReadTimeout → 400 + error:body-read-timeout + debounced WARN naming the leg's bypass action;
            no ban, no dropped metrics, no failure action, no gate Record (read happens before admission).
```

Two legs on one request: AppSec runs first. A body AppSec buffered whole is reused by ModSec with no read and no timer; ModSec still applies its own limit (413). Only when ModSec's limit is larger than AppSec's and the body is longer than AppSec's limit does ModSec read the rest from the network, under its own deadline.

### Call sites (enumerated; roots `pkg/**`, repo-root `*.go`, `tests/**`)

- `appsec.Client.Query`: 1 production (`pkg/bouncer/bouncer_serve_appsec.go:63`); 69 test calls (`pkg/appsec`: `zzz_failure_action_test.go` 21, `zzz_query_test.go` 21, `zzz_gate_test.go` 18, `zzz_nil_transport_test.go` 3, `zzz_test_helpers.go` 3, `zzz_timeout_test.go` 1, `zzz_client_body_read_protocols_test.go` 1; `pkg/bouncer/zzz_modsec_test.go` 1). Pattern `\.Query\(` minus `URL.Query()`.
- `modsecurity.Client.Inspect`: 1 production (`pkg/bouncer/bouncer_serve_modsec.go:32`); 5 test calls (`pkg/modsecurity/zzz_inspect_test.go`).
- `wafhop.ReadBody`: 2 production (`pkg/appsec/query.go:272`, `pkg/modsecurity/inspect.go:57`); 14 test calls (`pkg/wafhop/zzz_body_test.go`).
- `IsBodyUnreadable` / `IsMethodWithBody` / `errUnreadableBody`: production `pkg/appsec/query.go` (7 lines), `pkg/modsecurity/inspect.go` (2); tests `pkg/wafhop/zzz_body_test.go`, `pkg/appsec/zzz_query_test.go`.
- `AppsecBodyLimit` readers (non-test): `pkg/appsec/client.go:102`, `pkg/appsec/session.go:43`, `pkg/configuration/configuration.go:252,918,959`; test-side `pkg/appsec/test_client.go:15`, `zzz_test_helpers.go:21`, `zzz_query_test.go`, `zzz_session_test.go`, `zzz_traefikemulator_test.go`.
- Tests that lock today's drop (all PASS on HEAD, see Reproduce): `TestIsBodyUnreadable`, `TestIsMethodWithBody` (wafhop); `Test_appsecQuery_streamingDoesNotBlock`, `Test_appsecQuery_dropUnreadableBody`, `Test_appsecQuery_unreadableBodyMethods`, `Test_appsecQuery_unreadableBodyGetNotDropped`, `Test_appsecQuery_unreadableBodyDeleteNotDropped`, `Test_appsecQuery_zeroBodyLimitForwardsPost`, `TestQuery_unreadableBodyWhileBackingOffIsGateSkip` (appsec); `TestInspect_unreadableBodyFollowsAppsecRule`, `TestInspect_unreadableBodyWhileBackingOffIsGateSkip` (modsecurity). Mock e2e `run.sh:46-50` (two POSTs → 403).

### Reproduce

- Unit, HEAD `f8a7a4ad`: `go test ./pkg/wafhop/ ./pkg/appsec/ ./pkg/modsecurity/ -run 'TestIsBodyUnreadable|TestIsMethodWithBody|unreadableBody|streamingDoesNotBlock|dropUnreadableBody|zeroBodyLimitForwardsPost' -count=1` → all 11 tests PASS: the tree asserts today's drop on AppSec, the passthrough bypass on ModSec, and the gate skip.
- Restic shape and deadline cut, Go 1.25.6 plain `net/http` (probe in session scratchpad, not in tree; recorded in `knowledge/research/std_go_net-http_body-read-deadline/`). Handler: `time.AfterFunc(300ms)` → `http.NewResponseController(w).SetReadDeadline(time.Now())` (fallback `Body.Close`), capped `io.ReadAll`, `fired := !timer.Stop()`, then 400:

| Request | Read result | `fired` | `ctx.Err()` | today's `IsClientGone` | Client saw |
|---|---|---|---|---|---|
| HTTP/1.1 chunked, body never ends | 2 bytes, `read tcp …: i/o timeout` (`os.ErrDeadlineExceeded`) at 300 ms | true | `context.Canceled` | **true** (would be "client disconnected", no answer) | 400 at 300 ms |
| h2c, no Content-Length, body never ends | 2 bytes, `i/o timeout` at 300 ms | true | nil | false (would be `ErrClientBodyRead`) | 400 at 300 ms |
| h2c POST, empty body, no Content-Length (restic `?create=true`) | `CL=-1`, `Body != NoBody`, 0 bytes, nil, 0 s | false | nil | — | 400 (handler) at 0 s |

- Same HTTP/1.1 program under a Yaegi **v0.16.1** binary (built from the module cache): cut at 300 ms, `fired=true`, client 400 at 300 ms. `time.AfterFunc` + `ResponseController.SetReadDeadline` + `Timer.Stop` run in interpreted code.
- End-to-end through Traefik: **not reproduced** in this phase (no Traefik run). The mock e2e lines `run.sh:46-50` already assert the 403 for HTTP/2 without `Content-Length`.

### Traefik v3.7.19 facts (source read from the local module cache)

- Plugin writer chain: `pkg/plugins/external.go` wraps external handlers in `entryWriter` / `exitWriter`; `exitWriter.SetReadDeadline` tries the inner writer, then the entry writer; every middleware wrapper (`capture`, `compress`, `customerrors`, `observability/status_code`, `recovery`, `response_modifier`, `retry`) implements `Unwrap() http.ResponseWriter`.
- `CHANGELOG.md` v3.7.17: "Fix broken flush, hijack, and deadlines in wrapped ResponseWriters (#14082)". #204 measured on v3.7.11 that the controller did not cut an HTTP/1.1 read; that fix is a plausible cause for v3.7.19 behaving differently. **Inference, not measured on v3.7.19.**
- Connection-level read deadline at accept = `readTimeout` (`pkg/server/server_entrypoint_tcp.go:294-300`); default `readTimeout` 60 s (`pkg/config/static/static_config.go:51`). h2c comes from `http.Server.Protocols.SetUnencryptedHTTP2` (`:681-682`), i.e. the stdlib HTTP/2 writer.
- HTTP/3: Traefik itself calls `http.NewResponseController(rw).SetReadDeadline` for h3 bodies with `ContentLength != 0` (`pkg/server/server_entrypoint_tcp_http3.go:120-133`), so the h3 writer supports it (inference: the plugin cut works on h3; not measured). The same comment: quic-go never leaves `Body` nil or `http.NoBody`; `ContentLength` is -1 when unknown.
- Traefik v3.7.18+ bundles Yaegi v0.16.3 (`go.mod:78`); this repo's Yaegi harness stays on v0.16.1 (`pkg/yaegitest/interpreter.go:1`), the stricter floor.

### Outside facts used

- `knowledge/research/std_go_net-http_body-read-deadline/` (ported from #204 and extended with this run's measurements; delegated write).
- `knowledge/research/ext_traefik_plugins_body-read-deadline/` (created this run from Traefik v3.7.19 source; delegated write). It adds one inference: the plugin's `ServeHTTP` receives Traefik's `entryWriter`; on HTTP/1.1 any plugin `SetReadDeadline` replaces Traefik's connection deadline, which is harmless here because the plugin only sets "now" when its own timer fires, never a later deadline.
- `knowledge/research/std_go_net-http_body-read-errors/` (in tree: HTTP/1.1 read-timeout failures cancel the request context; HTTP/2 ones do not).
- `knowledge/research/std_go_io_limit-reader/` (`LimitReader(r, n <= 0)` is immediate EOF).
- `knowledge/research/ext_yaegi_interp_select-cases/` (no `select` on the request path) and in-tree Yaegi rules (`pkg/logger/debounce.go:12-13`, `atomic.Value` not `atomic.Pointer`).
- Upstream #405 / #407 / #434 via GitHub MCP, re-fetched 2026-11-23 (below). Ticket-scoped evidence; kept here.

### Upstream proposals — re-verified on current heads (2026-11-23)

Heads moved since #204 verified them (#407 `45deb7f4` → `0d6d64e7`; #434 `6a211c47` → `aa8170d2`). Re-read with `pull_request_read get_diff`. Both still **open**, not merged; #405 open.

**#407** (`mathieuHa`, "inspect an unreadable body that ends in time instead of dropping it"):
1. Hardcoded wait — confirmed: `unreadableBodyWait = time.Second`, not configurable.
2. `appsecBodyLimit <= 0` drops without reading — confirmed (`readBodyWithin`: `if limit <= 0 { return nil, errUnreadableBody }`).
3. `crowdsecAppsecUnreadableBodyBlock: false` keeps headers-only — confirmed (`if !bouncer.appsecUnreadableBodyBlock || !isMethodWithBody(...) { GET }`).
4. DELETE without Content-Length stays headers-only — confirmed (same line).
5. Timed-out read goroutine is not cancelled — confirmed: nothing closes the body or sets a deadline on timeout. #204's measurement stands: on Go's HTTP/2 server that read ends when the handler returns and the stream closes; on an HTTP/1.1-shaped path it would hold the response. Do not say "runs indefinitely". #407 also starts its own goroutine on the request path, which this plugin avoids under Yaegi.

**#434** (`ffluegel`, "buffer non-streaming HTTP/2+ request bodies without Content-Length"):
1. Client-controlled `Content-Type` picks the path — confirmed (`application/grpc`, `application/grpc+*`, `application/connect+*`; a duplicated `Content-Type` header now counts as readable).
2. With `false`, a request claiming `application/grpc` skips body inspection — confirmed.
3. No plugin deadline — confirmed; its README: the request "fails after Traefik's `readTimeout` (60 seconds by default)".
4. gRPC unary blocked by default — confirmed (README).
5. HTTP/2/3 GET and DELETE without Content-Length stay headers-only — confirmed (`!isMethodWithBody` → unreadable).

**Fallback "set `crowdsecAppsecUnreadableBodyBlock: false`"**: that is the issue author's own verified workaround in #405 ("set the flag to `false` on a dedicated middleware"); #204 attributed a recommendation of it to `mathieuHa` on 2026-10-18 (not re-read here). Either way it is Problem 2: any client that omits `Content-Length` skips body inspection.

## Decisions

### Chosen seam / approach

- One read path in `pkg/wafhop`: `ReadBody` reads every body a leg forwards (AppSec: POST/PUT/PATCH/DELETE; ModSec: any method), capped at the leg's limit. `IsBodyUnreadable`, `IsMethodWithBody`, `errUnreadableBody`, and both drop branches are removed (decisions 1, 6, 7).
- A body of unknown length (`ContentLength < 0`, any protocol, HTTP/1.1 chunked included) gets a total read deadline per leg: `appsecBodyReadTimeoutSeconds` / `modsecBodyReadTimeoutSeconds`, default 30, `< 1` rejected. Bodies with a declared length keep today's behaviour (Traefik `readTimeout` → 400).
- Deadline mechanism inside `wafhop`: `time.AfterFunc` armed only when this call really reads from the client (not on reuse of a complete buffer); on fire, `SetReadDeadline(time.Now())` through a per-request controller the bouncer builds from `rw` (`http.NewResponseController`), and `Body.Close()` when that errors or no controller was given. After the read, `fired := !timer.Stop()` decides first, before `IsClientGone`. No goroutine of our own, no `select`, no `sync/atomic` type.
- Deadline outcome: new sentinel `wafhop.ErrBodyReadTimeout` (separate from, not wrapping, `ErrClientBodyRead`), returned unwritten by both legs. The bouncer answers HTTP 400 with header `error:body-read-timeout`, no ban, no dropped metrics, no failure action, no gate record, and a debounced (5 s) WARN per leg naming that leg's timeout key, the bypass action (`bypassAppsec` / `bypassModsec`, or `bypass`), plus `ip`, `method`, `host`, `path`.
- The controller reaches the legs as a parameter: `Query(req, pol, dl)`; `Inspect(req, dl)` replaces its now-dead `failureAction` parameter. The interface is narrow (`SetReadDeadline(time.Time) error`), so tests pass a stub or nil.
- `appsecBodyLimit <= 0` → 10485760 via one function `configuration.EffectiveAppsecBodyLimit`, applied in `appsec.Prepare` (snapshot, so the reclaim identity sees 10485760) and `appsec.New`; the `requiredInt0` entry and the duplicate `< 0` check go. `ReadBody` loses its "limit 0 = no cap" mode (no caller left); the `math.MaxInt64` guard stays.
- Each new key lives on its leg's Client and in its leg's reclaim identity, next to `BodyLimit` and `HTTPTimeoutSeconds`.
- Docs: new how-to page for streaming request bodies under `docs/how-to/` (listed in `docs/how-to/README.md`), keys in `docs/configuration.md`, rule changes in `docs/failure-modes.md`, `docs/how-it-works.md`, `docs/modsecurity.md`, `docs/concepts.md`, and the `error:body-read-timeout` row in `docs/how-to/verdict-in-access-logs.md`.

### Rejected alternatives

- One shared key: legs are shared per instance (owner Open + alias; `pkg/appsec/session.go`, `pkg/modsecurity/session.go`), and a router can use AppSec owned by one middleware and ModSec owned by another; an unprefixed key has no single owner and breaks the per-leg settings pattern.
- #204's ban path (`ban:appsec-body-timeout`, `plugin:appsec_body_timeout`): master now answers every "client body did not arrive whole" case with 400 and no ban (`pkg/bouncer/bouncer_serve_waf.go:20-27`, `docs/failure-modes.md:51`), including Traefik's own `readTimeout`; a ban would count a slow client as a WAF drop and need two new header reasons and two metrics origins.
- HTTP 408: invites automatic client retry (RFC 9110 §15.5.9) into the same block.
- Read in a goroutine and stop waiting (upstream #407): unowned read; own goroutine on the request path under Yaegi.
- `Body.Close()` alone: does not cut an HTTP/1.1 read (#204 measurement).
- `SetReadDeadline(now + d)` before the read, then clear it: clearing drops Traefik's own `readTimeout` deadline for the rest of an oversize body.
- `context.WithTimeout`: a context does not unblock a body `Read`.
- Classifying the cut by error type: on HTTP/1.1 the cut cancels the request context, so `IsClientGone` says "gone" (measured); the plugin's own timer is the only reliable signal.
- Content-Type classification (upstream #434): client-controlled; forbidden by decision 3.
- Checking `gate.BackingOff()` before reading: a new gate interaction (decision 9 out of scope).
- One deadline anchored on the first leg's start: adds per-request state on `bufferedBody` for a case that never happens with default limits (AppSec 10 MiB ≥ ModSec 8 MiB); per-leg reads are simpler and each key means what it says.

### Live contract

Live. Specs that change (propose confirms placement with `skill:opd-speclibrarian`):
- `core_plugin_wafhop_shared-request` — remove the unreadable class and its gate-skip sentence (`spec.md:8`); add the read deadline, `ErrBodyReadTimeout`, classification order, no uncapped mode.
- `core_plugin_appsec_failure-action` — drop "unreadable body" from the failure set (`:22-23`) and the backing-off skip (`:154`) with their scenarios.
- `core_plugin_appsec_client` — unknown-length read + deadline; `appsecBodyLimit <= 0` = 10 MiB replaces "zero = unlimited" (`:67-70`); drop-set sentences (`:106`, `:117`); identity key list (`:16`).
- `core_plugin_modsecurity_inspect` — `ErrUnavailable` no longer covers a streamed body (`:31`); `Inspect` parameter.
- `core_plugin_modsecurity_client` — ownership key list (`:16`).
- `core_plugin_middleware_bouncer` — the 400 `error:body-read-timeout` answer for both legs; header table row (`:290`).
- `core_plugin_middleware_config-validation` — the two new keys (`requiredInt1`); negative `appsecBodyLimit` accepted.
- Not touched: `core_plugin_lapi_usage-metrics` (no new origin).

## Open questions

- Q: One deadline key per leg or one shared key; name, default, validation, and does it enter each leg's reclaim identity?
  Rank: additive asked — two new public keys and two identity fields; decision 1 "Whether there is one key per leg (`appsecBodyReadTimeoutSeconds` / `modsecBodyReadTimeoutSeconds`, consistent with per-leg settings and shared leg instances) or one shared key: explore decides and records why"
  Decision: assumed — one key per leg: `appsecBodyReadTimeoutSeconds` (Go `AppsecBodyReadTimeoutSeconds`) and `modsecBodyReadTimeoutSeconds` (Go `ModsecBodyReadTimeoutSeconds`), `int64`, `omitempty`, default `30` each, in `requiredInt1` next to the `*HTTPTimeoutSeconds` siblings (`< 1` → `<Name>: cannot be less than 1`); no `0 = disabled` mode (it would reopen the hang decision 1 closes). Why per leg: leg instances are shared by owner (`appsecInstanceName` / `modsecInstanceName`, owner Open + alias), and a router may run AppSec owned by one middleware and ModSec owned by another; each leg's knobs live on its own Client and reclaim key (`pkg/appsec/session.go:18-31`, `pkg/modsecurity/session.go:20-26`), so a shared key would have no owner. Each key joins its leg's identity (a change Opens a new Client, spec "reclaimed by listener/sidecar identity"). Default 30 s: below Traefik's default `readTimeout` of 60 s (`traefik/traefik@v3.7.19:pkg/config/static/static_config.go:51`), so with Traefik defaults the plugin's logged block fires first; enough for 10 MiB on roughly 2.8 Mbit/s. Inside each package the stored field drops the leg prefix (`bodyReadTimeout`).
  By: explore

- Q: Which bodies get the deadline: HTTP/1.1 chunked, HTTP/3, bodies with a declared `Content-Length`?
  Rank: bounded asked — changes existing `wafhop.ReadBody` (2 production callers `pkg/appsec/query.go:272`, `pkg/modsecurity/inspect.go:57`; 14 test calls `pkg/wafhop/zzz_body_test.go`; roots `pkg/**`); decision 1 "Bodies of unknown length are read and inspected like any other body on both WAF legs … with a total read deadline"
  Decision: assumed — every body this leg reads whose length is unknown (`ContentLength < 0`), on every protocol: HTTP/1.1 chunked, HTTP/2, h2c, HTTP/3. The protocol a client picks must not change how long the plugin waits (principle line). Not bodies with a declared `Content-Length`: there the client signal cannot reduce inspection today (a stalled body ends at Traefik `readTimeout` → `ErrClientBodyRead` → 400), and requirement § Out of scope lists that deadline as not taken. The timer runs only while this call reads from the client: a complete body reused from the earlier leg arms nothing. Once the limit is reached the read stops and the rest streams on to `next` under Traefik's `readTimeout` only (decision 5). Consequence, not a policy change: an HTTP/3 GET whose body quic-go reports as unknown length is now read by ModSec (which already forwards bodies on any method) and still not by AppSec (method set unchanged).
  By: explore

- Q: How is the deadline told apart from a client disconnect, given `wafhop.IsClientGone` treats a canceled context and `context.DeadlineExceeded` as gone, and does the mechanism run under Yaegi v0.16.1?
  Rank: additive asked — new branch inside the read helper this change creates in `pkg/wafhop`; decision 1 "Implement the read and deadline once in `pkg/wafhop` so both legs share it"
  Decision: resolved — measured (Concepts › Reproduce): on HTTP/1.1 the deadline cut cancels the request context, so today's `IsClientGone` returns true and the request would be treated as a disconnect (no answer, while the client is still there and does receive a written response); on HTTP/2 it is `os.ErrDeadlineExceeded` with a live context. So classify by the plugin's own timer: `fired := !timer.Stop()` after the read, checked before `IsClientGone`; `fired` → `ErrBodyReadTimeout` whatever the read returned. `IsClientGone` stays unchanged for every other read. The callback sets `SetReadDeadline(time.Now())` on the controller and falls back to closing the body being read (captured when the timer is armed) on error or nil controller. The success path never touches the read deadline, so Traefik's `readTimeout` still bounds the rest of an oversize body. Yaegi v0.16.1: the same mechanism ran in interpreted code and cut an HTTP/1.1 read at the deadline (measured); no goroutine of our own, no `select` (`ext_yaegi_interp_select-cases`), no `atomic.Bool` / `atomic.Pointer`. Implement adds a Yaegi test with `pkg/yaegitest` (pattern `pkg/bouncer/zzz_yaegi_leg_binding_test.go`). Implement result: `pkg/wafhop/zzz_yaegi_body_read_deadline_test.go` passes under the yaegi v0.16.1 binary (HTTP/1.1 chunked stall cut through the controller in about 1 s, for one leg and for a second leg reading the rest through the first leg's buffered body; nil controller cut through `Close`). It first failed: Yaegi panics on a `nil` comparison of an interpreted interface (`wafhop.ReadDeadliner`) holding the native `*http.ResponseController` inside the timer goroutine, so the parameter is the concrete `*http.ResponseController` (deviations row by implement).
  By: implement

- Q: How does the per-request read-deadline control reach `pkg/wafhop` from the bouncer, which alone owns `rw`?
  Rank: bounded incidental — changes two existing signatures whose callers were enumerated: `appsec.Client.Query` (1 production `pkg/bouncer/bouncer_serve_appsec.go:63` + 69 test calls) and `modsecurity.Client.Inspect` (1 production `pkg/bouncer/bouncer_serve_modsec.go:32` + 5 test calls); roots `pkg/**`, repo-root `*.go`, `tests/**`; no criterion names a signature change, it is a means to decisions 1 and 2
  Decision: assumed — `serveAppSec` and `serveModSec` each build `http.NewResponseController(rw)` (cheap, symmetric; propose chose this over one build in `ServeHTTP`) and pass it as the concrete `*http.ResponseController` (implement: the narrow interface `wafhop.ReadDeadliner` propose chose panics under Yaegi v0.16.1 when nil-checked in the timer goroutine, measured): `Query(req, pol, ctrl)` gains a third parameter; `Inspect(req, ctrl)` replaces `failureAction`, whose only use was the removed drop branch (`pkg/modsecurity/inspect.go:42-55`). All call sites migrate in this change; tests pass nil (falls back to `Body.Close`), a controller on an `httptest.ResponseRecorder` (its `SetReadDeadline` fails, so the fallback runs), or a real `httptest` server. Not on `clientrequest.Request` (its doc keeps it to request + address; `pkg/clientrequest/request.go:21-23`), not on `appsec.Policy` (per-route fallback, not per-request I/O), not on the request context (hidden plumbing). Deviations row appended.
  By: implement

- Q: Status and remediation when the deadline expires: #204's ban path, master's `ErrClientBodyRead` → 400 contract, or 408? Does ModSec need its own reason / origin? Log level and text?
  Rank: additive asked — adds one header reason token to a closed list and one bouncer handler; decision 2 "Status/remediation: explore decides and records why, considering #204's ban path and master's newer `wafhop.ErrClientBodyRead` → 400 contract", decision 8 "logged above Debug (Warn), debounced, with a message that tells the operator to exclude streaming routes with `bypassAppsec`"
  Decision: assumed — the 400 family, with its own reason: both legs return `wafhop.ErrBodyReadTimeout`; the bouncer answers HTTP 400 `Bad Request` through one shared handler in `pkg/bouncer/bouncer_serve_waf.go`, header `error:body-read-timeout` (kind `error`, no third field), no ban template, no `bouncerRemediationStatusCode`, no dropped metrics or origin, no failure action, no gate `Record` (both legs read before admission). Fail-closed holds: `next` is never called. Why 400: master's newest contract says a body that did not arrive whole while the client is still there is "not a WAF verdict and not a WAF failure" (`pkg/wafhop/body.go:21-24`, `docs/failure-modes.md:51`), and Traefik's own `readTimeout` on the same request is already answered that way; the plugin deadline is the same symptom on a shorter clock. A distinct reason (not `client-body-read`) lets access logs and e2e tell the plugin deadline from Traefik's. Same reason for both legs (the WARN carries the leg). WARN via `logger.Debounced(…, slog.LevelWarn, 5*time.Second, msg)` from the bouncer (owner of `req` and the client address), one constant message per leg, e.g. "AppSec request body not received within appsecBodyReadTimeoutSeconds; request blocked. Exclude streaming routes with a bouncerActionRules bypassAppsec (or bypass) rule" and the ModSec twin naming `modsecBodyReadTimeoutSeconds` / `bypassModsec`; attrs `ip`, `method`, `host`, `path`, `timeoutSeconds`. Not 408 (client retry, RFC 9110 §15.5.9). Propose fixed the text in spec `core_plugin_middleware_bouncer` ("Body read deadline is logged at WARN once per window per leg"): `AppSec request body not received within appsecBodyReadTimeoutSeconds; request blocked. Exclude streaming routes with a bouncerActionRules bypassAppsec (or bypass) rule` and the ModSec twin; `timeoutSeconds` comes from a `BodyReadTimeoutSeconds()` accessor on each leg Client (design D5).
  By: propose

- Q: How do both legs share one buffered read and one deadline when AppSec truncates at its limit and ModSec rejects over its limit with 413?
  Rank: additive asked — reuses the existing `bufferedBody` path unchanged; decision 1 "a body already buffered by the first leg is reused by the second (existing `bufferedBody` reuse)", decision 5 "unchanged"
  Decision: assumed — no shared deadline object. Each leg calls `ReadBody` with its own limit, mode, and timeout. AppSec runs first: a body it buffered whole is reused by ModSec without a read or a timer, and ModSec still applies its own limit (413 over `modsecBodyLimit`, as today). If AppSec stopped at its limit (body longer than `appsecBodyLimit`), ModSec reads from the restored body (memory first, then the network) and arms its own deadline only for that read; with defaults (10 MiB ≥ 8 MiB) it never reaches the network. A leg skipped by `bypassAppsec` / `bypassModsec` reads nothing; the other leg reads alone under its own key. Worst case wait = AppSec timeout + ModSec timeout, only when `modsecBodyLimit > appsecBodyLimit`; documented with the keys.
  By: explore

- Q: Where does `appsecBodyLimit <= 0` → 10 MiB land, and what happens to `ReadBody`'s "limit 0 or less = no cap" mode?
  Rank: bounded asked — changes existing validation and the read cap; non-test readers enumerated (`pkg/appsec/client.go:102`, `pkg/appsec/session.go:43`, `pkg/configuration/configuration.go:252,918,959`; roots `pkg/**`, repo-root `*.go`); decision 4 "`appsecBodyLimit` values `<= 0` become 10 MiB (10485760). This removes '0 = unlimited' and replaces today's validation error for negative values"
  Decision: assumed — `configuration.EffectiveAppsecBodyLimit` (pattern `EffectiveFailureAction`, `pkg/configuration/configuration.go:224`) with a named `DefaultAppsecBodyLimit = 10485760` that `CreateConfig` also uses; called by `appsec.Prepare` (so the identity hashes 0, negative, and 10485760 the same) and `appsec.New` (a Client built without `Prepare`, e.g. tests, never holds a non-positive cap). Remove `AppsecBodyLimit` from `requiredInt0` (`:918`) and the duplicate check (`:959-961`). `ReadBody` drops its no-cap branches (`body.go:96`, `:116`, `:127`); the `math.MaxInt64` overflow guard stays; a non-positive limit becomes a caller bug documented as such. Moves with it: spec `core_plugin_appsec_client:67-70`, `docs/configuration.md:622-626`, `docs/concepts.md:84`, devdocs `core_plugin_appsec.md:50`, `core_plugin_wafhop_shared-request.md` gotcha "ReadBody treats 0 as no cap", `core_plugin_middleware_config-validation.md:52`, and `Test_appsecQuery_zeroBodyLimitForwardsPost` (rewritten: 0 and negative cap at 10 MiB). Removing the no-cap mode is not named by a criterion; it is dead once decision 4 lands (both callers pass ≥ 1) — Deviations row appended.
  By: explore

- Q: What happens to `IsBodyUnreadable`, `IsMethodWithBody`, `errUnreadableBody`, and the spec rule "an unreadable body while the gate is backing off is a skip"?
  Rank: bounded asked — removes existing predicates and branches (production callers `pkg/appsec/query.go`, `pkg/modsecurity/inspect.go`; tests listed under Call sites); decision 7 "Remove `IsBodyUnreadable` / `IsMethodWithBody` and their drop paths"
  Decision: assumed — remove all three and their tests (`TestIsBodyUnreadable`, `TestIsMethodWithBody`, the drop/unreadable tests in appsec and modsecurity, `TestQuery_unreadableBodyWhileBackingOffIsGateSkip`, `TestInspect_unreadableBodyWhileBackingOffIsGateSkip`); rewrite `Test_appsecQuery_streamingDoesNotBlock` as "stream hits the deadline". `isMethodWithForwardableBody` becomes AppSec's only method predicate (its "keep the two sets separate" comment goes). The gate-skip sentence (`openspec/specs/core_plugin_wafhop_shared-request/spec.md:8`, `core_plugin_appsec_failure-action/spec.md:154`) disappears with the class: no gate code changes (`Admit`, `BackingOff`, `Record` untouched), and the read-before-admission order stays what it already is for every readable body. Consequence an operator can see: while a leg backs off, an unknown-length body is now read (and a stream that never ends gets the 400 at the deadline) before the gate skip, exactly like a slow body with a length is today. The § Out of scope line "FailureAction / BackOffAction defaults and gate behaviour" is respected: no default and no gate rule changes. Devdocs gotchas move at devdocs impact (`core_plugin_appsec.md:89-90`, `core_plugin_modsecurity_inspect.md:14,33`, `core_plugin_wafhop_shared-request.md` "Unreadable body").
  By: explore

- Q: Does `http.ResponseController.SetReadDeadline` cut an HTTP/1.1 (and HTTP/3) read through Traefik v3.7.19's writer chain, where #204 measured "no" on v3.7.11?
  Rank: additive incidental — decides only test assertions and doc wording of the new path; no criterion names it
  Decision: resolved — measured yes (implement, mock e2e `tests/e2e/mock/scenarios/appsec`, Traefik v3.7.19 binary, plugin under Yaegi, `appsecBodyReadTimeoutSeconds: 2`, body `x`, then a 5 s pause): Traefik's access log shows `"POST /stream/h1-stall HTTP/1.1" 400 … 2001ms` and `"POST /stream/h2-stall HTTP/2.0" 400 … 2001ms`, and curl received `X-Remediation: error:body-read-timeout` on both. So the controller reaches the HTTP/1.1 connection through Traefik's writer chain; #204's "no" on v3.7.11 is not reproduced (#204's curl lines sent `(sleep N; printf x)`, and curl does not send the request before stdin yields its first byte, so its body never stalled inside the plugin; measured here, access log 1 ms). The e2e asserts 1500–3500 ms on both protocols; `docs/how-to/streaming-request-bodies.md` states the measurement. HTTP/3 stays unmeasured; docs say "expected". Explore's prior reasoning, kept: expected yes on v3.7.19, by source: every wrapper on the plugin path implements `Unwrap`, `exitWriter.SetReadDeadline` falls back to the entry writer (`pkg/plugins/external.go:104-111`), and v3.7.17 shipped "Fix broken flush, hijack, and deadlines in wrapped ResponseWriters (#14082)". HTTP/3: Traefik itself sets read deadlines through `ResponseController` on h3 (`server_entrypoint_tcp_http3.go:120-133`). Not measured on v3.7.19. Implement measures HTTP/1.1 chunked and h2c in the mock e2e (`tests/e2e/mock/scenarios/appsec`, Traefik v3.7.19) and asserts what it measures; if HTTP/1.1 is still not cut, the request is still blocked (timer fired) once the client ends or abandons the body or at Traefik's `readTimeout`, and docs say so. HTTP/3 stays unmeasured (no h3 e2e); docs say "expected" not "measured".
  By: implement

- Q: What do the e2e suites assert, and how is the restic shape (HTTP/2, empty body, no `Content-Length`) produced for ModSec?
  Rank: additive asked — edits and adds e2e assertions; Deliverables "the e2e scenarios that assert today's drop … Add e2e coverage for restic-shape requests (HTTP/2, no `Content-Length`) through ModSec"
  Decision: assumed — Mock AppSec (`run.sh`, `appsecBodyLimit: 4`, mock answers 403 only for a forwarded body containing `a=0`): the two lines at `:46-50` are POSTs (`curl -d`; the "GET" label is wrong) and become 200 (inspected, allowed); add HTTP/2 POST without length and body `a=0&` → 403; HTTP/2 DELETE without length `a=0&` → 403 (decision 6); HTTP/2 empty POST without length (`-T /dev/null` or `--data-binary ''` with `-H "Content-Length:"`) → 200; HTTP/1.1 chunked `a=0&` → 403; a stalled stream per protocol with `appsecBodyReadTimeoutSeconds: 2` in `dynamic.yml` (`(printf 'ab'; sleep 8) | curl -T - --max-time 6 …`, h2c with `--http2-prior-knowledge -H "Content-Length:"`, and HTTP/1.1 chunked) → 400 with `error:body-read-timeout` before the body ends (or the measured HTTP/1.1 timing). Real ModSec (`tests/e2e/real/modsec.Tests.ps1`): curl is the client (`--http2-prior-knowledge` against the h2c `web` entrypoint; Traefik enables h2c through `Protocols`): restic shape `POST /…?create=true` empty body no length → 200; an attack body without length (a CRS-triggering payload already used in that file) → CRS block; a stalled body → 400 `error:body-read-timeout` with a short `modsecBodyReadTimeoutSeconds` on that route's dynamic config. Unit tests pin `ContentLength -1` + empty body → WAF queried, request allowed, on both legs. Implement may use a Go client where curl cannot shape the request.
  By: explore

- Q: Which unit owns the client address written on the deadline WARN?
  Rank: additive incidental — reads an existing owner; no new identity derivation
  Decision: resolved — `clientrequest.Request` (`req.IPAddrString()`), whose address comes from `pkg/ip.GetRemoteIP` (`pkg/bouncer/bouncer.go:155-162`). The WARN is emitted in the bouncer, which holds that value for both legs; do not read `RemoteAddr` or forwarded headers again, and do not log from `pkg/wafhop` (it has no request identity).
  By: explore

- Q: Are #204's claims about upstream #407 / #434 and the `false` fallback still accurate for the PR description?
  Rank: additive asked — PR text only; Deliverables "The description MUST explain why not upstream #407 / #434 / the 'set `crowdsecAppsecUnreadableBodyBlock: false`' fallback (re-use #204's verified analysis)"
  Decision: resolved — both PR heads moved since #204; re-read on current heads 2026-11-23 (Concepts › Upstream proposals): every claim still holds; #434 additionally treats a duplicated `Content-Type` as readable. Keep #204's correction (the #407 read goroutine ends with the stream on Go's HTTP/2 server; do not say "indefinitely"). The `false` fallback is the #405 author's own workaround; #204's attribution of a recommendation to `mathieuHa` was not re-read and the PR should cite the issue, not a person.
  By: explore
