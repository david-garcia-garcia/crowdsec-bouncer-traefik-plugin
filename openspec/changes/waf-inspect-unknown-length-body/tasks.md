# Tasks

Spec ids (all folds): `core_plugin_wafhop_shared-request`, `core_plugin_appsec_failure-action`, `core_plugin_appsec_client`, `core_plugin_modsecurity_inspect`, `core_plugin_modsecurity_client`, `core_plugin_middleware_bouncer`, `core_plugin_middleware_config-validation`. How: `design.md` D1–D8. Yaegi rules: no `select`, no goroutine of our own on the request path, no `atomic.Bool` / `atomic.Pointer` (design Context). Each group lands its own tests and docs.

## 1. Config: per-leg read timeouts and the AppSec body-limit default

- [ ] 1.1 `pkg/configuration/configuration.go`: add named constants `DefaultAppsecBodyLimit = 10485760` and `DefaultBodyReadTimeoutSeconds = 30`; add fields `AppsecBodyReadTimeoutSeconds` (`appsecBodyReadTimeoutSeconds`) and `ModsecBodyReadTimeoutSeconds` (`modsecBodyReadTimeoutSeconds`), `int64`, `omitempty`, alphabetical by tag; default both to 30 in `New()` / `CreateConfig`, and use `DefaultAppsecBodyLimit` for the AppSec default. Verify: `go build ./...`.
- [ ] 1.2 Add `EffectiveAppsecBodyLimit(limit int64) int64` next to `EffectiveFailureAction` (`<= 0` → `DefaultAppsecBodyLimit`), with a doc comment. Verify: `pkg/configuration` unit test for `0`, `-1`, `1`, `10485760`.
- [ ] 1.3 `ValidateParams`: remove `AppsecBodyLimit` from `requiredInt0`; delete the duplicate `AppsecBodyLimit < 0` check; add both new keys to `requiredInt1`. Verify: `pkg/configuration` tests pass for the default config; `modsecBodyReadTimeoutSeconds: 0` fails with `ModsecBodyReadTimeoutSeconds: cannot be less than 1` (same for AppSec); `appsecBodyLimit: -1` passes; setting one key leaves the other at 30; `modsecBodyLimit: 0` with ModSec enabled still fails. Update any test that asserted `AppsecBodyLimit: cannot be less than 0`.
- [ ] 1.4 Docs: `docs/configuration.md` gets entries for **appsecBodyReadTimeoutSeconds** and **modsecBodyReadTimeoutSeconds**. Say what they bound (total time to receive a body without `Content-Length` — HTTP/1.1 chunked, HTTP/2/3 without the header — up to the leg's body limit), the default 30, the minimum 1, that a block is HTTP 400 `error:body-read-timeout` whatever the leg's failure action, that bodies with `Content-Length` are not affected, the arithmetic (10 MiB in 30 s ≈ 2.8 Mbit/s), the worst case AppSec + ModSec when `modsecBodyLimit > appsecBodyLimit`, and a link to the streaming how-to (group 5). Change **appsecBodyLimit** from "0 means no limit" to "`0` or a negative value means the default 10 MiB", with an upgrade note. Change the same sentence in `docs/concepts.md`. Verify: `rg -n "0 means no limit|no limit" docs/` has no hit about `appsecBodyLimit`.

## 2. Shared read path and deadline (`pkg/wafhop`)

- [ ] 2.1 `pkg/wafhop/body.go`: delete `IsBodyUnreadable` and `IsMethodWithBody`; add `ReadDeadliner` (`SetReadDeadline(time.Time) error`) and `ErrBodyReadTimeout` (not wrapping `ErrClientBodyRead`), each with a doc comment; rewrite the package comment and `ReadBody` doc (no "caller checks IsBodyUnreadable", no "limit 0 = no cap"; a non-positive limit is a caller bug). Verify: `go build ./pkg/wafhop/`.
- [ ] 2.2 `ReadBody(httpReq, limit, mode, dl, timeout)`: drop the no-cap branches (keep the `math.MaxInt64` guard); after the reuse return and only for `ContentLength < 0`, arm `time.AfterFunc(timeout)` whose callback calls `dl.SetReadDeadline(time.Now())` and falls back to closing the captured body when `dl` is nil or returns an error; after the read, `fired := !timer.Stop()` decides first (→ `ErrBodyReadTimeout`), then `IsClientGone`, then `ErrClientBodyRead`. The success path never calls `SetReadDeadline`. Verify: `go vet ./pkg/wafhop/`.
- [ ] 2.3 `pkg/wafhop/zzz_body_test.go`: delete `TestIsBodyUnreadable` / `TestIsMethodWithBody`; migrate the 14 `ReadBody` calls; add tests (design D8): nil-controller timeout through `Close`; stub controller called with a time at or before now; `fired` wins over a `context.Canceled`-wrapping read error; a declared-length slow body is not cut; reuse of a complete buffer starts no timer (timeout 1 ns still returns the data); real `httptest` HTTP/1.1 chunked and HTTP/2 (TLS `EnableHTTP2`) servers whose handler passes `http.NewResponseController(w)` get `ErrBodyReadTimeout` well before the client ends the body. Verify: `go test ./pkg/wafhop/ -count=1 -v` green.
- [ ] 2.4 Yaegi: add a `pkg/yaegitest` program that runs `wafhop.ReadBody` against a stalled body with a short timeout and a controller (pattern `pkg/bouncer/zzz_yaegi_leg_binding_test.go`). Verify: it passes with the `yaegi` binary on PATH (or skips only because the binary is absent). Record the result on explore.md, open question on how the deadline is told apart (`By: implement`).

## 3. AppSec leg

- [ ] 3.1 `pkg/appsec/client.go` / `session.go` / `test_client.go`: `Prepare` writes `EffectiveAppsecBodyLimit` back onto the snapshot; `New` stores the effective limit and `bodyReadTimeout` from `AppsecBodyReadTimeoutSeconds`; add `BodyReadTimeoutSeconds() int64`; `identity` gains `BodyReadTimeoutSeconds` (`bodyReadTimeoutSeconds`); `NewTestClient` uses the default constants. Verify: `zzz_session_test.go` has a mutation row for the new knob (keys differ) and a test that `appsecBodyLimit` `0` and omitted give equal keys.
- [ ] 3.2 `pkg/appsec/query.go`: delete `errUnreadableBody` and the `Query` branch that maps it; add `ErrBodyReadTimeout = wafhop.ErrBodyReadTimeout`; `Query(req, pol, dl wafhop.ReadDeadliner)`; `newAppsecForwardRequest` / `newAppsecBodyRequest` no longer take `Policy`; `newAppsecBodyRequest` has two branches (design D1) and calls `ReadBody(httpReq, c.appsecBodyLimit, wafhop.TruncateAtLimit, dl, c.bodyReadTimeout)`; drop the "keep the two sets separate" comment on `isMethodWithForwardableBody`. Verify: `go build ./...`.
- [ ] 3.3 Migrate the 69 `Query` test calls (explore.md, Call sites) to pass `nil` unless the test exercises the deadline. Delete `Test_appsecQuery_dropUnreadableBody`, `Test_appsecQuery_unreadableBodyMethods`, `Test_appsecQuery_unreadableBodyGetNotDropped`, `Test_appsecQuery_unreadableBodyDeleteNotDropped`, `TestQuery_unreadableBodyWhileBackingOffIsGateSkip`. Replace them with: `ProtoMajor 2` + `ContentLength -1` POST/PUT/PATCH/DELETE → listener gets POST with the bytes for `ban`, `passthrough`, `captcha`; empty such POST → listener called, allow; GET with such a body stays headers-only; same body with and without `Content-Length` → identical forwarded bytes; a stalled body → `ErrBodyReadTimeout`, listener not called, for each failure action and while the gate is backing off. Rewrite `Test_appsecQuery_streamingDoesNotBlock` as "stream hits the deadline" and `Test_appsecQuery_zeroBodyLimitForwardsPost` as "0 and -1 cap at 10485760". Verify: `go test ./pkg/appsec/ -count=1` green.

## 4. ModSec leg

- [ ] 4.1 `pkg/modsecurity/client.go` / `session.go`: store `bodyReadTimeout` from `ModsecBodyReadTimeoutSeconds`; add `BodyReadTimeoutSeconds() int64`; `ownership` gains `BodyReadTimeoutSeconds` (`bodyReadTimeoutSeconds`). Verify: `pkg/modsecurity` session test — changing only the new knob gives a different key and a different incarnation.
- [ ] 4.2 `pkg/modsecurity/inspect.go`: `Inspect(req, dl wafhop.ReadDeadliner)` replaces `failureAction`; delete the unreadable branch; `HasBody` → `ReadBody(req, c.bodyLimit, wafhop.RejectOverLimit, dl, c.bodyReadTimeout)`; update the doc comment's error list (`wafhop.ErrBodyReadTimeout`; `ErrUnavailable` no longer about the body). Verify: `go build ./...`.
- [ ] 4.3 `pkg/modsecurity/zzz_inspect_test.go`: migrate the 5 calls; delete `TestInspect_unreadableBodyFollowsAppsecRule` and `TestInspect_unreadableBodyWhileBackingOffIsGateSkip`; add: an unknown-length POST reaches the sidecar with its bytes (no `failureAction` input exists any more); an empty one reaches the sidecar and is allowed; a stalled one → `wafhop.ErrBodyReadTimeout`, sidecar not called; an unknown-length body over `modsecBodyLimit` → `ErrBodyTooLarge`. Verify: `go test ./pkg/modsecurity/ -count=1` green.
- [ ] 4.4 Docs: `docs/modsecurity.md` and the `bouncerModsecFailureAction` entry in `docs/configuration.md` drop the "streamed body without a length" rule and say that a body without `Content-Length` is read and inspected under `modsecBodyReadTimeoutSeconds`, so leaving out `Content-Length` no longer skips CRS. Verify: `rg -n "without a length|unreadable" docs/modsecurity.md docs/configuration.md` has no stale rule.

## 5. Bouncer answer, header, WARN, and operator docs

- [ ] 5.1 `pkg/bouncer/remediation_header.go`: `headerReasonBodyReadTimeout = "body-read-timeout"`. `pkg/bouncer/bouncer_serve_waf.go`: `handleBodyReadTimeoutServeHTTP(rw, req, leg, timeoutSeconds)` (design D6) with the two WARN message constants copied from spec `core_plugin_middleware_bouncer`. Verify: `go build ./...`.
- [ ] 5.2 `bouncer_serve_appsec.go`: pass `http.NewResponseController(rw)` to `Query`; add the `ErrBodyReadTimeout` case to `answerAppsecQueryError` (AppSec message, AppSec timeout). `bouncer_serve_modsec.go`: pass `http.NewResponseController(rw)` to `Inspect`; add the same case (ModSec message, ModSec timeout). Same order in both switches. Verify: `go vet ./pkg/bouncer/`.
- [ ] 5.3 `pkg/bouncer` tests (`zzz_modsec_test.go` `Query` call migrated): for each leg and each failure action, a stalled body without `Content-Length` → 400, `X-Remediation: error:body-read-timeout`, no dropped metrics, `next` not called; two timeouts within 5 s → one WARN per leg with `ip`, `method`, `host`, `path` (no query), `timeoutSeconds` (house log sink, `knowledge/devdocs/std_go_test_log-sink.md`); `bypassAppsec` / `bypassModsec` rows → that leg starts no read; restic shape (HTTP/2, empty body, no length) with both legs and default config → `next` called. Verify: `go test ./pkg/bouncer/ -count=1` green.
- [ ] 5.4 Docs: `docs/how-to/verdict-in-access-logs.md` gets the `error:body-read-timeout` row; `docs/failure-modes.md` (body-limit row, unreadable-body rule, failure-action scope), `docs/how-it-works.md` (body rule), and `docs/how-to/crowdsec-down.md` (if it describes body handling) stop describing the unreadable class and say the failure action covers only WAF failures. Add one sentence where body inspection is described: removing `Content-Length` no longer skips inspection on either leg. Verify: `rg -n -i "unreadable|without a length|IsBodyUnreadable" docs/` has no hit.
- [ ] 5.5 New page `docs/how-to/streaming-request-bodies.md`, listed in `docs/how-to/README.md`, that explains:
  - what is blocked and why (a body without `Content-Length` must end or reach the leg's body limit within that leg's timeout);
  - what passes: gRPC / Connect unary calls end and are inspected;
  - what is blocked: client-streaming and bidirectional gRPC, Connect client/bidi streaming, and long uploads without `Content-Length`;
  - what is not affected: WebSockets and response streaming;
  - YAML examples with `bouncerActionRules`: `bypassAppsec`, `bypassModsec`, and `bypass`, matched by gRPC service path, by host, by `Content-Type` combined with host or path, and a long-upload path with `method`;
  - the trade-off: matching requests are not inspected at all, LAPI decisions still apply unless the action is `bypass`, and `Content-Type` comes from the client, so always scope a rule with `host` and/or `path`;
  - a longer timeout as the alternative for slow but finite uploads;
  - HTTP/3 as expected, not measured.

  Verify: every relative link on the new page and in the files changed by 1.4, 4.4, and 5.4 resolves to an existing file or anchor.

## 6. Mock e2e (real Traefik v3.7.19, plugin under Yaegi)

- [ ] 6.1 `tests/e2e/mock/scenarios/appsec/dynamic.yml`: add `appsecBodyReadTimeoutSeconds: 2` (keys alphabetical; keep `appsecBodyLimit: 4`); add a second router only if a stalled line needs a different failure action. Verify: the scenario starts.
- [ ] 6.2 `tests/e2e/mock/scenarios/appsec/run.sh`: the two HTTP/2 lines at `:46-50` (both are POSTs; fix the "GET" label) expect `200`. Add:
  - HTTP/2 POST without `Content-Length`, body `a=0&` → `403`;
  - HTTP/2 DELETE without `Content-Length`, body `a=0&` → `403`;
  - HTTP/2 empty POST without `Content-Length` (restic shape) → `200`;
  - HTTP/1.1 chunked POST, body `a=0&` → `403`;
  - a stalled body per protocol (h2c with `--http2-prior-knowledge -H "Content-Length:"`, and HTTP/1.1 chunked) → `400` with `error:body-read-timeout` (when the scenario sets the remediation header name), using the client shape that works with curl (see #204 tasks 6.2: a body that ends late, checked against the Traefik access-log duration if curl cannot read an early answer).

  Verify: run the scenario locally (`knowledge/devdocs/build_e2e_mock.md`). Green.
- [ ] 6.3 Record whether Traefik v3.7.19 answered the HTTP/1.1 stall at the deadline (the controller reaches the connection under Yaegi) or only when the body ended. Write it on explore.md, open question on `SetReadDeadline` through Traefik (`By: implement`), and in the 5.5 page. If HTTP/1.1 is not cut, the assertion follows what was measured and the request stays blocked. Verify: the explore row and the doc agree with the run output.

## 7. Real e2e: ModSec through Traefik and CRS

- [ ] 7.1 `tests/e2e/real/config/dynamic/modsec.yml`: add a route (or a middleware) with `modsecBodyReadTimeoutSeconds: 2` for the stalled case. Keep the existing routes unchanged. Verify: the stack starts (`knowledge/devdocs/build_e2e_real.md`; local port remap per the repo's e2e note).
- [ ] 7.2 `tests/e2e/real/modsec.Tests.ps1`: with curl `--http2-prior-knowledge` against the h2c `web` entrypoint:
  - restic shape `POST /…?create=true`, empty body, no `Content-Length` → 200;
  - a CRS-triggering body already used in that file, sent without `Content-Length` → CRS block;
  - a stalled body on the 7.1 route → 400 with `error:body-read-timeout`.

  Use a Go client only where curl cannot shape the request. Verify: `Invoke-Pester tests/e2e/real/modsec.Tests.ps1` green locally; set `handoff.yaml` `localTests`.

## 8. Integration check

- [ ] 8.1 `go build ./... && go vet ./... && go test ./... -count=1` green; `golangci-lint run` if configured; root Yaegi test as CI runs it. Verify: `rg -n "IsBodyUnreadable|IsMethodWithBody|errUnreadableBody|unreadableBody" --glob '!openspec/changes/**' --glob '!devstate/**' --glob '!knowledge/**'` has no hits.
- [ ] 8.2 Walk the seven delta specs scenario by scenario against the tests from groups 1–7. Every scenario has a unit test or an e2e line, or a written reason why not (HTTP/3).

## Workflow follow-up

- Devdocs impact: `knowledge/devdocs/core_plugin_wafhop_shared-request.md` (Language "Unreadable body" goes; "Body read deadline" term; How to use; Gotcha "ReadBody treats 0 as no cap"), `core_plugin_appsec.md` (failure-action list, body limit, predicates), `core_plugin_modsecurity_inspect.md` (`Inspect` signature, streamed-body gotchas), `core_plugin_middleware_config-validation.md` (new keys, `appsecBodyLimit`).
- Archive: sync the seven deltas; edit the Purpose of `openspec/specs/core_plugin_appsec_failure-action/spec.md` to drop "or a request body that cannot be buffered for inspection"; regenerate `openspec/specs/map.md` (`validate-spec-map --write`).
- Pull request: title starts with `[NOMERGE] `. The description links upstream issue https://github.com/maxlerebourg/crowdsec-bouncer-traefik-plugin/issues/405, says this PR supersedes #204, and explains why not upstream #407 / #434 or the `crowdsecAppsecUnreadableBodyBlock: false` fallback (explore.md, Concepts › Upstream proposals, with #204's corrections).
