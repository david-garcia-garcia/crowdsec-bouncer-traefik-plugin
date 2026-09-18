# AppSec query: connection drain, body forwarding, and unreadable DELETE

Source: triage of stale PRs #35 and #43, revalidated against `master` at `340734f`. Both live in
`pkg/appsec/query.go`, so they are one ticket. Neither branch is mergeable: they conflict on
`query.go`, `test_client.go` and the AppSec spec and devdoc, and they predate the hot-swappable
transport of #64, so this is a re-implementation on current code.

The cost-versus-benefit filter has already been applied to what follows. Everything below is a
defect on a common path with a small, contained fix. Do not widen the scope beyond it.

## 1. The response body is not drained when AppSec is unavailable

`Query` calls `Do` and, when the AppSec listener answers 502, 503 or 504, returns before
`drainResponse` runs, because the `defer` is installed after that early return
(`pkg/appsec/query.go:103-108`). An undrained, unclosed response body cannot be reused by the
keep-alive pool, so exactly when the AppSec component is unhealthy the plugin also starts leaking
connections to it. Drain and close before every return path.

## 2. An unlimited body limit silently stops forwarding the body

`appsecBodyLimit == 0` is meant to mean "no limit", but it falls through to the `default` branch
and the request is forwarded as a GET without its body (`pkg/appsec/query.go:162`). So the one
setting an operator would choose to have AppSec inspect everything is the setting that makes it
inspect nothing. Treat zero as unlimited.

## 3. A read failure on the AppSec body bypasses the failure action

When reading the response body from AppSec fails, the error does not travel through
`FailureAction` (`pkg/appsec/query.go:116-117`), so a configured `ban` or `captcha` on AppSec
failure is not applied for that class of failure while it is applied for others. Route it through
the same policy as the rest.

## 4. The outbound Content-Length is not rebuilt

Headers are copied verbatim onto the outbound request (`pkg/appsec/query.go:133-137`). When the
forwarded body differs in length from the original, the stale `Content-Length` goes with it.
Rebuild it from what is actually being sent.

## 5. An unreadable DELETE is treated as a request that had a body

`isMethodWithBody` still lists DELETE (`pkg/appsec/query.go:81-84`). Over HTTP/3 a DELETE arrives
with `ContentLength < 0` and no readable body, so it takes the "unreadable body" path and is
dropped or banned (`pkg/appsec/query.go:157-158`), even though a DELETE was never going to carry
one. Take DELETE out of that set. POST, PUT and PATCH keep their current behaviour: an unreadable
body on a method that should have had one is still handled by the existing policy.

This is deliberately independent of the open question about gRPC streams (PR #51). Whatever is
decided there, a DELETE should not be dropped for a body it was never sending.

## Constraints

- **Build on the current transport.** #64 made the AppSec transport hot-swappable behind
  `atomic.Value`. Read it through the existing accessor (`currentTransport()` / the current key),
  and in the test helper store into the transport rather than assigning an `httpClient` field. Do
  not restore removed fields such as a stored `httpClient` or a duplicated `appsecKey`.
- **Do not reintroduce `crowdsecAppsecUnreadableBodyBlock`.**
  `openspec/specs/core_plugin_appsec_failure-action/spec.md` removed that knob deliberately. This
  ticket does not add a configuration option; every item above is a correctness fix with no new
  public surface.
- **Yaegi v0.16 is the runtime.** `go test .` at the repository root is the interpreter test,
  around 50 seconds, and it is the one that catches what compilation does not. No generic
  `atomic.Pointer[T]` as a struct field consumed from another package.

## Definition of done

- The five defects fixed, each with a test that fails before the fix.
- The AppSec spec leaves and devdoc updated where behaviour they describe has changed, in
  particular the unreadable-body scenarios and the meaning of a zero body limit.
- PRs #35 and #43 referenced in the PR body as the origin of the requirement, so they can be
  closed when this lands.
