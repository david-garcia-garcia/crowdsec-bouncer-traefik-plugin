# Captcha request routing: solved-form POST and custom challenge resources

Source: triage of stale PRs #48 and #50, revalidated against `master` at `340734f`.
Both describe the same hole in `pkg/bouncer/bouncer.go` `handleRemediationServeHTTP`, so they
are one ticket. The two branches themselves are not mergeable (content conflicts across
`pkg/captcha/captcha.go`, `pkg/bouncer/bouncer.go` and their `zzz_` tests, and their code
predates the HMAC cookie gate of #58 and the `Client.New` signature of today), so this is a
re-implementation on current code, not a rebase.

## Problem 1: a solved captcha form POST reaches the origin

Once the visitor solves the captcha, the plugin sets the gate cookie and the next request is
allowed through. But the request that carries the solution is itself a POST to the protected
URL, and it is forwarded upstream as a POST. Origins that only accept GET on that path answer
405, so the visitor solves the captcha correctly and still lands on an error page.

Today `handleRemediationServeHTTP` hands anything that passes `Check` straight to
`handleNextServeHTTP` (`pkg/bouncer/bouncer.go:300-303`) with no notion of "this request is the
captcha form submission". The fix is an early redirect: when the request is the captcha form
POST and the gate now allows the visitor, answer a 302 back to the same URL instead of
forwarding the POST body upstream.

Reuse what already exists. `pkg/captcha/captcha.go:136-167` already parses the captcha response
out of the request and restores the body afterwards, so do not add a second body reader.

## Problem 2: custom challenge resources never reach the origin, and HEAD gets banned

With a custom captcha provider, the challenge page pulls its own assets (the challenge script,
the widget endpoint). Those requests are themselves remediated, so the assets never load and the
challenge cannot render.

Related, and in the same function: `handleRemediationServeHTTP` requires `Method != HEAD` before
it considers serving a captcha (`pkg/bouncer/bouncer.go:300`), so a HEAD request against a
captcha-remediated URL falls through to the ban branch instead. A HEAD should be treated like the
GET it previews.

The needed behaviour is a passthrough: requests that target the configured custom challenge
resources go to the origin even while the visitor is under captcha remediation, and HEAD is not
excluded from the captcha path.

## Constraints that the old branches violate and this ticket must respect

- **No cache keys for captcha grace.** `openspec/specs/core_plugin_middleware_captcha-gate/spec.md`
  states the gate MUST NOT read or write cache keys for grace. #58 replaced the old
  `{ip}_captcha` cache entry with a stateless HMAC cookie. Decide "is this visitor past the
  captcha" through `Check(req, remoteIP)` and the cookie, never through the cache.
- **Do not touch the stream lease.** #66 replaced the read-then-write lease with
  `Cache().Acquire` (`pkg/lapi/client_stream.go:72-73`). Nothing in this ticket goes near it.
- **Yaegi v0.16 is the runtime.** The plugin is interpreted, so `go build` passing is not enough:
  `go test .` at the repo root is the interpreter test and it is the one that catches the real
  failures. No generic `atomic.Pointer[T]` as a struct field consumed from another package; use
  `atomic.Value`. Prefer plain, boring constructs over clever ones.
- The passthrough must not become a bypass. A request that matches the custom-resource rule must
  not be able to smuggle arbitrary paths past remediation: scope it to what the configured
  challenge URL actually needs, and say in the spec why that scope is safe.

## Definition of done

- Both behaviours implemented on today's code, with tests that fail before the fix.
- The spec leaves that own this behaviour updated (or a new leaf created) so the routing rules of
  `handleRemediationServeHTTP` are written down: which requests bypass remediation and why.
- PRs #48 and #50 are referenced in the PR body as the origin of the requirement, so they can be
  closed once this lands.
