## Context

See proposal.md for motivation. Dest `handleNextServeHTTP` already owns the AppSec-then-next seam. `appsecQuery` returns nil on HTTP 200 and on 500/unreachable when the matching `*Block` flag is false. Dest does not parse AppSec JSON envelopes. Trusted IPs skip in `ServeHTTP` before this function. Client address is `ip.GetRemoteIP`; path is `req.URL.Path`.

## Goals / Non-Goals

**Goals:**

- One check after a successful AppSec query: challenge-prefix paths 404 without `next`.
- Same 404 for passthrough-as-allow (nil error) as for HTTP 200.

**Non-Goals:**

- Relaying challenge/captcha JSON (dest does not do that today).
- Changing `appsecQuery` status mapping or trusted-IP skip.
- Bootstrapping a live OpenSpec catalog.

## Decisions

- **Where.** After `appsecQuery` returns nil inside `handleNextServeHTTP`, only when `appsecEnabled`. Alternative: inside `appsecQuery` — rejected; that function's job is the round-trip. Alternative: `ServeHTTP` before AppSec — rejected; a real AppSec ban/error on the prefix must still write as today.
- **Prefix.** `strings.HasPrefix(req.URL.Path, "/crowdsec-internal/challenge/")`. Trailing slash matches official `/*` and upstream PR 403 point 4. Bare `/crowdsec-internal/challenge` is not terminated.
- **Response.** `http.NotFound(rw, req)`. No custom body.
- **Constant.** `appsecChallengePathPrefix` next to the other AppSec header constants so the prefix is named once.
- **Tests.** Table or two cases in `bouncer_test.go`: `custom.js` 404 / `next` false; `/protected` allow still calls `next`.
- **Docs.** README AppSec section; no `openspec/specs/` leaf.

## Risks / Trade-offs

- [Bare `/crowdsec-internal/challenge` still reaches origin] → Traefik `PathPrefix` often includes it; operators who need that exact path covered can add a slash-terminated route. Prefix matches the ticket and upstream.
- [AppSec off still forwards the prefix] → intended: AppSec is not in use. Do not 404 when `appsecEnabled` is false.
- [Upstream PR 403 also changes captcha/metrics/unknown types] → out of scope; do not copy their patch.

## Migration Plan

Deploy with the plugin as usual. Rollback is the previous binary: challenge-prefix allows reach origin again. No persistent storage.

## Open Questions

None. Remaining assumed rows live on `devstate/explore.md`.
