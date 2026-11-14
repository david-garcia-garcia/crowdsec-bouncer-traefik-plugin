# Cut a stalled HTTP/1.1 AppSec body read at `appsecBodyReadTimeoutSeconds` behind Traefik

IssueKey: 2026-11-14-appsec-unknown-length-body
Size: large
Action: note

## Why this follow-up
Behind Traefik v3.7.11 (mock e2e, plugin under Yaegi), the body read deadline cannot cut an HTTP/1.1 chunked read: `http.ResponseController.SetReadDeadline` does not reach Traefik's connection through the writer the plugin receives, and `Body.Close` waits for the in-flight `Read`. The request is still blocked (`ban:appsec-body-timeout`), but the answer is sent only when the client ends or abandons its body, or at Traefik's entrypoint `readTimeout`. HTTP/2 is cut at the deadline. Until then the handler goroutine and the connection stay busy for a stalled HTTP/1.1 client.

## Why it was not taken
The cause is outside this repository: which Traefik `ResponseWriter` wrapper hides `Unwrap` / `SetReadDeadline` was not determined, and a fix would be a Traefik change (or an upstream report), not plugin code. The ticket's contract (fail-closed block) holds either way.

## Risks
- A slow-loris style HTTP/1.1 client holds a Traefik handler until Traefik's `readTimeout` (60 s by default, none if `0`).
- Operators reading the README might expect the 403 at `appsecBodyReadTimeoutSeconds` on HTTP/1.1; the README states the measured behaviour.

## Context
- Measurement: `tests/e2e/mock/scenarios/appsec/run.sh` (body read timeout block), `knowledge/research/std_go_net-http_body-read-deadline/notes.md` (Measured later).
- Plugin side: `pkg/appsec/query.go` `readClientBodyForAppsec`; `pkg/bouncer/bouncer.go` `applyAppsecServeHTTP` builds `http.NewResponseController(rw)`.
