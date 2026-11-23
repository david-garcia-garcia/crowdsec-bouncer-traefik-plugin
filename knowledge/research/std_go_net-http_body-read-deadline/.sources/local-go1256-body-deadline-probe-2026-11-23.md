---
url: session scratchpad probe (not in tree): scratchpad/probe/main.go (Go) and scratchpad/yprobe/main.go (Yaegi), session 17696c9f-ede9-4585-a730-94aa61621c26
title: Request body read deadline probe with timer flag and IsClientGone (Go 1.25.6, Yaegi v0.16.1)
fetched: 2026-11-23
authority: inference
---

Go 1.25.6 windows/amd64. One `http.Server` per case on 127.0.0.1; HTTP/1 only, or HTTP/1 + unencrypted HTTP/2 via `http.Protocols.SetUnencryptedHTTP2(true)` on server and Transport (h2c rows).

Handler: `rc := http.NewResponseController(w)`; `t := time.AfterFunc(300ms, func(){ if rc.SetReadDeadline(time.Now()) != nil { r.Body.Close() } })`; `io.ReadAll(io.LimitReader(r.Body, 1<<20))`; `fired := !t.Stop()`; `http.Error(w, "blocked", 400)`.
`isClientGone` = copy of `wafhop.IsClientGone`: `r.Context().Err() != nil || errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) || errors.Is(err, io.ErrUnexpectedEOF)`.
Client: POST, `ContentLength = -1`, body = `io.Pipe` writing `"ab"` and closing after 3 s (or closing at once for the empty-body row), client timeout 5 s.

| case | proto | CL | read | err | after | fired | ctx.Err() | isClientGone | os.ErrDeadlineExceeded | client |
|------|-------|----|------|-----|-------|-------|-----------|--------------|------------------------|--------|
| chunked, never-ending | HTTP/1.1 | -1 | 2 | `read tcp …: i/o timeout` | 300 ms | true | `context canceled` | true | true | 400 at 300 ms |
| h2c, never-ending | HTTP/2.0 | -1 | 2 | `i/o timeout` | 300 ms | true | nil | false | true | 400 at 300 ms |
| h2c, empty body (restic `?create=true` shape) | HTTP/2.0 | -1 | 0 | nil | 0 s | false | nil | false | false | 400 at 0 s |

`Body == http.NoBody` was false in all three rows.

Yaegi row: same HTTP/1.1 handler (`body := r.Body` captured for the fallback), run with `yaegi run main.go` using a binary built from the module cache `github.com/traefik/yaegi@v0.16.1/cmd/yaegi` (the binary reports `version devel`):

```
server: read=2 err=read tcp 127.0.0.1:…: i/o timeout after=300ms fired=true
client: status=400 after=300ms
```

Re-run 2026-11-23 by the research sub-agent with identical output.
