---
url: C:\Users\DAVIDG~1\AppData\Local\Temp\claude\6c6ddc6106f2992b\2987d4cf-a96b-41ed-81db-1e857bb896ae\scratchpad\probe\main.go
title: Server request body read deadline probe (Go 1.25.6)
fetched: 2026-11-14
authority: inference
---

Go 1.25.6 windows/amd64. One `http.Server` per case on 127.0.0.1. HTTP/2 = unencrypted via `http.Protocols.SetUnencryptedHTTP2(true)` on server and Transport. Client: POST, `ContentLength = -1`, body = `io.Pipe` that writes `"ab"` and never ends (client closes it after 3 s with no response). Deadline 300 ms. Handler writes 403 after the read. Output file: `C:\Users\DAVIDG~1\AppData\Local\Temp\claude\6c6ddc6106f2992b\2987d4cf-a96b-41ed-81db-1e857bb896ae\tasks\biohez3t3.output`. HTTP/1 rows are chunked (`CL=-1`).

| case | ReadAll returned | error | client saw |
|------|------------------|-------|------------|
| h2, `time.AfterFunc` -> `r.Body.Close()` | 300 ms | `body closed by handler` (not context, not os deadline) | 403 at 300 ms |
| h1, `time.AfterFunc` -> `r.Body.Close()` | 3 s, only when the client ended its body | nil | 403 at 3 s (deadline not enforced) |
| h2, `time.AfterFunc` -> `http.NewResponseController(w).SetReadDeadline(time.Now())` | 300 ms | `i/o timeout`; `errors.Is(os.ErrDeadlineExceeded)`=true, `context.DeadlineExceeded`=false | 403 at 300 ms |
| h1, same ResponseController call | 300 ms | `read tcp ...: i/o timeout`; os.ErrDeadlineExceeded=true, context.DeadlineExceeded=false | 403 at 300 ms |
| h2, `Server.ReadTimeout` 500 ms, plain ReadAll | 500 ms | `i/o timeout`; os.ErrDeadlineExceeded=true, context.DeadlineExceeded=false | 403 at 500 ms |
| h1, `Server.ReadTimeout` 500 ms | 500 ms | `read tcp ...: i/o timeout`; os.ErrDeadlineExceeded=true, context.DeadlineExceeded=false | 403 at 500 ms |
| h2, ReadAll in a goroutine, handler gives up at 300 ms, no cancel (upstream PR #407 shape) | background read at 300 ms, when the handler returned and the stream closed | `stream error: stream ID 1; NO_ERROR` | 403 at 300 ms |
| h1, same goroutine shape | handler returned at 300 ms; background read at 3 s when the client ended its body | nil | 403 at 3 s |
| h2 POST, client body = pipe closed with no data (restic `?create=true` shape) | 0 s, len 0 | nil | 403 at 0 s; server saw `ContentLength=-1`, `Body != http.NoBody` |
| h2, `ReadTimeout` 5 s plus ResponseController deadline at 300 ms | 300 ms | os.ErrDeadlineExceeded=true | 403 at 300 ms |

`SetReadDeadline` returned nil in every ResponseController case (writer was the stdlib one, no wrapper).
