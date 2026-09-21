**Describe the bug** 🐛

When AppSec body inspection is active, `appsecQuery` buffers the request body before forwarding it. If the **client** goes away mid-body — cancels an HTTP/2 stream, backgrounds a mobile app, drops off wifi — `io.ReadAll` returns an error, and the plugin converts that read failure into a **ban**. The request is answered `403` with `ReasonAPPSEC`, and the access log attributes the block to CrowdSec even though CrowdSec never saw the request.

The buffering branch, and the caller that turns any error into a ban:

```go
case bouncer.appsecBodyLimit > 0 && httpReq.Body != nil:
    limitedReader := io.LimitReader(httpReq.Body, bouncer.appsecBodyLimit)
    teeReader := io.TeeReader(limitedReader, &bodyBuffer)
    bodyBytes, err := io.ReadAll(teeReader)
    if err != nil {
        return fmt.Errorf("appsecQuery:GetBody %w", err)   // ← client aborted, not an attack
    }
```

```go
if err := appsecQuery(bouncer, remoteIP, req); err != nil {
    bouncer.handleBanServeHTTP(rw, req, remoteIP, configuration.ReasonAPPSEC)
    return
}
```

Still present on `main` (`710e888`) — the signature changed to `return nil, fmt.Errorf("appsecQuery:GetBody %w", err)` in the bot-detection PR, but the semantics are the same.

**Three things make this hard to diagnose, which is most of why I'm reporting it:**

1. **None of the fail-open options apply.** `crowdsecAppsecFailureBlock` guards an AppSec `500`; `crowdsecAppsecUnreachableBlock` guards AppSec being unreachable; `crowdsecAppsecUnreadableBodyBlock` guards the *by-design* unreadable case in `isBodyUnreadable` (HTTP/2+ with no `Content-Length`). A mid-stream read failure is none of those, so it fails **closed** with all three set to `false`.
2. **It is invisible at the default log level.** Every 403 path in `ServeHTTP` / `handleNextServeHTTP` logs at `DEBUG`; only `getRemoteIp`, `checkerContains`, `appsecQuery:unreachable` and the AppSec `500` log above it. At `INFO` a storm of these produces **zero** plugin log lines, which is what sent me looking at CrowdSec first — `cscli decisions list` was empty, `cscli alerts list` showed nothing for the client, and the AppSec container had logged the source as allowlisted and skipped.
3. **`crowdsecAppsecBodyLimit` defaults to `10485760`, not `0`.** Leaving it unset does not mean "no body inspection" — it puts every POST with a body through the buffering branch. Easy to assume otherwise from the docs.

**Expected behavior** 👀

A body read failure caused by the client disconnecting should not be a ban. If the client is gone there is nothing to protect against and nothing to serve the 403 to. I'd expect either:

- treat a read error on the **client** body as "client gone" and stop processing (or pass through), the same spirit as the existing `isBodyUnreadable` handling; or
- gate it behind an existing/new fail-open option so operators can choose — right now there is no configuration that avoids it.

Distinguishing a client-side cancellation (`context.Canceled`, `http2.StreamError` with `CANCEL`, `io.ErrUnexpectedEOF`) from a genuine read fault would be enough.

**To Reproduce**

No CrowdSec decision or AppSec rule needed — the source IP can even be allowlisted.

1. Put the bouncer in front of any backend with `crowdsecAppsecEnabled: true` and `crowdsecAppsecBodyLimit` left at its default.
2. Set `logLevel: DEBUG` on the middleware.
3. Send a large POST over HTTP/2 and abort it mid-body, e.g.
   `curl --max-time 2 --limit-rate 60k -F "f=@5mb.bin" https://<host>/<upload-path>`
4. Repeat a few times.

Observed (IPs and hostname anonymised):

```
level=DEBUG msg="handleNextServeHTTP ip:<client-ip> isWaf:true appsecQuery:GetBody stream error: stream ID 5; CANCEL"
level=DEBUG msg="handleNextServeHTTP ip:<client-ip> isWaf:true appsecQuery:GetBody stream error: stream ID 7; CANCEL"
level=DEBUG msg="handleNextServeHTTP ip:<client-ip> isWaf:true appsecQuery:GetBody stream error: stream ID 9; CANCEL"
```

Traefik access log for those three, next to one upload allowed to complete:

| status | OriginStatus | ServiceName | proto | RequestContentSize |
|---|---|---|---|---|
| 401 (from backend) | 401 | present | HTTP/2.0 | 5,000,438 |
| **403** | **0** | **absent** | HTTP/2.0 | 131,072 |
| **403** | **0** | **absent** | HTTP/2.0 | 131,072 |
| **403** | **0** | **absent** | HTTP/2.0 | 131,072 |

`OriginStatus: 0` with no `ServiceName` = terminated by the middleware, never reached the backend. `RequestContentSize` is only the bytes that arrived before the abort.

**Real-world symptom:** a phone photo-backup client produced 34 of these in a day against an otherwise healthy service — bursty, bodies from 0 bytes to ~3.4 MB, while uploads that completed in the same window went up to ~92 MB. So it is not a size threshold; it tracks how often the client cancels. Uploads themselves still succeed on retry, so the practical damage is modest — but the requests are counted as dropped in the metrics pushed to LAPI, and the access log misrepresents what CrowdSec is doing.

**Relevant config** (redacted)

```yaml
crowdsecMode: appsec
crowdsecAppsecEnabled: true
crowdsecAppsecFailureBlock: false
crowdsecAppsecUnreachableBlock: false
crowdsecAppsecUnreadableBodyBlock: false
crowdsecAppsecHost: <appsec-host>:7422
crowdsecLapiHost: <lapi-host>:8080
crowdsecLapiScheme: http
# crowdsecAppsecBodyLimit not set → 10485760
```

**Version**
- OS: Docker (Kubernetes, Talos Linux)
- Traefik version: 3.7.11, chart 41.0.1, Gateway API provider
- Plugin version: 1.7.1 (also confirmed on `main`, `710e888`)
- Redis: not used

**Context** 🔎

Found and reproduced with `logLevel: DEBUG` as the template asks. One genuinely useful side effect worth noting for anyone else debugging: DEBUG cleanly separates the two causes of a 403 that the access log cannot — a real AppSec block logs `appsecQuery statusCode:403`, while this defect logs `appsecQuery:GetBody …`.

Happy to open a PR if you'd like it fixed that way — say which shape you'd prefer (silent pass-through vs. a new option).

<sub>Investigation and write-up done with Claude Code; the reproduction, logs and version checks above are from a live deployment.</sub>
