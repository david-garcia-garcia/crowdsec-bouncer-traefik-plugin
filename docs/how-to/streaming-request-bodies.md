[Documentation](../README.md) › [How-to](README.md) › Run streaming request bodies through the WAF legs

# Run streaming request bodies through the WAF legs

AppSec and ModSec read the request body before they judge a request. A body without `Content-Length` (HTTP/1.1 chunked, or HTTP/2 and HTTP/3 without the header) is read like any other, under a total deadline per WAF: [`appsecBodyReadTimeoutSeconds`](../configuration.md#appsecbodyreadtimeoutseconds) and [`modsecBodyReadTimeoutSeconds`](../configuration.md#modsecbodyreadtimeoutseconds), 30 seconds by default. The body must end, or reach that WAF's body limit, within the timeout. Otherwise the request is blocked with HTTP 400 and the verdict header `error:body-read-timeout`, whatever the failure action says, and Traefik logs a WARN line that names the request.

Leaving out `Content-Length` therefore no longer skips inspection, on either WAF. A request body that never ends is blocked on every route where that WAF runs.

## What passes, what is blocked

| Request | Result |
| ------- | ------ |
| gRPC or Connect unary call | Passes. The body ends after one message and is inspected. |
| An upload without `Content-Length` that ends within the timeout | Passes after inspection. The WAF sees at most its body limit; with AppSec, the rest reaches your application uninspected. |
| An empty POST without `Content-Length` (for example `restic init` against `rest-server`) | Passes after inspection. |
| gRPC client streaming or bidirectional streaming | Blocked after the timeout: the request body stays open for the life of the call. |
| Connect client or bidirectional streaming | Blocked after the timeout, for the same reason. |
| A long upload without `Content-Length` that does not finish within the timeout | Blocked. With the defaults a client must send 10 MB to AppSec in 30 s, about 2.8 Mbit/s. |
| WebSockets | Not affected: the handshake is a GET without a body. |
| Response streaming (server-sent events, gRPC server streaming, downloads) | Not affected: only the request body is read. |
| A body with a `Content-Length` | Not affected by these timeouts. Traefik's entry point `readTimeout` still applies. |

## Exclude a streaming route

Skip the WAF on the routes that stream request bodies with [`bouncerActionRules`](../configuration.md#bounceractionrules). `bypassAppsec` skips AppSec, `bypassModsec` skips ModSec, and `bypass` skips LAPI, AppSec, and ModSec. Use the action for the WAFs that run on that router.

A gRPC service, matched by its path (`/<package>.<Service>/<Method>`):

```yaml
bouncerActionRules:
  - name: grpc-signal-stream
    path: "^/signalexchange\\.SignalExchange/"
    action: [bypassAppsec, bypassModsec]
```

A host that only serves streaming RPCs:

```yaml
bouncerActionRules:
  - name: grpc-host
    host: "^grpc\\.example\\.com$"
    action: [bypassAppsec, bypassModsec]
```

gRPC by `Content-Type`, always together with a host or a path:

```yaml
bouncerActionRules:
  - name: grpc-on-api-host
    host: "^api\\.example\\.com$"
    headers:
      Content-Type: "^application/grpc"
    action: [bypassAppsec, bypassModsec]
```

A long-upload endpoint, limited to its method:

```yaml
bouncerActionRules:
  - name: large-uploads
    method: "^(POST|PUT)$"
    path: "^/upload/"
    action: [bypassModsec]
```

A route that must skip every CrowdSec check, LAPI decisions included:

```yaml
bouncerActionRules:
  - name: internal-stream
    host: "^stream\\.internal\\.example\\.com$"
    action: [bypass]
```

A `bypass`, `bypassAppsec`, or `bypassModsec` rule with a `path` skips nothing when the path can be read more than one way, and never skips AppSec under `/crowdsec-internal/challenge/` (see [`bouncerActionRules`](../configuration.md#bounceractionrules)).

## What you give up

- A matching request is not inspected at all by the WAF the rule skips: not its headers, not the first bytes of its body.
- LAPI decisions still apply with `bypassAppsec` and `bypassModsec`: a banned IP is still banned. Only `bypass` skips them too.
- `Content-Type`, like every header, comes from the client. A rule that matches on `Content-Type` alone lets any client skip the WAF by sending that header. Always scope it with `host`, `path`, or both.

## Slow but finite uploads

When the body does end, but more slowly than the timeout allows, raise the timeout of that WAF instead of skipping it:

```yaml
appsecBodyReadTimeoutSeconds: 120
modsecBodyReadTimeoutSeconds: 120
```

The timeout is the total time to receive the body up to the WAF's limit, not the time between two bytes. When ModSec runs next to AppSec and [`modsecBodyLimit`](../configuration.md#modsecbodylimit) is larger than [`appsecBodyLimit`](../configuration.md#appsecbodylimit), ModSec reads the rest under its own timeout, so the longest wait is the sum of both.

## How fast the block arrives

The plugin cuts the read when the timeout fires and answers at once, without waiting for the client to end its body. Measured with Traefik v3.7.19 in this repository's end-to-end tests: with a 2 s timeout, a stalled HTTP/1.1 chunked body and a stalled HTTP/2 body are both answered HTTP 400 after 2.0 s, while the client only ends its body after 5 s. HTTP/3 is expected to behave the same way, but is not measured.
