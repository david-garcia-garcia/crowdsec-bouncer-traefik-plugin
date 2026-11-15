## Purpose

`package wafhop` holds the inbound-request rules the WAF legs (AppSec and ModSec) share: which client bodies may be buffered, how one is buffered under a leg's limit, how a client that left is told apart from a broken body, and which headers stay off the WAF copy. Each leg keeps its own settings (`appsecBodyLimit`, `modsecBodyLimit`, FailureAction, FailMode); this package holds no setting.

## Requirements

### Requirement: One body rule set for every WAF leg
AppSec and ModSec SHALL decide body shape with `wafhop.HasBody`, `wafhop.IsBodyUnreadable` (a body on HTTP/2 or later with unknown length), and `wafhop.IsMethodWithBody` (POST, PUT, PATCH). Neither leg SHALL read an unreadable body. On an unreadable body with a body method, each leg SHALL apply its own fallback (AppSec FailureAction unless `passthrough`, ModSec FailMode `close`); otherwise it SHALL inspect headers only. Neither leg SHALL keep a private copy of these predicates.

#### Scenario: ModSec does not read a gRPC stream
- **WHEN** a POST arrives over HTTP/2 with no Content-Length
- **AND** `bouncerModsecFailMode` is `open`
- **THEN** ModSec does not read the body
- **AND** the sidecar receives the request with no body

#### Scenario: ModSec close drops an uninspectable POST
- **WHEN** a POST arrives over HTTP/2 with no Content-Length
- **AND** `bouncerModsecFailMode` is `close`
- **THEN** the response is an empty HTTP 502

### Requirement: ReadBody buffers under the leg's limit and restores the body
`wafhop.ReadBody(req, limit, mode)` SHALL buffer the client body and SHALL replace `req.Body` so `next` reads every client byte. `TruncateAtLimit` (AppSec) SHALL return at most `limit` bytes. `RejectOverLimit` (ModSec) SHALL return `ErrBodyTooLarge` for a body longer than `limit`. A `limit` of 0 or less SHALL mean no cap. It SHALL read at most `limit + 1` bytes when capped and MUST NOT size a buffer from an uncapped Content-Length. A body an earlier leg buffered whole and nobody read since SHALL be returned without a second read or copy, and SHALL still be checked against this leg's limit.

#### Scenario: AppSec truncation keeps the rest for origin
- **WHEN** `appsecBodyLimit` is 4 and the body is `0123456789`
- **THEN** AppSec receives `0123`
- **AND** `next` reads `0123456789`

#### Scenario: Both legs share one buffer
- **WHEN** AppSec and ModSec are both subscribed and the body is shorter than both limits
- **THEN** the client body is read once
- **AND** ModSec forwards the same bytes AppSec buffered

#### Scenario: ModSec limit still applies to a reused body
- **WHEN** AppSec buffered a 10-byte body whole
- **AND** `modsecBodyLimit` is 5
- **THEN** ModSec answers HTTP 413

### Requirement: Client-body failures are classified once
A read failure while buffering SHALL be `ErrClientDisconnected` when the inbound request context is done or the error is `context.Canceled`, `context.DeadlineExceeded`, or `io.ErrUnexpectedEOF`; any other read failure SHALL wrap `ErrClientBodyRead`. `appsec.ErrClientDisconnected` and `appsec.ErrClientBodyRead` SHALL be these same values. For either leg the bouncer SHALL answer `ErrClientDisconnected` without writing (optional `error:client-disconnected` header) and `ErrClientBodyRead` with HTTP 400 (optional `error:client-body-read` header), with no ban, no dropped metrics, no origin, and no leg fallback. Around the WAF call itself a leg SHALL use `wafhop.IsInboundCanceled`, so the WAF client's own timeout stays a WAF failure.

#### Scenario: ModSec upload reset is not a 502
- **WHEN** the client resets while ModSec buffers its body
- **THEN** ModSec does not call the sidecar
- **AND** the bouncer writes nothing and does not apply FailMode

#### Scenario: Sidecar timeout is a WAF failure
- **WHEN** the sidecar does not answer within `modsecHttpTimeoutSeconds`
- **THEN** the request follows `bouncerModsecFailMode`
- **AND** the gate records a failure

### Requirement: The WAF copy omits a static hop-by-hop list
Both legs SHALL build the WAF copy with `wafhop.CopyEndToEndHeaders`, omitting `Connection`, `Keep-Alive`, `Proxy-Authenticate`, `Proxy-Authorization`, `Proxy-Connection`, `TE`, `Trailer`, `Trailers`, `Transfer-Encoding`, `Upgrade`, and the client `Content-Length`. Names the client lists in its own `Connection` header MUST still be copied, and the list MUST NOT be a pattern, so a client cannot hide a header from the WAF. The AppSec verdict relay and the ModSec copied block SHALL use `wafhop.IsHopByHopHeader` for the same list.

#### Scenario: Connection cannot hide Cookie
- **WHEN** the client sends `Connection: Cookie` and a `Cookie` header
- **THEN** the WAF copy carries `Cookie`

#### Scenario: WebSocket handshake copy has no Upgrade
- **WHEN** a WebSocket handshake is inspected by ModSec
- **THEN** the sidecar copy has no `Upgrade` or `Connection` header
- **AND** the request passed to `next` keeps both
