## Purpose

`package wafhop` holds the inbound-request rules the WAF legs (AppSec and ModSec) share: how a client body is buffered under a leg's limit and, when it has no `Content-Length`, under the leg's total read deadline; how that deadline, a client that left, and a broken body are told apart; and which headers stay off the WAF copy. Each leg keeps its own settings (`appsecBodyLimit`, `modsecBodyLimit`, `appsecBodyReadTimeoutSeconds`, `modsecBodyReadTimeoutSeconds`, `bouncerAppsecFailureAction`, `bouncerModsecFailureAction`); this package holds no setting.

## Requirements

### Requirement: ReadBody buffers under the leg's limit and restores the body
`wafhop.ReadBody` SHALL take the leg's limit, limit mode, read deadline, and per-request read-deadline control. It SHALL buffer the client body and SHALL replace `req.Body` so `next` reads every client byte. `TruncateAtLimit` (AppSec) SHALL return at most `limit` bytes. `RejectOverLimit` (ModSec) SHALL return `ErrBodyTooLarge` for a body longer than `limit`. `limit` SHALL be positive: there is no uncapped mode, and every caller SHALL pass its leg's effective limit. It SHALL read at most `limit + 1` bytes and MUST NOT size a buffer from a Content-Length larger than `limit`. A body an earlier leg buffered whole and nobody read since SHALL be returned without a second read or copy, SHALL still be checked against this leg's limit, and SHALL NOT start this leg's read deadline.

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

#### Scenario: A reused body does not wait again
- **WHEN** AppSec buffered a body of unknown length whole
- **THEN** ModSec returns the same bytes without reading from the client
- **AND** ModSec's read deadline does not start

### Requirement: Client-body failures are classified once
A read failure while buffering SHALL be `ErrClientDisconnected` when the inbound request context is done or the error is `context.Canceled`, `context.DeadlineExceeded`, or `io.ErrUnexpectedEOF`; any other read failure SHALL wrap `ErrClientBodyRead`. When the leg's read deadline expired during the read, the result SHALL be `ErrBodyReadTimeout` whatever the read returned, and that check SHALL come before the client-disconnect check. `appsec.ErrClientDisconnected` and `appsec.ErrClientBodyRead` SHALL be these same values. For either leg the bouncer SHALL answer `ErrClientDisconnected` without writing (optional `error:client-disconnected` header), `ErrClientBodyRead` with HTTP 400 (optional `error:client-body-read` header), and `ErrBodyReadTimeout` with HTTP 400 (optional `error:body-read-timeout` header, `core_plugin_middleware_bouncer`), with no ban, no dropped metrics, no origin, and no leg fallback. Around the WAF call itself a leg SHALL use `wafhop.IsInboundCanceled`, so the WAF client's own timeout stays a WAF failure.

#### Scenario: ModSec upload reset is not a failure
- **WHEN** the client resets while ModSec buffers its body
- **THEN** ModSec does not call the sidecar
- **AND** the bouncer writes nothing and does not apply `bouncerModsecFailureAction`

#### Scenario: Sidecar timeout is a WAF failure
- **WHEN** the sidecar does not answer within `modsecHttpTimeoutSeconds`
- **THEN** the request follows `bouncerModsecFailureAction`
- **AND** the gate records a failure

#### Scenario: A deadline cut is not a disconnect
- **WHEN** the read deadline cuts an HTTP/1.1 chunked body read
- **AND** the cut cancels the inbound request context
- **THEN** `ReadBody` returns `ErrBodyReadTimeout`, not `ErrClientDisconnected`

### Requirement: The WAF copy omits a static hop-by-hop list
Both legs SHALL build the WAF copy with `wafhop.CopyEndToEndHeaders`, omitting `Connection`, `Keep-Alive`, `Proxy-Authenticate`, `Proxy-Authorization`, `Proxy-Connection`, `TE`, `Trailer`, `Trailers`, `Transfer-Encoding`, `Upgrade`, and the client `Content-Length`. Names the client lists in its own `Connection` header MUST still be copied, and the list MUST NOT be a pattern, so a client cannot hide a header from the WAF. The AppSec verdict relay and the ModSec copied block SHALL use `wafhop.IsHopByHopHeader` for the same list.

#### Scenario: Connection cannot hide Cookie
- **WHEN** the client sends `Connection: Cookie` and a `Cookie` header
- **THEN** the WAF copy carries `Cookie`

#### Scenario: WebSocket handshake copy has no Upgrade
- **WHEN** a WebSocket handshake is inspected by ModSec
- **THEN** the sidecar copy has no `Upgrade` or `Connection` header
- **AND** the request passed to `next` keeps both

### Requirement: Every WAF leg reads a body of any length
AppSec and ModSec SHALL read every body they forward through `wafhop.ReadBody`. Neither leg SHALL skip, drop, or inspect headers only because a body has no `Content-Length` or because of the HTTP version: HTTP/1.1 chunked, HTTP/2, and HTTP/3 bodies of unknown length SHALL be inspected like a body with a declared length. A body MUST NOT select a leg's failure action. Neither leg SHALL keep a private copy of these rules.

#### Scenario: ModSec inspects an HTTP/2 POST without Content-Length
- **WHEN** a POST arrives over HTTP/2 with no Content-Length and a body that ends
- **AND** `bouncerModsecFailureAction` is `passthrough`
- **THEN** ModSec reads the body
- **AND** the sidecar receives those bytes

#### Scenario: ModSec ban does not drop an HTTP/2 POST without Content-Length
- **WHEN** a POST arrives over HTTP/2 with no Content-Length and a body that ends
- **AND** `bouncerModsecFailureAction` is `ban`
- **THEN** the sidecar is called with that body
- **AND** the response is not `ban:modsec-failure`

#### Scenario: Restic repository creation reaches the WAF
- **WHEN** a POST arrives over HTTP/2 with an empty body and no Content-Length
- **AND** AppSec and ModSec are both subscribed with default settings
- **THEN** AppSec and the sidecar are both called
- **AND** a clean verdict lets the request reach `next`

### Requirement: A body of unknown length is read under the leg's total read deadline
When `ReadBody` reads a body of unknown length from the client, it SHALL bound that read by the leg's total read deadline (`appsecBodyReadTimeoutSeconds` or `modsecBodyReadTimeoutSeconds`), counted from the start of this read: the time to receive the body, not an idle timeout. On expiry it SHALL cut the read and return `ErrBodyReadTimeout`. A body with a declared length SHALL NOT get this deadline.

#### Scenario: A stalled HTTP/2 body is cut at the deadline
- **WHEN** an HTTP/2 POST without Content-Length sends 2 bytes and then nothing
- **AND** the leg's read deadline is 1 second
- **THEN** `ReadBody` returns `ErrBodyReadTimeout` after about 1 second
- **AND** the WAF is not called

#### Scenario: A body with Content-Length gets no plugin deadline
- **WHEN** a POST with a declared Content-Length sends its bytes slower than the leg's read deadline
- **THEN** `ReadBody` does not cut the read
- **AND** only the server's own read timeout bounds it

### Requirement: The read deadline cuts the read without changing the success path
On expiry `ReadBody` SHALL cut the in-flight read through the per-request read-deadline control the bouncer passes in, and SHALL close the body instead when that control is missing or returns an error. It SHALL NOT start a goroutine of its own. A read that ends before the deadline MUST NOT change the connection's read deadline, so the server's own read timeout still bounds the rest of an oversize body.

#### Scenario: A stalled HTTP/1.1 chunked body is cut at the deadline
- **WHEN** an HTTP/1.1 chunked POST sends 2 bytes and then nothing
- **AND** the per-request read-deadline control is available
- **THEN** `ReadBody` returns `ErrBodyReadTimeout` after about the leg's read deadline

#### Scenario: The rest of an oversize body keeps the server read timeout
- **WHEN** AppSec reads the first `appsecBodyLimit` bytes of a longer body of unknown length in time
- **THEN** the connection read deadline is unchanged
- **AND** the rest of the body streams to `next` under the server's own read timeout
