---
url: https://github.com/golang/go/blob/go1.25.6/src/net/http/h2_bundle.go
title: net/http bundled HTTP/2 server - request body close, per-stream read deadline
fetched: 2026-11-14
authority: source
ref: golang/go@go1.25.6:src/net/http/h2_bundle.go
---

`http2errClosedBody = errors.New("body closed by handler")` (L4017).

`func (b *http2requestBody) Close` (L6508): `b.pipe.BreakWithError(http2errClosedBody)` once. A pending `Read` on the pipe returns that error.

`func (st *http2stream) onReadTimeout` (L5951): `st.body.CloseWithError(fmt.Errorf("%w", os.ErrDeadlineExceeded))`. Comment: wrapped "to avoid callers depending on us returning the bare error".

Per-stream ReadTimeout (L6072-6074): when `Server.ReadTimeout > 0`, after headers the conn deadline is cleared (`sc.conn.SetReadDeadline(time.Time{})`) and `st.readDeadline = sc.srv.afterFunc(sc.hs.ReadTimeout, st.onReadTimeout)`.

`func (w *http2responseWriter) SetReadDeadline` (L6778):
- deadline non-zero and in the past -> `st.onReadTimeout()` immediately (L6783).
- otherwise on the serve goroutine: if a timer exists and `Stop()` returns false (already fired or stream closed) -> return, no change (L6787-6790).
- zero deadline -> `st.readDeadline = nil` (L6794). This also drops the ReadTimeout-derived timer.
- else arm a new timer or `Reset` the existing one (L6795-6798).

`func (sc *http2serverConn) closeStream` (L5668): stops `st.readDeadline`, and if `st.body != nil` calls `p.CloseWithError(err)` (L5700). A reader still blocked on the stream body returns at this point.
