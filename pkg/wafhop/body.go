// Package wafhop holds the inbound-request rules shared by the WAF legs (AppSec and ModSec).
// It buffers a client body under a leg's limit and, for a body of unknown length, under the leg's
// total read deadline; tells a deadline, a client that left mid-upload, and a broken body apart; and
// keeps connection-scoped headers off the WAF copy.
// Each leg keeps its own settings (body limit, read timeout, failure fallback); this package only holds the rules.
package wafhop

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"math"
	"net/http"
	"time"
)

// ErrClientDisconnected is a client that left (or canceled) while its body was being buffered.
// The leg MUST NOT call its WAF and MUST NOT apply its failure fallback; the bouncer stops without a ban.
var ErrClientDisconnected = errors.New("wafhop:clientDisconnected")

// ErrClientBodyRead is any other failure reading the client body (for example the server read
// timeout on a slow HTTP/2 upload). The request never arrived whole, so it is not a WAF verdict and
// not a WAF failure: the bouncer answers 400 without a ban.
var ErrClientBodyRead = errors.New("wafhop:clientBodyRead")

// ErrBodyReadTimeout is a body of unknown length that did not end, or reach the leg's limit, within the
// leg's read timeout. It neither wraps nor is wrapped by ErrClientBodyRead, so errors.Is keeps the two
// apart. The leg does not call its WAF; the bouncer answers 400 whatever the leg's failure action says.
var ErrBodyReadTimeout = errors.New("wafhop:bodyReadTimeout")

// ErrBodyTooLarge is a body longer than the limit under RejectOverLimit.
var ErrBodyTooLarge = errors.New("wafhop:bodyTooLarge")

// LimitMode is what ReadBody does with a body longer than the leg's limit.
type LimitMode int

const (
	// TruncateAtLimit returns the first limit bytes. The bytes past the limit still reach next.
	TruncateAtLimit LimitMode = iota
	// RejectOverLimit returns ErrBodyTooLarge.
	RejectOverLimit
)

// HasBody reports a request body the server did not replace with http.NoBody.
func HasBody(httpReq *http.Request) bool {
	return httpReq.Body != nil && httpReq.Body != http.NoBody
}

// IsClientGone reports a client disconnect or cancel behind err.
// The canceled request context is the primary signal: net/http cancels it before the body read
// fails when an HTTP/2 stream is reset (the error is an unexported stream error that does not wrap
// context.Canceled) and when an HTTP/1.1 connection read fails (TCP reset, read timeout).
func IsClientGone(httpReq *http.Request, err error) bool {
	return httpReq.Context().Err() != nil ||
		errors.Is(err, context.Canceled) ||
		errors.Is(err, context.DeadlineExceeded) ||
		errors.Is(err, io.ErrUnexpectedEOF)
}

// IsInboundCanceled reports a client that canceled the inbound request. Use it around the WAF call
// itself, where a DeadlineExceeded is the WAF client's own timeout (a WAF failure), not the client leaving.
func IsInboundCanceled(httpReq *http.Request, err error) bool {
	return errors.Is(httpReq.Context().Err(), context.Canceled) || errors.Is(err, context.Canceled)
}

// ReadBody buffers httpReq.Body for one WAF hop and puts an equivalent body back on httpReq for next.
//
// TruncateAtLimit returns at most limit bytes. RejectOverLimit returns ErrBodyTooLarge for a body
// longer than limit. Either way next later reads the whole client body. limit MUST be at least 1:
// a non-positive limit is a caller bug, since every leg resolves its own default before it calls.
//
// A body an earlier leg already buffered whole is reused without a second read or copy.
// A body of unknown length (ContentLength < 0: HTTP/1.1 chunked, HTTP/2 or HTTP/3 without the header)
// is read under timeout, the total time to receive it up to limit. When the timeout fires, this call
// cuts its own read through ctrl (falling back to closing the body when ctrl is nil or cannot reach the
// connection) and returns
// ErrBodyReadTimeout whatever error the cut produced. A body with a declared length starts no timer.
// A client that left is ErrClientDisconnected. Any other read failure wraps ErrClientBodyRead.
func ReadBody(httpReq *http.Request, limit int64, mode LimitMode, ctrl *http.ResponseController, timeout time.Duration) ([]byte, error) {
	data, timedOut, err := bufferBody(httpReq, limit, ctrl, timeout)
	// The deadline is decided first: on HTTP/1.1 the cut also cancels the request context, which the
	// disconnect check below would misread as a client that left.
	if timedOut {
		return nil, ErrBodyReadTimeout
	}
	if err != nil {
		if IsClientGone(httpReq, err) {
			return nil, ErrClientDisconnected
		}
		return nil, fmt.Errorf("%w: %s", ErrClientBodyRead, err.Error())
	}
	// A body reused from an earlier leg can be longer than this leg's limit, so check the length here.
	if int64(len(data)) <= limit {
		return data, nil
	}
	if mode == RejectOverLimit {
		return nil, ErrBodyTooLarge
	}
	return data[:limit], nil
}

// bufferBody reads at most limit+1 bytes and replaces httpReq.Body with those bytes followed by the
// unread rest. More than limit bytes means the body is longer than limit. A whole body an earlier leg
// buffered and nobody read since is returned as is and starts no timer. timedOut reports that the read
// deadline fired during this call's read.
func bufferBody(httpReq *http.Request, limit int64, ctrl *http.ResponseController, timeout time.Duration) (data []byte, timedOut bool, err error) {
	if prior, ok := httpReq.Body.(*bufferedBody); ok && prior.complete && !prior.touched {
		return prior.data, false, nil
	}
	src := httpReq.Body
	var buf bytes.Buffer
	reader := io.Reader(src)
	// At math.MaxInt64, limit+1 overflows and LimitReader would read nothing: read the whole body instead.
	if limit < math.MaxInt64 {
		reader = io.LimitReader(src, limit+1)
	}
	// Grow only under the cap: ContentLength is the client's word and must not size a larger buffer.
	if httpReq.ContentLength > 0 && httpReq.ContentLength <= limit {
		buf.Grow(int(httpReq.ContentLength))
	}

	// Read the body. Only a body of unknown length runs under the deadline; this call owns the cut.
	if httpReq.ContentLength < 0 {
		timer := time.AfterFunc(timeout, func() { cutBodyRead(ctrl, src) })
		_, err = buf.ReadFrom(reader)
		// Stop reports false once the callback has run (or is running): the deadline fired.
		timedOut = !timer.Stop()
	} else {
		_, err = buf.ReadFrom(reader)
	}
	if timedOut || err != nil {
		return nil, timedOut, err
	}

	// Put the buffered bytes, then the unread rest, back on the request for the next reader.
	data = buf.Bytes()
	complete := int64(len(data)) <= limit
	replay := &bufferedBody{data: data, complete: complete, rest: src}
	if complete {
		replay.reader = bytes.NewReader(data)
	} else {
		replay.reader = io.MultiReader(bytes.NewReader(data), src)
	}
	httpReq.Body = replay
	return data, false, nil
}

// cutBodyRead unblocks an in-flight body read when the read deadline fires. The connection read
// deadline cuts HTTP/1.1 and HTTP/2; closing the body only cuts HTTP/2, so it is the fallback when
// there is no controller or the controller cannot reach the connection. The success path never sets
// a deadline, so Traefik's own readTimeout keeps bounding the rest of an oversize body.
func cutBodyRead(ctrl *http.ResponseController, body io.Closer) {
	if ctrl == nil || ctrl.SetReadDeadline(time.Now()) != nil {
		_ = body.Close()
	}
}

// bufferedBody is the client body after a leg buffered it: data, then the unread rest.
// data is never written after creation, so a later leg may return it without copying.
type bufferedBody struct {
	data     []byte
	complete bool
	touched  bool
	reader   io.Reader
	rest     io.ReadCloser
}

// Read serves data, then the unread rest.
func (b *bufferedBody) Read(p []byte) (int, error) {
	b.touched = true
	return b.reader.Read(p)
}

// Close closes the original client body.
func (b *bufferedBody) Close() error {
	return b.rest.Close()
}
