// Package wafhop holds the inbound-request rules shared by the WAF legs (AppSec and ModSec).
// It decides which client bodies may be buffered, buffers one under a leg's limit, tells a client
// that left mid-upload apart from a broken body, and keeps connection-scoped headers off the WAF copy.
// Each leg keeps its own settings (body limit, failure fallback); this package only holds the rules.
package wafhop

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"math"
	"net/http"
)

// ErrClientDisconnected is a client that left (or canceled) while its body was being buffered.
// The leg MUST NOT call its WAF and MUST NOT apply its failure fallback; the bouncer stops without a ban.
var ErrClientDisconnected = errors.New("wafhop:clientDisconnected")

// ErrClientBodyRead is any other failure reading the client body (for example the server read
// timeout on a slow HTTP/2 upload). The request never arrived whole, so it is not a WAF verdict and
// not a WAF failure: the bouncer answers 400 without a ban.
var ErrClientBodyRead = errors.New("wafhop:clientBodyRead")

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

// IsBodyUnreadable reports a streamed HTTP/2 or HTTP/3 body of unknown length (gRPC and other
// streaming exchanges). Buffering it can block until the peer gives up, so no leg reads it.
func IsBodyUnreadable(httpReq *http.Request) bool {
	return HasBody(httpReq) && httpReq.ProtoMajor >= 2 && httpReq.ContentLength < 0
}

// IsMethodWithBody reports the methods whose uninspectable body is a drop candidate: POST, PUT, PATCH.
// DELETE is deliberately absent: a DELETE body is worth inspecting when readable, but not worth a drop.
func IsMethodWithBody(method string) bool {
	switch method {
	case http.MethodPost, http.MethodPut, http.MethodPatch:
		return true
	default:
		return false
	}
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
// TruncateAtLimit returns at most limit bytes; limit 0 or less means no cap.
// RejectOverLimit returns ErrBodyTooLarge for a body longer than limit; limit 0 or less means no cap.
// Either way next later reads the whole client body.
//
// A body an earlier leg already buffered whole is reused without a second read or copy.
// A client that left is ErrClientDisconnected. Any other read failure wraps ErrClientBodyRead.
// The caller checks HasBody and IsBodyUnreadable first.
func ReadBody(httpReq *http.Request, limit int64, mode LimitMode) ([]byte, error) {
	data, err := bufferBody(httpReq, limit)
	if err != nil {
		if IsClientGone(httpReq, err) {
			return nil, ErrClientDisconnected
		}
		return nil, fmt.Errorf("%w: %s", ErrClientBodyRead, err.Error())
	}
	// A body reused from an earlier leg can be longer than this leg's limit, so check the length here.
	if limit <= 0 || int64(len(data)) <= limit {
		return data, nil
	}
	if mode == RejectOverLimit {
		return nil, ErrBodyTooLarge
	}
	return data[:limit], nil
}

// bufferBody reads at most limit+1 bytes (all of them when limit is 0 or less) and replaces
// httpReq.Body with those bytes followed by the unread rest. More than limit bytes means the body is
// longer than limit. A whole body an earlier leg buffered and nobody read since is returned as is.
func bufferBody(httpReq *http.Request, limit int64) ([]byte, error) {
	if prior, ok := httpReq.Body.(*bufferedBody); ok && prior.complete && !prior.touched {
		return prior.data, nil
	}
	src := httpReq.Body
	var buf bytes.Buffer
	reader := io.Reader(src)
	// At math.MaxInt64, limit+1 overflows and LimitReader would read nothing: read the whole body instead.
	if limit > 0 && limit < math.MaxInt64 {
		reader = io.LimitReader(src, limit+1)
		// Grow only under a cap: ContentLength is the client's word and must not size an unbounded buffer.
		if httpReq.ContentLength > 0 && httpReq.ContentLength <= limit {
			buf.Grow(int(httpReq.ContentLength))
		}
	}
	if _, err := buf.ReadFrom(reader); err != nil {
		return nil, err
	}
	data := buf.Bytes()
	complete := limit <= 0 || int64(len(data)) <= limit
	replay := &bufferedBody{data: data, complete: complete, rest: src}
	if complete {
		replay.reader = bytes.NewReader(data)
	} else {
		replay.reader = io.MultiReader(bytes.NewReader(data), src)
	}
	httpReq.Body = replay
	return data, nil
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
