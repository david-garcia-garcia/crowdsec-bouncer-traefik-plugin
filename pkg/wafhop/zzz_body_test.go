package wafhop

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestIsBodyUnreadable(t *testing.T) {
	realBody := func() io.ReadCloser { return io.NopCloser(strings.NewReader("data")) }
	tests := []struct {
		name          string
		protoMajor    int
		contentLength int64
		body          io.ReadCloser
		want          bool
	}{
		{name: "http2 grpc stream without content-length", protoMajor: 2, contentLength: -1, body: realBody(), want: true},
		{name: "http3 stream without content-length", protoMajor: 3, contentLength: -1, body: realBody(), want: true},
		{name: "http2 with content-length", protoMajor: 2, contentLength: 42, body: realBody(), want: false},
		{name: "http1.1 chunked without content-length", protoMajor: 1, contentLength: -1, body: realBody(), want: false},
		{name: "http2 without body", protoMajor: 2, contentLength: -1, body: nil, want: false},
		{name: "http2 with http.NoBody", protoMajor: 2, contentLength: -1, body: http.NoBody, want: false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req, _ := http.NewRequest(http.MethodPost, "http://localhost", nil)
			req.ProtoMajor = tt.protoMajor
			req.ContentLength = tt.contentLength
			req.Body = tt.body
			if got := IsBodyUnreadable(req); got != tt.want {
				t.Errorf("IsBodyUnreadable() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestIsMethodWithBody(t *testing.T) {
	for method, want := range map[string]bool{
		http.MethodPost: true, http.MethodPut: true, http.MethodPatch: true,
		http.MethodDelete: false, http.MethodGet: false, http.MethodHead: false,
	} {
		if got := IsMethodWithBody(method); got != want {
			t.Errorf("IsMethodWithBody(%q) = %v, want %v", method, got, want)
		}
	}
}

func readAllBody(t *testing.T, req *http.Request) string {
	t.Helper()
	got, err := io.ReadAll(req.Body)
	if err != nil {
		t.Fatalf("read restored body: %v", err)
	}
	return string(got)
}

func TestReadBody_truncateKeepsTheRestForNext(t *testing.T) {
	req := httptest.NewRequest(http.MethodPost, "http://example.com/", strings.NewReader("0123456789"))
	got, err := ReadBody(req, 4, TruncateAtLimit)
	if err != nil {
		t.Fatalf("err=%v", err)
	}
	if string(got) != "0123" {
		t.Fatalf("forwarded %q want 0123", got)
	}
	if rest := readAllBody(t, req); rest != "0123456789" {
		t.Fatalf("next reads %q want the whole body", rest)
	}
}

func TestReadBody_truncateZeroLimitReadsAll(t *testing.T) {
	req := httptest.NewRequest(http.MethodPost, "http://example.com/", strings.NewReader("0123456789"))
	got, err := ReadBody(req, 0, TruncateAtLimit)
	if err != nil || string(got) != "0123456789" {
		t.Fatalf("got %q err=%v", got, err)
	}
	if rest := readAllBody(t, req); rest != "0123456789" {
		t.Fatalf("next reads %q", rest)
	}
}

func TestReadBody_rejectOverLimit(t *testing.T) {
	req := httptest.NewRequest(http.MethodPost, "http://example.com/", strings.NewReader("0123456789"))
	if _, err := ReadBody(req, 9, RejectOverLimit); !errors.Is(err, ErrBodyTooLarge) {
		t.Fatalf("err=%v want ErrBodyTooLarge", err)
	}
	exact := httptest.NewRequest(http.MethodPost, "http://example.com/", strings.NewReader("0123456789"))
	got, err := ReadBody(exact, 10, RejectOverLimit)
	if err != nil || string(got) != "0123456789" {
		t.Fatalf("body at the limit: got %q err=%v", got, err)
	}
	if rest := readAllBody(t, exact); rest != "0123456789" {
		t.Fatalf("next reads %q", rest)
	}
}

// A second leg reuses the whole body the first leg buffered: same bytes, no second read.
func TestReadBody_secondLegReusesWholeBody(t *testing.T) {
	src := &countingBody{Reader: strings.NewReader("payload")}
	req := httptest.NewRequest(http.MethodPost, "http://example.com/", nil)
	req.Body = src
	first, err := ReadBody(req, 100, TruncateAtLimit)
	if err != nil {
		t.Fatalf("first leg: %v", err)
	}
	readsAfterFirst := src.reads
	second, err := ReadBody(req, 100, RejectOverLimit)
	if err != nil {
		t.Fatalf("second leg: %v", err)
	}
	if src.reads != readsAfterFirst {
		t.Fatalf("second leg read the client body again (%d reads, want %d)", src.reads, readsAfterFirst)
	}
	if &first[0] != &second[0] {
		t.Fatal("second leg copied the body instead of reusing it")
	}
	if rest := readAllBody(t, req); rest != "payload" {
		t.Fatalf("next reads %q", rest)
	}
	if err := req.Body.Close(); err != nil || !src.closed {
		t.Fatalf("Close must reach the client body: err=%v closed=%v", err, src.closed)
	}
}

// A reused body still obeys the second leg's own limit.
func TestReadBody_reuseAppliesThisLegLimit(t *testing.T) {
	req := httptest.NewRequest(http.MethodPost, "http://example.com/", strings.NewReader("0123456789"))
	if _, err := ReadBody(req, 0, TruncateAtLimit); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadBody(req, 5, RejectOverLimit); !errors.Is(err, ErrBodyTooLarge) {
		t.Fatalf("err=%v want ErrBodyTooLarge", err)
	}
	req2 := httptest.NewRequest(http.MethodPost, "http://example.com/", strings.NewReader("0123456789"))
	if _, err := ReadBody(req2, 0, TruncateAtLimit); err != nil {
		t.Fatal(err)
	}
	got, err := ReadBody(req2, 3, TruncateAtLimit)
	if err != nil || string(got) != "012" {
		t.Fatalf("got %q err=%v", got, err)
	}
}

// After a truncated first read the second leg reads the rest, and next still gets every byte.
func TestReadBody_secondLegAfterTruncation(t *testing.T) {
	req := httptest.NewRequest(http.MethodPost, "http://example.com/", strings.NewReader("0123456789"))
	if _, err := ReadBody(req, 4, TruncateAtLimit); err != nil {
		t.Fatal(err)
	}
	got, err := ReadBody(req, 100, RejectOverLimit)
	if err != nil || string(got) != "0123456789" {
		t.Fatalf("got %q err=%v", got, err)
	}
	if rest := readAllBody(t, req); rest != "0123456789" {
		t.Fatalf("next reads %q", rest)
	}
}

func TestReadBody_classifiesReadErrors(t *testing.T) {
	tests := []struct {
		name     string
		err      error
		canceled bool
		want     error
	}{
		{name: "context canceled", err: context.Canceled, want: ErrClientDisconnected},
		{name: "deadline exceeded", err: context.DeadlineExceeded, want: ErrClientDisconnected},
		{name: "unexpected EOF", err: io.ErrUnexpectedEOF, want: ErrClientDisconnected},
		{name: "any error on a canceled request", err: errors.New("stream reset"), canceled: true, want: ErrClientDisconnected},
		{name: "other error on a live request", err: errors.New("read timeout"), want: ErrClientBodyRead},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodPost, "http://example.com/", nil)
			if tt.canceled {
				ctx, cancel := context.WithCancel(req.Context())
				cancel()
				req = req.WithContext(ctx)
			}
			req.Body = io.NopCloser(&failingReader{err: tt.err})
			_, err := ReadBody(req, 100, RejectOverLimit)
			if !errors.Is(err, tt.want) {
				t.Fatalf("err=%v want %v", err, tt.want)
			}
		})
	}
}

// The WAF client's own timeout is a WAF failure, not the client leaving.
func TestIsInboundCanceled(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "http://example.com/", nil)
	if IsInboundCanceled(req, context.DeadlineExceeded) {
		t.Fatal("a WAF client timeout must not count as an inbound cancel")
	}
	ctx, cancel := context.WithCancel(req.Context())
	cancel()
	if !IsInboundCanceled(req.WithContext(ctx), errors.New("dial")) {
		t.Fatal("a canceled inbound context is an inbound cancel")
	}
}

type countingBody struct {
	io.Reader
	reads  int
	closed bool
}

func (c *countingBody) Read(p []byte) (int, error) {
	c.reads++
	return c.Reader.Read(p)
}

func (c *countingBody) Close() error {
	c.closed = true
	return nil
}

type failingReader struct{ err error }

func (f *failingReader) Read([]byte) (int, error) { return 0, f.err }
