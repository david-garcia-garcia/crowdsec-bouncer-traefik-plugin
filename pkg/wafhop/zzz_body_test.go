package wafhop

import (
	"context"
	"errors"
	"io"
	"math"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// testBodyReadTimeout is the read deadline for tests whose body never stalls.
const testBodyReadTimeout = 5 * time.Second

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
	got, err := ReadBody(req, 4, TruncateAtLimit, nil, testBodyReadTimeout)
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

func TestReadBody_rejectOverLimit(t *testing.T) {
	req := httptest.NewRequest(http.MethodPost, "http://example.com/", strings.NewReader("0123456789"))
	if _, err := ReadBody(req, 9, RejectOverLimit, nil, testBodyReadTimeout); !errors.Is(err, ErrBodyTooLarge) {
		t.Fatalf("err=%v want ErrBodyTooLarge", err)
	}
	exact := httptest.NewRequest(http.MethodPost, "http://example.com/", strings.NewReader("0123456789"))
	got, err := ReadBody(exact, 10, RejectOverLimit, nil, testBodyReadTimeout)
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
	first, err := ReadBody(req, 100, TruncateAtLimit, nil, testBodyReadTimeout)
	if err != nil {
		t.Fatalf("first leg: %v", err)
	}
	readsAfterFirst := src.reads
	second, err := ReadBody(req, 100, RejectOverLimit, nil, testBodyReadTimeout)
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
	if _, err := ReadBody(req, 100, TruncateAtLimit, nil, testBodyReadTimeout); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadBody(req, 5, RejectOverLimit, nil, testBodyReadTimeout); !errors.Is(err, ErrBodyTooLarge) {
		t.Fatalf("err=%v want ErrBodyTooLarge", err)
	}
	req2 := httptest.NewRequest(http.MethodPost, "http://example.com/", strings.NewReader("0123456789"))
	if _, err := ReadBody(req2, 100, TruncateAtLimit, nil, testBodyReadTimeout); err != nil {
		t.Fatal(err)
	}
	got, err := ReadBody(req2, 3, TruncateAtLimit, nil, testBodyReadTimeout)
	if err != nil || string(got) != "012" {
		t.Fatalf("got %q err=%v", got, err)
	}
}

// After a truncated first read the second leg reads the rest, and next still gets every byte.
func TestReadBody_secondLegAfterTruncation(t *testing.T) {
	req := httptest.NewRequest(http.MethodPost, "http://example.com/", strings.NewReader("0123456789"))
	if _, err := ReadBody(req, 4, TruncateAtLimit, nil, testBodyReadTimeout); err != nil {
		t.Fatal(err)
	}
	got, err := ReadBody(req, 100, RejectOverLimit, nil, testBodyReadTimeout)
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
			_, err := ReadBody(req, 100, RejectOverLimit, nil, testBodyReadTimeout)
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

// TestReadBody_maxInt64LimitReadsAll proves the largest limit does not overflow into an empty body
// for the WAF and for next, in either mode.
func TestReadBody_maxInt64LimitReadsAll(t *testing.T) {
	for _, mode := range []LimitMode{TruncateAtLimit, RejectOverLimit} {
		req := httptest.NewRequest(http.MethodPost, "http://example.com/", strings.NewReader("hello world"))
		got, err := ReadBody(req, math.MaxInt64, mode, nil, testBodyReadTimeout)
		if err != nil || string(got) != "hello world" {
			t.Fatalf("mode %v: got %q err=%v", mode, got, err)
		}
		if rest := readAllBody(t, req); rest != "hello world" {
			t.Fatalf("mode %v: next reads %q", mode, rest)
		}
	}
}

// At the uncapped limit the client's Content-Length must not size the buffer before any byte arrives.
func TestReadBody_maxInt64LimitIgnoresDeclaredLength(t *testing.T) {
	req := httptest.NewRequest(http.MethodPost, "http://example.com/", strings.NewReader("hello world"))
	req.ContentLength = math.MaxInt64 / 2
	got, err := ReadBody(req, math.MaxInt64, RejectOverLimit, nil, testBodyReadTimeout)
	if err != nil || string(got) != "hello world" {
		t.Fatalf("got %q err=%v", got, err)
	}
}
