package wafhop

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

// stalledTestBody serves first, then blocks until it is cut (Close or the test controller), and then
// returns cutErr. It stands in for a client that never ends its body.
type stalledTestBody struct {
	first   []byte
	sent    bool
	cutErr  error
	cutOnce sync.Once
	cut     chan struct{}
	closed  bool
}

// newStalledTestBody returns a body that stalls after first until it is cut.
func newStalledTestBody(first string, cutErr error) *stalledTestBody {
	return &stalledTestBody{first: []byte(first), cutErr: cutErr, cut: make(chan struct{})}
}

// Read serves first once, then blocks until the body is cut.
func (s *stalledTestBody) Read(p []byte) (int, error) {
	if !s.sent {
		s.sent = true
		return copy(p, s.first), nil
	}
	<-s.cut
	return 0, s.cutErr
}

// Close cuts the read, the way closing an HTTP/2 request body does.
func (s *stalledTestBody) Close() error {
	s.cutOnce.Do(func() {
		s.closed = true
		close(s.cut)
	})
	return nil
}

// newUnknownLengthTestRequest is an HTTP/2 POST with body and no Content-Length.
func newUnknownLengthTestRequest(body io.ReadCloser) *http.Request {
	req := httptest.NewRequest(http.MethodPost, "http://example.com/", nil)
	req.ProtoMajor = 2
	req.ContentLength = -1
	req.Body = body
	return req
}

// With no controller the deadline cuts the read by closing the body.
func TestReadBody_deadlineWithoutControllerClosesBody(t *testing.T) {
	body := newStalledTestBody("part", errors.New("http2: request body closed"))
	req := newUnknownLengthTestRequest(body)
	started := time.Now()
	_, err := ReadBody(req, 100, TruncateAtLimit, nil, 50*time.Millisecond)
	if !errors.Is(err, ErrBodyReadTimeout) {
		t.Fatalf("err=%v want ErrBodyReadTimeout", err)
	}
	if errors.Is(err, ErrClientBodyRead) || errors.Is(err, ErrClientDisconnected) {
		t.Fatalf("err=%v must not match the other client-body sentinels", err)
	}
	if !body.closed {
		t.Fatal("the fallback must close the body")
	}
	if elapsed := time.Since(started); elapsed > 2*time.Second {
		t.Fatalf("ReadBody returned after %v, want about 50ms", elapsed)
	}
}

// A controller that cannot reach the connection (here a recorder) falls back to closing the body.
func TestReadBody_deadlineFallsBackToCloseWhenControllerFails(t *testing.T) {
	body := newStalledTestBody("part", errors.New("http2: request body closed"))
	req := newUnknownLengthTestRequest(body)
	controller := http.NewResponseController(httptest.NewRecorder())
	_, err := ReadBody(req, 100, RejectOverLimit, controller, 50*time.Millisecond)
	if !errors.Is(err, ErrBodyReadTimeout) {
		t.Fatalf("err=%v want ErrBodyReadTimeout", err)
	}
	if !body.closed {
		t.Fatal("a controller that cannot set the deadline must fall back to Close")
	}
}

// The deadline wins over a read error that looks like a client that left (HTTP/1.1 cancels the
// request context when its connection read deadline cuts the read).
func TestReadBody_deadlineWinsOverCanceledRead(t *testing.T) {
	body := newStalledTestBody("part", fmt.Errorf("read: %w", context.Canceled))
	req := newUnknownLengthTestRequest(body)
	ctx, cancel := context.WithCancel(req.Context())
	defer cancel()
	req = req.WithContext(ctx)
	go func() {
		// Cancel the context as net/http does on an HTTP/1.1 cut, before the read returns.
		time.Sleep(30 * time.Millisecond)
		cancel()
	}()
	_, err := ReadBody(req, 100, TruncateAtLimit, nil, 60*time.Millisecond)
	if !errors.Is(err, ErrBodyReadTimeout) {
		t.Fatalf("err=%v want ErrBodyReadTimeout", err)
	}
}

// A body with a declared length starts no deadline, however slow it is.
func TestReadBody_declaredLengthIsNotCut(t *testing.T) {
	req := httptest.NewRequest(http.MethodPost, "http://example.com/", nil)
	req.ContentLength = 4
	req.Body = io.NopCloser(&slowTestReader{data: "abcd", delay: 200 * time.Millisecond})
	got, err := ReadBody(req, 100, TruncateAtLimit, nil, 20*time.Millisecond)
	if err != nil || string(got) != "abcd" {
		t.Fatalf("got %q err=%v", got, err)
	}
}

// A body of unknown length that ends in time is read whole and restored for next.
func TestReadBody_unknownLengthWithinDeadline(t *testing.T) {
	req := newUnknownLengthTestRequest(io.NopCloser(strings.NewReader("a=0&")))
	got, err := ReadBody(req, 100, TruncateAtLimit, nil, time.Second)
	if err != nil || string(got) != "a=0&" {
		t.Fatalf("got %q err=%v", got, err)
	}
	if rest := readAllBody(t, req); rest != "a=0&" {
		t.Fatalf("next reads %q", rest)
	}
}

// A second leg reusing a complete buffer starts no timer: even a 1ns timeout returns the data.
func TestReadBody_reuseStartsNoTimer(t *testing.T) {
	req := newUnknownLengthTestRequest(io.NopCloser(strings.NewReader("payload")))
	if _, err := ReadBody(req, 100, TruncateAtLimit, nil, time.Second); err != nil {
		t.Fatal(err)
	}
	got, err := ReadBody(req, 100, RejectOverLimit, nil, time.Nanosecond)
	if err != nil || string(got) != "payload" {
		t.Fatalf("got %q err=%v", got, err)
	}
}

// slowTestReader waits delay, then serves data.
type slowTestReader struct {
	data  string
	delay time.Duration
	done  bool
}

// Read sleeps once, then returns data and EOF.
func (s *slowTestReader) Read(p []byte) (int, error) {
	if s.done {
		return 0, io.EOF
	}
	time.Sleep(s.delay)
	s.done = true
	return copy(p, s.data), nil
}

// bodyReadOutcome is what the test handler saw from ReadBody.
type bodyReadOutcome struct {
	err     error
	elapsed time.Duration
}

// serveStalledBodyRead starts a server whose handler reads the body through http.NewResponseController,
// sends a body that never ends from client, and returns what ReadBody returned.
func serveStalledBodyRead(t *testing.T, server *httptest.Server, client *http.Client) bodyReadOutcome {
	t.Helper()
	outcomes := make(chan bodyReadOutcome, 1)
	server.Config.Handler = http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
		started := time.Now()
		_, err := ReadBody(r, 1<<20, TruncateAtLimit, http.NewResponseController(rw), 300*time.Millisecond)
		outcomes <- bodyReadOutcome{err: err, elapsed: time.Since(started)}
		rw.WriteHeader(http.StatusBadRequest)
	})
	bodyReader, bodyWriter := io.Pipe()
	defer func() { _ = bodyWriter.Close() }()
	go func() { _, _ = bodyWriter.Write([]byte("partial")) }()
	go func() {
		req, _ := http.NewRequest(http.MethodPost, server.URL+"/stream", bodyReader)
		res, err := client.Do(req)
		if err == nil {
			_ = res.Body.Close()
		}
	}()
	select {
	case got := <-outcomes:
		return got
	case <-time.After(10 * time.Second):
		t.Fatal("ReadBody did not return within 10s: the deadline did not cut the read")
		return bodyReadOutcome{}
	}
}

// A real HTTP/1.1 chunked body that never ends is cut at the deadline through the response controller.
// Closing an HTTP/1.1 body does not unblock its read, so only the controller can end this one.
func TestReadBody_deadlineCutsHTTP1Chunked(t *testing.T) {
	server := httptest.NewUnstartedServer(nil)
	server.Start()
	defer server.Close()
	got := serveStalledBodyRead(t, server, server.Client())
	if !errors.Is(got.err, ErrBodyReadTimeout) {
		t.Fatalf("err=%v want ErrBodyReadTimeout", got.err)
	}
	if got.elapsed > 3*time.Second {
		t.Fatalf("cut after %v, want about 300ms", got.elapsed)
	}
}

// A real HTTP/2 body without Content-Length that never ends is cut at the deadline.
func TestReadBody_deadlineCutsHTTP2(t *testing.T) {
	server := httptest.NewUnstartedServer(nil)
	server.EnableHTTP2 = true
	server.StartTLS()
	defer server.Close()
	got := serveStalledBodyRead(t, server, server.Client())
	if !errors.Is(got.err, ErrBodyReadTimeout) {
		t.Fatalf("err=%v want ErrBodyReadTimeout", got.err)
	}
	if got.elapsed > 3*time.Second {
		t.Fatalf("cut after %v, want about 300ms", got.elapsed)
	}
}

// When the leg reads its limit in time, the timer is stopped and no read deadline is set, so next
// reads the rest of a longer body after the leg's timeout has passed, under the server's own timeout.
func TestReadBody_restOfOversizeBodyIsNotCut(t *testing.T) {
	type restOutcome struct {
		forwarded string
		rest      string
		err       error
	}
	outcomes := make(chan restOutcome, 1)
	server := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
		forwarded, err := ReadBody(r, 4, TruncateAtLimit, http.NewResponseController(rw), 100*time.Millisecond)
		if err != nil {
			outcomes <- restOutcome{err: err}
			return
		}
		rest, err := io.ReadAll(r.Body)
		outcomes <- restOutcome{forwarded: string(forwarded), rest: string(rest), err: err}
	}))
	defer server.Close()
	bodyReader, bodyWriter := io.Pipe()
	go func() {
		_, _ = bodyWriter.Write([]byte("abcdef"))
		// Past the leg's 100 ms timeout: only a deadline left on the connection would cut this.
		time.Sleep(400 * time.Millisecond)
		_, _ = bodyWriter.Write([]byte("ghij"))
		_ = bodyWriter.Close()
	}()
	go func() {
		res, err := server.Client().Post(server.URL+"/upload", "application/octet-stream", bodyReader)
		if err == nil {
			_ = res.Body.Close()
		}
	}()
	select {
	case got := <-outcomes:
		if got.err != nil || got.forwarded != "abcd" || got.rest != "abcdefghij" {
			t.Fatalf("forwarded=%q rest=%q err=%v want abcd, abcdefghij, nil", got.forwarded, got.rest, got.err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("handler did not finish")
	}
}
