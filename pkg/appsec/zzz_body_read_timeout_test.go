package appsec

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pkg/configuration"
	logger "github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pkg/logger"
)

// stallingBody is a client body that sends nothing until Close, then returns readErrAfterClose.
// It stands for a stream that never ends; Close is what the deadline fallback calls.
type stallingBody struct {
	closed            chan struct{}
	closeOnce         sync.Once
	readErrAfterClose error
}

// newStallingBody returns a stallingBody whose cut read returns readErrAfterClose.
func newStallingBody(readErrAfterClose error) *stallingBody {
	return &stallingBody{closed: make(chan struct{}), readErrAfterClose: readErrAfterClose}
}

// Read blocks until Close, then returns the configured error.
func (b *stallingBody) Read(_ []byte) (int, error) {
	<-b.closed
	return 0, b.readErrAfterClose
}

// Close unblocks Read. Safe from the deadline timer goroutine and from test cleanup.
func (b *stallingBody) Close() error {
	b.closeOnce.Do(func() { close(b.closed) })
	return nil
}

// newCountingAppsecServer is an allow-only AppSec listener that counts its calls.
func newCountingAppsecServer(t *testing.T) (*httptest.Server, *int32) {
	t.Helper()
	var hits int32
	appsecServer := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, _ *http.Request) {
		atomic.AddInt32(&hits, 1)
		rw.WriteHeader(http.StatusOK)
		_, _ = rw.Write([]byte(`{"action":"allow"}`))
	}))
	t.Cleanup(appsecServer.Close)
	return appsecServer, &hits
}

// newOneSecondDeadlineClient is a Query client whose unknown-length body deadline is 1 second.
func newOneSecondDeadlineClient(t *testing.T, log *slog.Logger) (*Client, *int32) {
	t.Helper()
	appsecServer, hits := newCountingAppsecServer(t)
	appsecURL, _ := url.Parse(appsecServer.URL)
	client := NewTestClient(appsecURL, appsecServer.Client(), log)
	client.bodyReadTimeoutSeconds = 1
	return client, hits
}

// TestBodyReadTimeout_StalledBodyBlocksForEveryFailureAction: a body that never ends is cut at the
// deadline (Body.Close fallback, no controller) and returns ErrBodyReadTimeout without calling AppSec.
func TestBodyReadTimeout_StalledBodyBlocksForEveryFailureAction(t *testing.T) {
	failureActions := []string{configuration.FailureActionBan, configuration.FailureActionPassthrough, configuration.FailureActionCaptcha}
	for _, failureAction := range failureActions {
		t.Run(failureAction, func(t *testing.T) {
			t.Parallel()
			client, hits := newOneSecondDeadlineClient(t, logger.New("ERROR", ""))
			body := newStallingBody(errors.New("http2: request body closed by handler"))
			t.Cleanup(func() { _ = body.Close() })
			started := time.Now()
			decision, err := client.Query(withTestAddress(newUnknownLengthRequest(http.MethodPost, body)), Policy{FailureAction: failureAction}, nil)
			elapsed := time.Since(started)
			if !errors.Is(err, ErrBodyReadTimeout) {
				t.Fatalf("Query() error %v want ErrBodyReadTimeout", err)
			}
			if decision != nil {
				t.Fatalf("Query() returned decision %#v", decision)
			}
			if elapsed < 900*time.Millisecond || elapsed > 3*time.Second {
				t.Fatalf("Query() returned after %v, want about 1s", elapsed)
			}
			if got := atomic.LoadInt32(hits); got != 0 {
				t.Fatalf("AppSec listener called %d times, want 0", got)
			}
		})
	}
}

// TestBodyReadTimeout_FiredTimerWinsOverReadError: once the timer fired, the outcome is the deadline
// whatever the cut read returned, including errors that would otherwise mean a client disconnect.
func TestBodyReadTimeout_FiredTimerWinsOverReadError(t *testing.T) {
	readErrs := []struct {
		name string
		err  error
	}{
		{name: "wrapped context canceled", err: fmt.Errorf("read: %w", context.Canceled)},
		{name: "unexpected EOF", err: io.ErrUnexpectedEOF},
		{name: "clean EOF as the timer races the last byte", err: io.EOF},
	}
	for _, readCase := range readErrs {
		t.Run(readCase.name, func(t *testing.T) {
			t.Parallel()
			client, hits := newOneSecondDeadlineClient(t, logger.New("ERROR", ""))
			body := newStallingBody(readCase.err)
			t.Cleanup(func() { _ = body.Close() })
			_, err := client.Query(withTestAddress(newUnknownLengthRequest(http.MethodPost, body)), Policy{FailureAction: configuration.FailureActionPassthrough}, nil)
			if !errors.Is(err, ErrBodyReadTimeout) {
				t.Fatalf("Query() error %v want ErrBodyReadTimeout", err)
			}
			if errors.Is(err, ErrClientDisconnected) {
				t.Fatal("a fired deadline must not be reported as a client disconnect")
			}
			if got := atomic.LoadInt32(hits); got != 0 {
				t.Fatalf("AppSec listener called %d times, want 0", got)
			}
		})
	}
}

// TestBodyReadTimeout_ReachingLimitEndsDeadline: a stream that delivers appsecBodyLimit bytes and keeps
// streaming is inspected at once; the remainder is left for origin with no plugin deadline.
func TestBodyReadTimeout_ReachingLimitEndsDeadline(t *testing.T) {
	capture := &forwardCaptureRoundTripper{}
	client := newForwardCaptureClient(capture)
	client.bodyReadTimeoutSeconds = 1
	client.appsecBodyLimit = 4
	stalledTail := newStallingBody(io.EOF)
	t.Cleanup(func() { _ = stalledTail.Close() })
	stream := struct {
		io.Reader
		io.Closer
	}{Reader: io.MultiReader(strings.NewReader("abcdef"), stalledTail), Closer: stalledTail}
	started := time.Now()
	decision, err := client.Query(withTestAddress(newUnknownLengthRequest(http.MethodPost, stream)), Policy{}, nil)
	if err != nil {
		t.Fatalf("Query() returned error: %v", err)
	}
	if elapsed := time.Since(started); elapsed > 500*time.Millisecond {
		t.Fatalf("Query() waited %v; reaching the limit must end the read", elapsed)
	}
	if decision == nil || decision.Action != ActionAllow || capture.body != "abcd" {
		t.Fatalf("decision %#v, AppSec body %q; want allow and the first 4 bytes", decision, capture.body)
	}
}

// slowDeclaredBody delivers its payload only after delay; it stands for a slow upload with Content-Length.
type slowDeclaredBody struct {
	payload *strings.Reader
	delay   time.Duration
	waited  bool
}

// Read waits once for delay, then serves the payload.
func (b *slowDeclaredBody) Read(buf []byte) (int, error) {
	if !b.waited {
		time.Sleep(b.delay)
		b.waited = true
	}
	return b.payload.Read(buf)
}

// Close is a no-op; the body ends by EOF.
func (b *slowDeclaredBody) Close() error { return nil }

// TestBodyReadTimeout_DeclaredContentLengthIsNotCut: a body with Content-Length slower than the
// deadline is still read in full and inspected; the plugin arms no timer for it.
func TestBodyReadTimeout_DeclaredContentLengthIsNotCut(t *testing.T) {
	const payload = "slow-but-declared"
	capture := &forwardCaptureRoundTripper{}
	client := newForwardCaptureClient(capture)
	client.bodyReadTimeoutSeconds = 1
	req := httptest.NewRequest(http.MethodPost, "http://localhost/", nil)
	req.ProtoMajor = 2
	req.Body = &slowDeclaredBody{payload: strings.NewReader(payload), delay: 1500 * time.Millisecond}
	req.ContentLength = int64(len(payload))
	decision, err := client.Query(withTestAddress(req), Policy{FailureAction: configuration.FailureActionBan}, nil)
	if err != nil {
		t.Fatalf("Query() returned error: %v", err)
	}
	if decision == nil || decision.Action != ActionAllow {
		t.Fatalf("Query() want allow, got %#v", decision)
	}
	if capture.body != payload {
		t.Fatalf("AppSec body %q want %q", capture.body, payload)
	}
}

// TestBodyReadTimeout_WarnIsDebouncedWithRequestAttrs: two timeouts inside 5 seconds log one WARN
// that names the key and the escape hatch and carries ip, method, host, path, and timeoutSeconds.
func TestBodyReadTimeout_WarnIsDebouncedWithRequestAttrs(t *testing.T) {
	logger.ResetDebounceForTest()
	t.Cleanup(logger.ResetDebounceForTest)
	log, sink := newTestLogSink(slog.LevelInfo)
	client, _ := newOneSecondDeadlineClient(t, log)
	for range 2 {
		body := newStallingBody(io.EOF)
		t.Cleanup(func() { _ = body.Close() })
		req := newUnknownLengthRequest(http.MethodPut, body)
		req.URL.Path = "/upload"
		req.Host = "files.example"
		if _, err := client.Query(withTestAddress(req), Policy{}, nil); !errors.Is(err, ErrBodyReadTimeout) {
			t.Fatalf("Query() error %v want ErrBodyReadTimeout", err)
		}
	}
	logged := sink.String()
	if count := strings.Count(logged, msgBodyReadTimeout); count != 1 {
		t.Fatalf("WARN logged %d times, want 1:\n%s", count, logged)
	}
	if !strings.Contains(msgBodyReadTimeout, "appsecBodyReadTimeoutSeconds") || !strings.Contains(msgBodyReadTimeout, "bypassAppsec") {
		t.Fatalf("WARN %q must name appsecBodyReadTimeoutSeconds and bypassAppsec", msgBodyReadTimeout)
	}
	var record map[string]any
	for _, line := range strings.Split(strings.TrimSpace(logged), "\n") {
		if strings.Contains(line, msgBodyReadTimeout) {
			if err := json.Unmarshal([]byte(line), &record); err != nil {
				t.Fatalf("log line %q: %v", line, err)
			}
		}
	}
	want := map[string]any{
		"level":          "WARN",
		"ip":             "1.2.3.4",
		"method":         http.MethodPut,
		"host":           "files.example",
		"path":           "/upload",
		"timeoutSeconds": float64(1),
	}
	for key, wantValue := range want {
		if record[key] != wantValue {
			t.Errorf("WARN attr %s = %#v want %#v (record %v)", key, record[key], wantValue, record)
		}
	}
}

// queryOutcome is what the front handler saw from Query on a real server connection.
type queryOutcome struct {
	err        error
	elapsed    time.Duration
	protoMajor int
}

// TestBodyReadTimeout_HTTP1ChunkedStallIsCutByResponseController: on HTTP/1.1 only the response
// controller's read deadline cuts the read (Body.Close waits for the in-flight Read).
func TestBodyReadTimeout_HTTP1ChunkedStallIsCutByResponseController(t *testing.T) {
	outcome := runStalledClientBodyThroughServer(t, false)
	if outcome.protoMajor != 1 {
		t.Fatalf("front server saw HTTP/%d, want HTTP/1.1", outcome.protoMajor)
	}
	assertStalledClientBodyCut(t, outcome)
}

// TestBodyReadTimeout_HTTP2StallIsCutByResponseController: same stall over HTTP/2 (TLS, ALPN h2).
func TestBodyReadTimeout_HTTP2StallIsCutByResponseController(t *testing.T) {
	outcome := runStalledClientBodyThroughServer(t, true)
	if outcome.protoMajor != 2 {
		t.Fatalf("front server saw HTTP/%d, want HTTP/2", outcome.protoMajor)
	}
	assertStalledClientBodyCut(t, outcome)
}

// assertStalledClientBodyCut checks the deadline outcome arrived about one second in, long before the client ended its body.
func assertStalledClientBodyCut(t *testing.T, outcome queryOutcome) {
	t.Helper()
	if !errors.Is(outcome.err, ErrBodyReadTimeout) {
		t.Fatalf("Query() error %v want ErrBodyReadTimeout", outcome.err)
	}
	if outcome.elapsed > 3*time.Second {
		t.Fatalf("Query() returned after %v, want about 1s", outcome.elapsed)
	}
}

// runStalledClientBodyThroughServer sends a body without Content-Length that never ends to a real
// server whose handler calls Query with http.NewResponseController(w), and returns what Query did.
func runStalledClientBodyThroughServer(t *testing.T, useHTTP2 bool) queryOutcome {
	t.Helper()
	client, hits := newOneSecondDeadlineClient(t, logger.New("ERROR", ""))
	outcomes := make(chan queryOutcome, 1)
	front := httptest.NewUnstartedServer(http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
		started := time.Now()
		_, err := client.Query(withTestAddress(r), Policy{FailureAction: configuration.FailureActionPassthrough}, http.NewResponseController(rw))
		outcomes <- queryOutcome{err: err, elapsed: time.Since(started), protoMajor: r.ProtoMajor}
		rw.WriteHeader(http.StatusForbidden)
	}))
	if useHTTP2 {
		front.EnableHTTP2 = true
		front.StartTLS()
	} else {
		front.Start()
	}
	defer front.Close()

	// The client writes a few bytes and keeps its body open until the test ends.
	bodyReader, bodyWriter := io.Pipe()
	defer func() { _ = bodyWriter.Close() }()
	go func() { _, _ = bodyWriter.Write([]byte("partial")) }()
	req, err := http.NewRequest(http.MethodPost, front.URL+"/stream", bodyReader)
	if err != nil {
		t.Fatal(err)
	}
	go func() {
		res, doErr := front.Client().Do(req)
		if doErr == nil {
			_, _ = io.Copy(io.Discard, res.Body)
			_ = res.Body.Close()
		}
	}()

	timeout := time.NewTimer(10 * time.Second)
	defer timeout.Stop()
	select {
	case outcome := <-outcomes:
		if got := atomic.LoadInt32(hits); got != 0 {
			t.Fatalf("AppSec listener called %d times, want 0", got)
		}
		return outcome
	case <-timeout.C:
		t.Fatal("Query() was not cut by the body read deadline within 10s")
		return queryOutcome{}
	}
}
