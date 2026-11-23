package appsec

import (
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pkg/configuration"
)

// unknownLengthTestFailureActions are the failure actions a body without Content-Length must not depend on.
func unknownLengthTestFailureActions() []string {
	return []string{configuration.FailureActionBan, configuration.FailureActionPassthrough, configuration.FailureActionCaptcha}
}

// Test_appsecQuery_unknownLengthBodyIsInspected proves a body without Content-Length on HTTP/2 reaches
// AppSec as a POST with its bytes, on every body method, whatever the failure action says.
func Test_appsecQuery_unknownLengthBodyIsInspected(t *testing.T) {
	const payload = "a=0&"
	for _, method := range []string{http.MethodPost, http.MethodPut, http.MethodPatch, http.MethodDelete} {
		for _, failureAction := range unknownLengthTestFailureActions() {
			t.Run(method+"/"+failureAction, func(t *testing.T) {
				capture := &forwardCaptureRoundTripper{}
				req := newUnknownLengthTestRequest(method, payload)
				decision, err := newForwardCaptureClient(capture).Query(withTestAddress(req), Policy{FailureAction: failureAction}, nil)
				if err != nil || decision == nil || decision.Action != ActionAllow {
					t.Fatalf("Query() = %#v, %v want allow", decision, err)
				}
				if capture.method != http.MethodPost || capture.body != payload {
					t.Fatalf("AppSec got %s %q want POST %q", capture.method, capture.body, payload)
				}
				if got := capture.header.Get("Content-Length"); got != strconv.Itoa(len(payload)) {
					t.Fatalf("Content-Length header %q want %d", got, len(payload))
				}
				if got := capture.header.Get(crowdsecAppsecVerbHeader); got != method {
					t.Fatalf("%s %q want %q", crowdsecAppsecVerbHeader, got, method)
				}
				if origin := readAllTestBody(t, req); origin != payload {
					t.Fatalf("origin body %q want %q", origin, payload)
				}
			})
		}
	}
}

// Test_appsecQuery_emptyUnknownLengthPostIsInspected is the restic shape: an empty HTTP/2 POST with no
// Content-Length reaches AppSec and is allowed.
func Test_appsecQuery_emptyUnknownLengthPostIsInspected(t *testing.T) {
	capture := &forwardCaptureRoundTripper{}
	req := newUnknownLengthTestRequest(http.MethodPost, "")
	decision, err := newForwardCaptureClient(capture).Query(withTestAddress(req), Policy{FailureAction: configuration.FailureActionBan}, nil)
	if err != nil || decision == nil || decision.Action != ActionAllow {
		t.Fatalf("Query() = %#v, %v want allow", decision, err)
	}
	if capture.method != http.MethodPost || capture.body != "" {
		t.Fatalf("AppSec got %s %q want an empty POST", capture.method, capture.body)
	}
}

// Test_appsecQuery_unknownLengthGetStaysHeadersOnly proves a GET body is still not forwarded, so a GET
// body that never ends is never read.
func Test_appsecQuery_unknownLengthGetStaysHeadersOnly(t *testing.T) {
	done := make(chan struct{})
	defer close(done)
	capture := &forwardCaptureRoundTripper{}
	finished := make(chan error, 1)
	go func() {
		_, err := newForwardCaptureClient(capture).Query(withTestAddress(newUnknownLengthGetRequest(done)), Policy{FailureAction: configuration.FailureActionBan}, nil)
		finished <- err
	}()
	select {
	case err := <-finished:
		if err != nil {
			t.Fatalf("Query() on a GET with a body of unknown length returned error: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Query() read the body of a GET (issue #351 regression)")
	}
	if capture.method != http.MethodGet || capture.body != "" {
		t.Fatalf("AppSec got %s %q want a headers-only GET", capture.method, capture.body)
	}
}

// Test_appsecQuery_contentLengthDoesNotChangeForwardedBytes proves leaving out Content-Length does not
// change what AppSec inspects.
func Test_appsecQuery_contentLengthDoesNotChangeForwardedBytes(t *testing.T) {
	const payload = "user=admin' OR 1=1"
	withLength := &forwardCaptureRoundTripper{}
	req := httptest.NewRequest(http.MethodPost, "http://localhost/", strings.NewReader(payload))
	if _, err := newForwardCaptureClient(withLength).Query(withTestAddress(req), Policy{}, nil); err != nil {
		t.Fatal(err)
	}
	withoutLength := &forwardCaptureRoundTripper{}
	if _, err := newForwardCaptureClient(withoutLength).Query(withTestAddress(newUnknownLengthTestRequest(http.MethodPost, payload)), Policy{}, nil); err != nil {
		t.Fatal(err)
	}
	if withLength.method != withoutLength.method || withLength.body != withoutLength.body ||
		withLength.header.Get("Content-Length") != withoutLength.header.Get("Content-Length") {
		t.Fatalf("with Content-Length %s %q (%s), without %s %q (%s)",
			withLength.method, withLength.body, withLength.header.Get("Content-Length"),
			withoutLength.method, withoutLength.body, withoutLength.header.Get("Content-Length"))
	}
}

// Test_appsecQuery_streamHitsTheDeadline proves a body that never ends (gRPC client stream) is
// ErrBodyReadTimeout after appsecBodyReadTimeoutSeconds, AppSec is not called, and the failure action
// does not change that.
func Test_appsecQuery_streamHitsTheDeadline(t *testing.T) {
	for _, failureAction := range unknownLengthTestFailureActions() {
		t.Run(failureAction, func(t *testing.T) {
			capture := &forwardCaptureRoundTripper{}
			client := newForwardCaptureClient(capture)
			client.bodyReadTimeout = 50 * time.Millisecond
			req := newStreamingTestRequest(http.MethodPost)
			defer func() { _ = req.Body.Close() }()
			started := time.Now()
			decision, err := client.Query(withTestAddress(req), Policy{FailureAction: failureAction}, nil)
			if !errors.Is(err, ErrBodyReadTimeout) {
				t.Fatalf("Query() = %#v, %v want ErrBodyReadTimeout", decision, err)
			}
			if errors.Is(err, ErrClientBodyRead) || errors.Is(err, ErrClientDisconnected) || errors.Is(err, ErrFailureCaptcha) {
				t.Fatalf("Query() error %v must only be ErrBodyReadTimeout", err)
			}
			if capture.method != "" {
				t.Fatalf("AppSec was called (%s) for a stalled body", capture.method)
			}
			if elapsed := time.Since(started); elapsed > 2*time.Second {
				t.Fatalf("Query() returned after %v, want about 50ms", elapsed)
			}
		})
	}
}

// readAllTestBody reads what next would read from req.
func readAllTestBody(t *testing.T, req *http.Request) string {
	t.Helper()
	origin, err := io.ReadAll(req.Body)
	if err != nil {
		t.Fatalf("origin body: %v", err)
	}
	return string(origin)
}
