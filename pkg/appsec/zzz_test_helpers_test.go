package appsec

import (
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"

	"github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pkg/clientrequest"
	"github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pkg/configuration"
	logger "github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pkg/logger"
)

func testAppsecConfig(host string) *configuration.Config {
	return &configuration.Config{
		AppsecBodyLimit:              10485760,
		AppsecBodyReadTimeoutSeconds: configuration.DefaultBodyReadTimeoutSeconds,
		AppsecEnabled:                true,
		AppsecHost:                   host,
		AppsecHTTPTimeoutSeconds:     1,
		AppsecKey:                    "test-key",
		AppsecPath:                   "/",
		AppsecScheme:                 "http",
		AppsecTLSInsecureVerify:      true,
	}
}

// buildTestRequest is a GET http://localhost/ with the standard 1.2.3.4 client address.
func buildTestRequest() clientrequest.Request {
	return withTestAddress(httptest.NewRequest(http.MethodGet, "http://localhost/", nil))
}

// withTestAddress attaches the standard 1.2.3.4 client address to a request the test already built.
func withTestAddress(httpReq *http.Request) clientrequest.Request {
	return clientrequest.New(httpReq, "1.2.3.4", net.ParseIP("1.2.3.4"))
}

func newQueryClient(appsecURL *url.URL, client *http.Client) *Client {
	return NewTestClient(appsecURL, client, logger.New("INFO", ""))
}

type blockingBody struct {
	done <-chan struct{}
}

func (b blockingBody) Read(_ []byte) (int, error) {
	<-b.done
	return 0, io.EOF
}

func (blockingBody) Close() error { return nil }

// failingBody simulates a readable POST whose io.ReadAll fails mid-copy (client disconnect).
type failingBody struct {
	err error
}

func (b failingBody) Read(_ []byte) (int, error) {
	return 0, b.err
}

func (failingBody) Close() error { return nil }

func newReadablePostWithFailingBody(readErr error) *http.Request {
	req := httptest.NewRequest(http.MethodPost, "http://localhost/", failingBody{err: readErr})
	req.ProtoMajor = 1
	req.ContentLength = 100
	return req
}

// stallingTestBody blocks every Read until Close, the way an HTTP/2 stream that never ends blocks
// until its handler closes the body.
type stallingTestBody struct {
	once sync.Once
	cut  chan struct{}
}

// newStallingTestBody returns a body that stalls until it is closed.
func newStallingTestBody() *stallingTestBody {
	return &stallingTestBody{cut: make(chan struct{})}
}

// Read blocks until Close, then fails like a closed HTTP/2 request body.
func (b *stallingTestBody) Read(_ []byte) (int, error) {
	<-b.cut
	return 0, errors.New("http2: request body closed due to handler exiting")
}

// Close unblocks Read.
func (b *stallingTestBody) Close() error {
	b.once.Do(func() { close(b.cut) })
	return nil
}

// newStreamingTestRequest is a gRPC client stream over HTTP/2 whose body never ends until it is closed.
func newStreamingTestRequest(method string) *http.Request {
	req, _ := http.NewRequest(method, "http://localhost/signalexchange.SignalExchange/ConnectStream", newStallingTestBody())
	req.Header.Set("Content-Type", "application/grpc")
	req.ProtoMajor = 2
	req.ContentLength = -1
	return req
}

// newStalledUnknownLengthGetTestRequest is an HTTP/3 GET whose body never ends: AppSec must not read it.
func newStalledUnknownLengthGetTestRequest(done <-chan struct{}) *http.Request {
	req, _ := http.NewRequest(http.MethodGet, "http://localhost/", blockingBody{done: done})
	req.ProtoMajor = 3
	req.ContentLength = -1
	return req
}

// newUnknownLengthTestRequest is an HTTP/2 request with body and no Content-Length.
func newUnknownLengthTestRequest(method, body string) *http.Request {
	req, _ := http.NewRequest(method, "http://localhost/", io.NopCloser(strings.NewReader(body)))
	req.ProtoMajor = 2
	req.ContentLength = -1
	return req
}

func assertClientDisconnectedQuery(t *testing.T, readErr error, failureAction string) {
	t.Helper()
	var appsecHits int
	appsecServer := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, _ *http.Request) {
		appsecHits++
		rw.WriteHeader(http.StatusOK)
		_, _ = rw.Write([]byte(`{"action":"allow"}`))
	}))
	defer appsecServer.Close()
	appsecURL, _ := url.Parse(appsecServer.URL)
	client := newQueryClient(appsecURL, appsecServer.Client())
	decision, err := client.Query(withTestAddress(newReadablePostWithFailingBody(readErr)), Policy{FailureAction: failureAction}, nil)
	if !errors.Is(err, ErrClientDisconnected) {
		t.Fatalf("Query() error %v want ErrClientDisconnected", err)
	}
	if decision != nil {
		t.Fatalf("Query() expected no decision, got %#v", decision)
	}
	if appsecHits != 0 {
		t.Fatalf("AppSec server called %d times, want 0", appsecHits)
	}
}

// assertUnclassifiedBodyReadIsClientBodyRead checks that a read failure with a live request context
// is ErrClientBodyRead (answered 400 by the bouncer), never a GetBody ban, even with passthrough.
func assertUnclassifiedBodyReadIsClientBodyRead(t *testing.T) {
	t.Helper()
	var appsecHits int
	appsecServer := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, _ *http.Request) {
		appsecHits++
		rw.WriteHeader(http.StatusOK)
	}))
	defer appsecServer.Close()
	appsecURL, _ := url.Parse(appsecServer.URL)
	client := newQueryClient(appsecURL, appsecServer.Client())
	for _, failureAction := range []string{configuration.FailureActionBan, configuration.FailureActionPassthrough} {
		_, err := client.Query(withTestAddress(newReadablePostWithFailingBody(errors.New("disk read fault"))), Policy{FailureAction: failureAction}, nil)
		if !errors.Is(err, ErrClientBodyRead) {
			t.Fatalf("failureAction=%s: Query() error %v want ErrClientBodyRead", failureAction, err)
		}
		if errors.Is(err, ErrClientDisconnected) {
			t.Fatalf("failureAction=%s: Query() error %v must not be ErrClientDisconnected", failureAction, err)
		}
		if !strings.Contains(err.Error(), "disk read fault") {
			t.Fatalf("failureAction=%s: Query() error %q want the read error text", failureAction, err.Error())
		}
	}
	if appsecHits != 0 {
		t.Fatalf("AppSec server called %d times, want 0", appsecHits)
	}
}

// assertCanceledContextReadErrIsDisconnect checks that any read error is a client disconnect once
// the request context is canceled (HTTP/2 stream reset, HTTP/1.1 TCP reset or read timeout).
func assertCanceledContextReadErrIsDisconnect(t *testing.T) {
	t.Helper()
	var appsecHits int
	appsecServer := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, _ *http.Request) {
		appsecHits++
		rw.WriteHeader(http.StatusOK)
	}))
	defer appsecServer.Close()
	appsecURL, _ := url.Parse(appsecServer.URL)
	client := newQueryClient(appsecURL, appsecServer.Client())
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	req := newReadablePostWithFailingBody(errors.New("stream error: stream ID 1; CANCEL")).WithContext(ctx)
	_, err := client.Query(withTestAddress(req), Policy{FailureAction: configuration.FailureActionBan}, nil)
	if !errors.Is(err, ErrClientDisconnected) {
		t.Fatalf("Query() error %v want ErrClientDisconnected", err)
	}
	if appsecHits != 0 {
		t.Fatalf("AppSec server called %d times, want 0", appsecHits)
	}
}

// captureRoundTripper records the outbound AppSec request length headers.
type captureRoundTripper struct {
	contentLength       int64
	contentLengthHeader string
	transferEncoding    string
}

// RoundTrip records length headers then allows the query.
func (rt *captureRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	rt.contentLength = req.ContentLength
	rt.contentLengthHeader = req.Header.Get("Content-Length")
	rt.transferEncoding = req.Header.Get("Transfer-Encoding")
	return &http.Response{
		StatusCode: http.StatusOK,
		Body:       io.NopCloser(strings.NewReader(`{"action":"allow"}`)),
		Header:     make(http.Header),
		Request:    req,
	}, nil
}

// forwardCaptureRoundTripper records the whole outbound AppSec request without dialing a listener.
type forwardCaptureRoundTripper struct {
	method string
	header http.Header
	body   string
}

// RoundTrip records the forwarded method, headers, and body then allows the query.
func (rt *forwardCaptureRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	rt.method = req.Method
	rt.header = req.Header.Clone()
	if req.Body != nil {
		body, _ := io.ReadAll(req.Body)
		rt.body = string(body)
	}
	return &http.Response{
		StatusCode: http.StatusOK,
		Body:       io.NopCloser(strings.NewReader(`{"action":"allow"}`)),
		Header:     make(http.Header),
		Request:    req,
	}, nil
}

// newForwardCaptureClient returns a Client whose AppSec round-trip is captured instead of sent.
func newForwardCaptureClient(capture *forwardCaptureRoundTripper) *Client {
	return NewTestClient(&url.URL{Scheme: "http", Host: "appsec.example"}, &http.Client{Transport: capture}, logger.New("INFO", ""))
}
