package appsec

import (
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pkg/clientrequest"
	"github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pkg/configuration"
	logger "github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pkg/logger"
)

func testAppsecConfig(host string) *configuration.Config {
	return &configuration.Config{
		AppsecBodyLimit:          10485760,
		AppsecEnabled:            true,
		AppsecHost:               host,
		AppsecHTTPTimeoutSeconds: 1,
		AppsecKey:                "test-key",
		AppsecPath:               "/",
		AppsecScheme:             "http",
		AppsecTLSInsecureVerify:  true,
	}
}

// buildTestRequest builds a Query test request with the standard 1.2.3.4 client address.
func buildTestRequest(httpReq *http.Request) clientrequest.Request {
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

func newStreamingRequest(done <-chan struct{}) *http.Request {
	req, _ := http.NewRequest(http.MethodPost, "http://localhost/signalexchange.SignalExchange/ConnectStream", blockingBody{done: done})
	req.Header.Set("Content-Type", "application/grpc")
	req.ProtoMajor = 2
	req.ContentLength = -1
	return req
}

func newUnreadableGetRequest(done <-chan struct{}) *http.Request {
	req, _ := http.NewRequest(http.MethodGet, "http://localhost/", blockingBody{done: done})
	req.ProtoMajor = 3
	req.ContentLength = -1
	return req
}

// newUnreadableDeleteRequest is an HTTP/2 DELETE whose body cannot be buffered.
func newUnreadableDeleteRequest(done <-chan struct{}) *http.Request {
	req, _ := http.NewRequest(http.MethodDelete, "http://localhost/", blockingBody{done: done})
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
	decision, err := client.Query(buildTestRequest(newReadablePostWithFailingBody(readErr)), Policy{FailureAction: failureAction})
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

func assertUnclassifiedBodyReadStillGetBody(t *testing.T) {
	t.Helper()
	var appsecHits int
	appsecServer := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, _ *http.Request) {
		appsecHits++
		rw.WriteHeader(http.StatusOK)
	}))
	defer appsecServer.Close()
	appsecURL, _ := url.Parse(appsecServer.URL)
	client := newQueryClient(appsecURL, appsecServer.Client())
	sentinel := errors.New("disk read fault")
	_, err := client.Query(buildTestRequest(newReadablePostWithFailingBody(sentinel)), Policy{FailureAction: configuration.FailureActionPassthrough})
	if err == nil {
		t.Fatal("Query() expected error for unclassified body read failure")
	}
	if !errors.Is(err, sentinel) {
		t.Fatalf("Query() error %v want wrap of %v", err, sentinel)
	}
	if !strings.Contains(err.Error(), "appsecQuery:GetBody") {
		t.Fatalf("Query() error %q want appsecQuery:GetBody prefix", err.Error())
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
