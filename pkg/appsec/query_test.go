package appsec

import (
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/maxlerebourg/crowdsec-bouncer-traefik-plugin/pkg/configuration"
	logger "github.com/maxlerebourg/crowdsec-bouncer-traefik-plugin/pkg/logger"
)

type blockingBody struct {
	done <-chan struct{}
}

func (b blockingBody) Read(_ []byte) (int, error) {
	<-b.done
	return 0, io.EOF
}

func (blockingBody) Close() error { return nil }

func Test_isBodyUnreadable(t *testing.T) {
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
			if got := isBodyUnreadable(req); got != tt.want {
				t.Errorf("isBodyUnreadable() = %v, want %v", got, tt.want)
			}
		})
	}
}

func newStreamingRequest(done <-chan struct{}) *http.Request {
	req, _ := http.NewRequest(http.MethodPost, "http://localhost/signalexchange.SignalExchange/ConnectStream", blockingBody{done: done})
	req.Header.Set("Content-Type", "application/grpc")
	req.ProtoMajor = 2
	req.ContentLength = -1
	return req
}

func newQueryClient(appsecURL *url.URL, client *http.Client) *Client {
	return NewTestClient(appsecURL, client, logger.New("INFO", ""))
}

func Test_appsecQuery_streamingDoesNotBlock(t *testing.T) {
	appsecServer := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, _ *http.Request) {
		rw.WriteHeader(http.StatusOK)
	}))
	defer appsecServer.Close()
	appsecURL, _ := url.Parse(appsecServer.URL)
	client := newQueryClient(appsecURL, appsecServer.Client())
	done := make(chan struct{})
	defer close(done)
	finished := make(chan error, 1)
	go func() {
		_, err := client.Query("1.2.3.4", newStreamingRequest(done), Policy{FailureAction: configuration.FailureActionPassthrough})
		finished <- err
	}()
	select {
	case err := <-finished:
		if err != nil {
			t.Errorf("Query() on streaming request returned error: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Query() blocked on a streaming request body (issue #323 regression)")
	}
}

func Test_appsecQuery_dropUnreadableBody(t *testing.T) {
	appsecServer := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, _ *http.Request) {
		rw.WriteHeader(http.StatusOK)
	}))
	defer appsecServer.Close()
	appsecURL, _ := url.Parse(appsecServer.URL)
	client := newQueryClient(appsecURL, appsecServer.Client())
	done := make(chan struct{})
	defer close(done)
	finished := make(chan error, 1)
	go func() {
		_, err := client.Query("1.2.3.4", newStreamingRequest(done), Policy{FailureAction: configuration.FailureActionBan})
		finished <- err
	}()
	select {
	case err := <-finished:
		if err == nil {
			t.Error("Query() expected an error to block the request, got nil")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Query() blocked on a streaming request body (issue #323 regression)")
	}
}

func newUnreadableGetRequest(done <-chan struct{}) *http.Request {
	req, _ := http.NewRequest(http.MethodGet, "http://localhost/", blockingBody{done: done})
	req.ProtoMajor = 3
	req.ContentLength = -1
	return req
}

func Test_appsecQuery_unreadableBodyGetNotDropped(t *testing.T) {
	appsecServer := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, _ *http.Request) {
		rw.WriteHeader(http.StatusOK)
	}))
	defer appsecServer.Close()
	appsecURL, _ := url.Parse(appsecServer.URL)
	client := newQueryClient(appsecURL, appsecServer.Client())
	done := make(chan struct{})
	defer close(done)
	finished := make(chan error, 1)
	go func() {
		_, err := client.Query("1.2.3.4", newUnreadableGetRequest(done), Policy{FailureAction: configuration.FailureActionBan})
		finished <- err
	}()
	select {
	case err := <-finished:
		if err != nil {
			t.Errorf("Query() on an HTTP/3 GET without content-length returned error: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Query() blocked on an HTTP/3 GET request body (issue #351 regression)")
	}
}

func Test_appsecQuery_reusesConnection(t *testing.T) {
	statuses := []int{http.StatusOK, http.StatusForbidden, http.StatusInternalServerError,
		http.StatusBadGateway, http.StatusServiceUnavailable, http.StatusGatewayTimeout}
	for _, status := range statuses {
		t.Run(http.StatusText(status), func(t *testing.T) {
			var mu sync.Mutex
			conns := map[string]bool{}
			appsecServer := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
				mu.Lock()
				conns[r.RemoteAddr] = true
				mu.Unlock()
				rw.WriteHeader(status)
				if _, errWrite := rw.Write([]byte(`{"action":"allow"}`)); errWrite != nil {
					t.Errorf("appsec stub write: %v", errWrite)
				}
			}))
			defer appsecServer.Close()
			appsecURL, _ := url.Parse(appsecServer.URL)
			client := newQueryClient(appsecURL, appsecServer.Client())
			const calls = 10
			for i := 0; i < calls; i++ { //nolint:intrange
				req, _ := http.NewRequest(http.MethodGet, "http://localhost/", nil)
				_, _ = client.Query("1.2.3.4", req, Policy{FailureAction: configuration.FailureActionPassthrough})
			}
			mu.Lock()
			defer mu.Unlock()
			if len(conns) != 1 {
				t.Errorf("Query() opened %d connections for %d calls, want 1 (response body not drained?)", len(conns), calls)
			}
		})
	}
}

func Test_appsecQuery_allowJSONPasses(t *testing.T) {
	appsecServer := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, _ *http.Request) {
		rw.WriteHeader(http.StatusOK)
		_, _ = rw.Write([]byte(`{"action":"allow"}`))
	}))
	defer appsecServer.Close()
	appsecURL, _ := url.Parse(appsecServer.URL)
	decision, err := newQueryClient(appsecURL, appsecServer.Client()).Query("1.2.3.4", httptest.NewRequest(http.MethodGet, "http://localhost/", nil), Policy{})
	if err != nil {
		t.Fatalf("Query() returned error: %v", err)
	}
	if decision == nil || decision.Action != ActionAllow {
		t.Fatalf("Query() want allow decision, got %#v", decision)
	}
}

func Test_appsecQuery_emptyOKPasses(t *testing.T) {
	appsecServer := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, _ *http.Request) {
		rw.WriteHeader(http.StatusOK)
	}))
	defer appsecServer.Close()
	appsecURL, _ := url.Parse(appsecServer.URL)
	decision, err := newQueryClient(appsecURL, appsecServer.Client()).Query("1.2.3.4", httptest.NewRequest(http.MethodGet, "http://localhost/", nil), Policy{})
	if err != nil {
		t.Fatalf("Query() returned error: %v", err)
	}
	if decision == nil || decision.Action != ActionAllow {
		t.Fatalf("Query() want allow for empty 200, got %#v", decision)
	}
}

func Test_appsecQuery_challengeJSON(t *testing.T) {
	appsecServer := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, _ *http.Request) {
		rw.WriteHeader(http.StatusForbidden)
		_, _ = rw.Write([]byte(`{"action":"challenge","http_status":200,"user_body_content":"<html>challenge</html>"}`))
	}))
	defer appsecServer.Close()
	appsecURL, _ := url.Parse(appsecServer.URL)
	decision, err := newQueryClient(appsecURL, appsecServer.Client()).Query("1.2.3.4", httptest.NewRequest(http.MethodGet, "http://localhost/", nil), Policy{})
	if err != nil {
		t.Fatalf("Query() returned error: %v", err)
	}
	if decision == nil || decision.Action != ActionChallenge {
		t.Fatalf("Query() want challenge, got %#v", decision)
	}
	if decision.HTTPStatus != http.StatusOK || decision.UserBodyContent != "<html>challenge</html>" {
		t.Fatalf("Query() challenge fields: %#v", decision)
	}
}

func Test_appsecQuery_emptyForbiddenErrors(t *testing.T) {
	appsecServer := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, _ *http.Request) {
		rw.WriteHeader(http.StatusForbidden)
	}))
	defer appsecServer.Close()
	appsecURL, _ := url.Parse(appsecServer.URL)
	decision, err := newQueryClient(appsecURL, appsecServer.Client()).Query("1.2.3.4", httptest.NewRequest(http.MethodGet, "http://localhost/", nil), Policy{})
	if err == nil {
		t.Fatal("Query() expected error for empty 403")
	}
	if decision != nil {
		t.Fatalf("Query() returned decision: %#v", decision)
	}
}

func Test_appsecQuery_oversizedOKResponsePasses(t *testing.T) {
	appsecServer := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, _ *http.Request) {
		rw.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(rw, strings.Repeat("x", int(appsecResponseBodyLimit)+1))
	}))
	defer appsecServer.Close()
	appsecURL, _ := url.Parse(appsecServer.URL)
	decision, err := newQueryClient(appsecURL, appsecServer.Client()).Query("1.2.3.4", httptest.NewRequest(http.MethodGet, "http://localhost/", nil), Policy{})
	if err != nil {
		t.Fatalf("Query() returned error: %v", err)
	}
	if decision == nil || decision.Action != ActionAllow {
		t.Fatalf("Query() want allow for oversized 200, got %#v", decision)
	}
}

func Test_appsecQuery_oversizedForbiddenResponseBlocks(t *testing.T) {
	appsecServer := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, _ *http.Request) {
		rw.WriteHeader(http.StatusForbidden)
		_, _ = io.WriteString(rw, strings.Repeat("x", int(appsecResponseBodyLimit)+1))
	}))
	defer appsecServer.Close()
	appsecURL, _ := url.Parse(appsecServer.URL)
	decision, err := newQueryClient(appsecURL, appsecServer.Client()).Query("1.2.3.4", httptest.NewRequest(http.MethodGet, "http://localhost/", nil), Policy{})
	if err == nil {
		t.Fatal("Query() expected error, got nil")
	}
	if decision != nil {
		t.Fatalf("Query() returned decision: %#v", decision)
	}
}

func Test_appsecQuery_forwardContentLengthMatchesTruncatedBody(t *testing.T) {
	const limit = 8
	var gotLength string
	var gotBody []byte
	appsecServer := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
		gotLength = r.Header.Get("Content-Length")
		gotBody, _ = io.ReadAll(r.Body)
		rw.WriteHeader(http.StatusOK)
		_, _ = rw.Write([]byte(`{"action":"allow"}`))
	}))
	defer appsecServer.Close()
	appsecURL, _ := url.Parse(appsecServer.URL)
	client := NewTestClientWithBodyLimit(appsecURL, appsecServer.Client(), logger.New("INFO", ""), limit)
	req := httptest.NewRequest(http.MethodPost, "http://localhost/", strings.NewReader("0123456789abcdef"))
	req.Header.Set("Content-Length", "16")
	req.Header.Set("Transfer-Encoding", "chunked")
	_, err := client.Query("1.2.3.4", req, Policy{FailureAction: configuration.FailureActionPassthrough})
	if err != nil {
		t.Fatalf("Query() returned error: %v", err)
	}
	if gotLength != "8" {
		t.Fatalf("Content-Length = %q, want 8", gotLength)
	}
	if string(gotBody) != "01234567" {
		t.Fatalf("forwarded body = %q, want truncated prefix", string(gotBody))
	}
}

func Test_appsecQuery_bodyLimitZeroForwardsFullPost(t *testing.T) {
	payload := strings.Repeat("a", 32)
	var gotMethod string
	var gotBody []byte
	appsecServer := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
		gotMethod = r.Method
		gotBody, _ = io.ReadAll(r.Body)
		rw.WriteHeader(http.StatusOK)
		_, _ = rw.Write([]byte(`{"action":"allow"}`))
	}))
	defer appsecServer.Close()
	appsecURL, _ := url.Parse(appsecServer.URL)
	client := NewTestClientWithBodyLimit(appsecURL, appsecServer.Client(), logger.New("INFO", ""), 0)
	req := httptest.NewRequest(http.MethodPost, "http://localhost/", strings.NewReader(payload))
	_, err := client.Query("1.2.3.4", req, Policy{FailureAction: configuration.FailureActionPassthrough})
	if err != nil {
		t.Fatalf("Query() returned error: %v", err)
	}
	if gotMethod != http.MethodPost {
		t.Fatalf("AppSec method = %q, want POST", gotMethod)
	}
	if string(gotBody) != payload {
		t.Fatalf("forwarded body length = %d, want %d", len(gotBody), len(payload))
	}
}

type errReadCloser struct {
	err error
}

func (e errReadCloser) Read(_ []byte) (int, error) { return 0, e.err }
func (errReadCloser) Close() error                 { return nil }

func Test_appsecQuery_failureActionOnReadError(t *testing.T) {
	appsecServer := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, _ *http.Request) {
		rw.WriteHeader(http.StatusOK)
		if flusher, ok := rw.(http.Flusher); ok {
			flusher.Flush()
		}
	}))
	defer appsecServer.Close()
	appsecURL, _ := url.Parse(appsecServer.URL)
	transport := appsecServer.Client().Transport
	client := &http.Client{Transport: transport}
	queryClient := newQueryClient(appsecURL, client)
	req := httptest.NewRequest(http.MethodGet, "http://localhost/", nil)

	origTransport := queryClient.httpClient.Transport
	queryClient.httpClient.Transport = roundTripFunc(func(r *http.Request) (*http.Response, error) {
		res, err := origTransport.RoundTrip(r)
		if err != nil {
			return nil, err
		}
		res.Body = errReadCloser{err: io.ErrUnexpectedEOF}
		return res, nil
	})

	_, err := queryClient.Query("1.2.3.4", req, Policy{FailureAction: configuration.FailureActionBan})
	if err == nil {
		t.Fatal("ban on read error expected an error")
	}

	decision, err := queryClient.Query("1.2.3.4", req, Policy{FailureAction: configuration.FailureActionPassthrough})
	if err != nil {
		t.Fatalf("passthrough on read error: %v", err)
	}
	if decision == nil || decision.Action != ActionAllow {
		t.Fatalf("passthrough on read error want allow, got %#v", decision)
	}
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }
