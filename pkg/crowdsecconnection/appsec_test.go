package crowdsecconnection

import (
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

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

func appsecConn(appsecURL *url.URL, client *http.Client) *CrowdsecConnection {
	return &CrowdsecConnection{
		appsecScheme:     appsecURL.Scheme,
		appsecHost:       appsecURL.Host,
		appsecPath:       "/",
		appsecBodyLimit:  10485760,
		httpAppsecClient: client,
		log:              logger.New("INFO", ""),
	}
}

func Test_appsecQuery_streamingDoesNotBlock(t *testing.T) {
	appsecServer := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, _ *http.Request) {
		rw.WriteHeader(http.StatusOK)
	}))
	defer appsecServer.Close()
	appsecURL, _ := url.Parse(appsecServer.URL)
	conn := appsecConn(appsecURL, appsecServer.Client())
	done := make(chan struct{})
	defer close(done)
	finished := make(chan error, 1)
	go func() {
		_, err := conn.AppsecQuery("1.2.3.4", newStreamingRequest(done), AppsecPolicy{UnreachableBlock: true, FailureBlock: true})
		finished <- err
	}()
	select {
	case err := <-finished:
		if err != nil {
			t.Errorf("AppsecQuery() on streaming request returned error: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("AppsecQuery() blocked on a streaming request body (issue #323 regression)")
	}
}

func Test_appsecQuery_dropUnreadableBody(t *testing.T) {
	appsecServer := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, _ *http.Request) {
		rw.WriteHeader(http.StatusOK)
	}))
	defer appsecServer.Close()
	appsecURL, _ := url.Parse(appsecServer.URL)
	conn := appsecConn(appsecURL, appsecServer.Client())
	done := make(chan struct{})
	defer close(done)
	finished := make(chan error, 1)
	go func() {
		_, err := conn.AppsecQuery("1.2.3.4", newStreamingRequest(done), AppsecPolicy{UnreadableBodyBlock: true})
		finished <- err
	}()
	select {
	case err := <-finished:
		if err == nil {
			t.Error("AppsecQuery() expected an error to block the request, got nil")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("AppsecQuery() blocked on a streaming request body (issue #323 regression)")
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
	conn := appsecConn(appsecURL, appsecServer.Client())
	done := make(chan struct{})
	defer close(done)
	finished := make(chan error, 1)
	go func() {
		_, err := conn.AppsecQuery("1.2.3.4", newUnreadableGetRequest(done), AppsecPolicy{UnreadableBodyBlock: true})
		finished <- err
	}()
	select {
	case err := <-finished:
		if err != nil {
			t.Errorf("AppsecQuery() on an HTTP/3 GET without content-length returned error: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("AppsecQuery() blocked on an HTTP/3 GET request body (issue #351 regression)")
	}
}

func Test_appsecQuery_reusesConnection(t *testing.T) {
	for _, status := range []int{http.StatusOK, http.StatusForbidden, http.StatusInternalServerError} {
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
			conn := appsecConn(appsecURL, appsecServer.Client())
			const calls = 10
			for i := 0; i < calls; i++ { //nolint:intrange
				req, _ := http.NewRequest(http.MethodGet, "http://localhost/", nil)
				_, _ = conn.AppsecQuery("1.2.3.4", req, AppsecPolicy{FailureBlock: false})
			}
			mu.Lock()
			defer mu.Unlock()
			if len(conns) != 1 {
				t.Errorf("AppsecQuery() opened %d connections for %d calls, want 1 (response body not drained?)", len(conns), calls)
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
	decision, err := appsecConn(appsecURL, appsecServer.Client()).AppsecQuery("1.2.3.4", httptest.NewRequest(http.MethodGet, "http://localhost/", nil), AppsecPolicy{})
	if err != nil {
		t.Fatalf("AppsecQuery() returned error: %v", err)
	}
	if decision == nil || decision.Action != AppsecActionAllow {
		t.Fatalf("AppsecQuery() want allow decision, got %#v", decision)
	}
}

func Test_appsecQuery_challengeJSON(t *testing.T) {
	appsecServer := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, _ *http.Request) {
		rw.WriteHeader(http.StatusForbidden)
		_, _ = rw.Write([]byte(`{"action":"challenge","http_status":200,"user_body_content":"<html>challenge</html>"}`))
	}))
	defer appsecServer.Close()
	appsecURL, _ := url.Parse(appsecServer.URL)
	decision, err := appsecConn(appsecURL, appsecServer.Client()).AppsecQuery("1.2.3.4", httptest.NewRequest(http.MethodGet, "http://localhost/", nil), AppsecPolicy{})
	if err != nil {
		t.Fatalf("AppsecQuery() returned error: %v", err)
	}
	if decision == nil || decision.Action != AppsecActionChallenge {
		t.Fatalf("AppsecQuery() want challenge, got %#v", decision)
	}
	if decision.HTTPStatus != http.StatusOK || decision.UserBodyContent != "<html>challenge</html>" {
		t.Fatalf("AppsecQuery() challenge fields: %#v", decision)
	}
}

func Test_appsecQuery_emptyForbiddenErrors(t *testing.T) {
	appsecServer := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, _ *http.Request) {
		rw.WriteHeader(http.StatusForbidden)
	}))
	defer appsecServer.Close()
	appsecURL, _ := url.Parse(appsecServer.URL)
	decision, err := appsecConn(appsecURL, appsecServer.Client()).AppsecQuery("1.2.3.4", httptest.NewRequest(http.MethodGet, "http://localhost/", nil), AppsecPolicy{})
	if err == nil {
		t.Fatal("AppsecQuery() expected error for empty 403")
	}
	if decision != nil {
		t.Fatalf("AppsecQuery() returned decision: %#v", decision)
	}
}

func Test_appsecQuery_oversizedOKResponsePasses(t *testing.T) {
	appsecServer := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, _ *http.Request) {
		rw.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(rw, strings.Repeat("x", int(appsecResponseBodyLimit)+1))
	}))
	defer appsecServer.Close()
	appsecURL, _ := url.Parse(appsecServer.URL)
	decision, err := appsecConn(appsecURL, appsecServer.Client()).AppsecQuery("1.2.3.4", httptest.NewRequest(http.MethodGet, "http://localhost/", nil), AppsecPolicy{})
	if err != nil {
		t.Fatalf("AppsecQuery() returned error: %v", err)
	}
	if decision == nil || decision.Action != AppsecActionAllow {
		t.Fatalf("AppsecQuery() want allow for oversized 200, got %#v", decision)
	}
}

func Test_appsecQuery_oversizedForbiddenResponseBlocks(t *testing.T) {
	appsecServer := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, _ *http.Request) {
		rw.WriteHeader(http.StatusForbidden)
		_, _ = io.WriteString(rw, strings.Repeat("x", int(appsecResponseBodyLimit)+1))
	}))
	defer appsecServer.Close()
	appsecURL, _ := url.Parse(appsecServer.URL)
	decision, err := appsecConn(appsecURL, appsecServer.Client()).AppsecQuery("1.2.3.4", httptest.NewRequest(http.MethodGet, "http://localhost/", nil), AppsecPolicy{})
	if err == nil {
		t.Fatal("AppsecQuery() expected error, got nil")
	}
	if decision != nil {
		t.Fatalf("AppsecQuery() returned decision: %#v", decision)
	}
}
