package appsec

import (
	"context"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pkg/clientrequest"
	"github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pkg/configuration"
	logger "github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pkg/logger"
)

// Test_appsecQuery_clientDisconnected is a regression for
// https://github.com/maxlerebourg/crowdsec-bouncer-traefik-plugin/issues/395
func Test_appsecQuery_clientDisconnected(t *testing.T) {
	clientGoneErrs := []struct {
		name string
		err  error
	}{
		{name: "context canceled", err: context.Canceled},
		{name: "deadline exceeded", err: context.DeadlineExceeded},
		{name: "unexpected EOF", err: io.ErrUnexpectedEOF},
	}
	for _, goneCase := range clientGoneErrs {
		t.Run(goneCase.name+"/ban-action-still-disconnects", func(t *testing.T) {
			assertClientDisconnectedQuery(t, goneCase.err, configuration.FailureActionBan)
		})
		t.Run(goneCase.name+"/passthrough-action-still-disconnects", func(t *testing.T) {
			assertClientDisconnectedQuery(t, goneCase.err, configuration.FailureActionPassthrough)
		})
	}
	t.Run("unclassified read error keeps GetBody wrap", assertUnclassifiedBodyReadStillGetBody)
}

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
		_, err := client.Query(withTestAddress(newStreamingRequest(done)), Policy{FailureAction: configuration.FailureActionPassthrough})
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
		_, err := client.Query(withTestAddress(newStreamingRequest(done)), Policy{FailureAction: configuration.FailureActionBan})
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
		_, err := client.Query(withTestAddress(newUnreadableGetRequest(done)), Policy{FailureAction: configuration.FailureActionBan})
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
	for _, status := range []int{http.StatusOK, http.StatusForbidden, http.StatusInternalServerError, http.StatusBadGateway, http.StatusServiceUnavailable, http.StatusGatewayTimeout} {
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
				_, _ = client.Query(withTestAddress(req), Policy{FailureAction: configuration.FailureActionPassthrough})
			}
			mu.Lock()
			defer mu.Unlock()
			if len(conns) != 1 {
				t.Errorf("Query() opened %d connections for %d calls, want 1 (response body not drained?)", len(conns), calls)
			}
		})
	}
}

// Test_appsecQuery_userAgentIncludesPluginVersion checks AppSec Query User-Agent includes the Client plugin version.
func Test_appsecQuery_userAgentIncludesPluginVersion(t *testing.T) {
	const wantVersion = "v9.9.9-test"
	gotUA := ""
	appsecServer := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
		gotUA = r.Header.Get("User-Agent")
		rw.WriteHeader(http.StatusOK)
		_, _ = rw.Write([]byte(`{"action":"allow"}`))
	}))
	defer appsecServer.Close()
	appsecURL, _ := url.Parse(appsecServer.URL)
	client := newQueryClient(appsecURL, appsecServer.Client())
	client.pluginVersion = wantVersion
	_, err := client.Query(buildTestRequest(), Policy{})
	if err != nil {
		t.Fatalf("Query() returned error: %v", err)
	}
	wantUA := "Crowdsec-Bouncer-Traefik-Plugin/" + wantVersion
	if gotUA != wantUA {
		t.Fatalf("User-Agent %q want %q", gotUA, wantUA)
	}
}

func Test_appsecQuery_allowJSONPasses(t *testing.T) {
	appsecServer := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, _ *http.Request) {
		rw.WriteHeader(http.StatusOK)
		_, _ = rw.Write([]byte(`{"action":"allow"}`))
	}))
	defer appsecServer.Close()
	appsecURL, _ := url.Parse(appsecServer.URL)
	decision, err := newQueryClient(appsecURL, appsecServer.Client()).Query(buildTestRequest(), Policy{})
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
	decision, err := newQueryClient(appsecURL, appsecServer.Client()).Query(buildTestRequest(), Policy{})
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
	decision, err := newQueryClient(appsecURL, appsecServer.Client()).Query(buildTestRequest(), Policy{})
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

func Test_appsecQuery_captchaJSON(t *testing.T) {
	appsecServer := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, _ *http.Request) {
		rw.WriteHeader(http.StatusForbidden)
		_, _ = rw.Write([]byte(`{"action":"captcha","http_status":403,"user_body_content":"<html>captcha</html>"}`))
	}))
	defer appsecServer.Close()
	appsecURL, _ := url.Parse(appsecServer.URL)
	decision, err := newQueryClient(appsecURL, appsecServer.Client()).Query(buildTestRequest(), Policy{})
	if err != nil {
		t.Fatalf("Query() returned error: %v", err)
	}
	if decision == nil || decision.Action != ActionCaptcha {
		t.Fatalf("Query() want captcha, got %#v", decision)
	}
	if decision.HTTPStatus != http.StatusForbidden || decision.UserBodyContent != "<html>captcha</html>" {
		t.Fatalf("Query() captcha fields: %#v", decision)
	}
}

func Test_appsecQuery_emptyForbiddenErrors(t *testing.T) {
	appsecServer := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, _ *http.Request) {
		rw.WriteHeader(http.StatusForbidden)
	}))
	defer appsecServer.Close()
	appsecURL, _ := url.Parse(appsecServer.URL)
	decision, err := newQueryClient(appsecURL, appsecServer.Client()).Query(buildTestRequest(), Policy{})
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
	decision, err := newQueryClient(appsecURL, appsecServer.Client()).Query(buildTestRequest(), Policy{})
	if err != nil {
		t.Fatalf("Query() returned error: %v", err)
	}
	if decision == nil || decision.Action != ActionAllow {
		t.Fatalf("Query() want allow for oversized 200, got %#v", decision)
	}
}

// Test_appsecQuery_zeroBodyLimitForwardsPost proves limit 0 POSTs the full body and restores it for origin.
func Test_appsecQuery_zeroBodyLimitForwardsPost(t *testing.T) {
	const payload = "hello-appsec-body"
	var gotMethod string
	var gotBody string
	appsecServer := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
		gotMethod = r.Method
		body, _ := io.ReadAll(r.Body)
		gotBody = string(body)
		rw.WriteHeader(http.StatusOK)
		_, _ = rw.Write([]byte(`{"action":"allow"}`))
	}))
	defer appsecServer.Close()
	appsecURL, _ := url.Parse(appsecServer.URL)
	client := newQueryClient(appsecURL, appsecServer.Client())
	client.appsecBodyLimit = 0
	req := httptest.NewRequest(http.MethodPost, "http://localhost/", strings.NewReader(payload))
	_, err := client.Query(withTestAddress(req), Policy{})
	if err != nil {
		t.Fatalf("Query() returned error: %v", err)
	}
	if gotMethod != http.MethodPost {
		t.Fatalf("AppSec method %q want POST", gotMethod)
	}
	if gotBody != payload {
		t.Fatalf("AppSec body %q want %q", gotBody, payload)
	}
	restored, err := io.ReadAll(req.Body)
	if err != nil {
		t.Fatalf("origin body: %v", err)
	}
	if string(restored) != payload {
		t.Fatalf("origin body %q want %q", restored, payload)
	}
}

// Test_appsecQuery_rebuildsContentLengthFromForwardedBytes proves outbound length matches the copied bytes.
func Test_appsecQuery_rebuildsContentLengthFromForwardedBytes(t *testing.T) {
	const forwarded = "abcd"
	capture := &captureRoundTripper{}
	client := NewTestClient(&url.URL{Scheme: "http", Host: "appsec.example"}, &http.Client{Transport: capture}, logger.New("INFO", ""))
	req := httptest.NewRequest(http.MethodPost, "http://localhost/", strings.NewReader(forwarded))
	req.Header.Set("Content-Length", "999")
	req.Header.Set("Transfer-Encoding", "chunked")
	_, err := client.Query(withTestAddress(req), Policy{})
	if err != nil {
		t.Fatalf("Query() returned error: %v", err)
	}
	if capture.contentLength != int64(len(forwarded)) {
		t.Fatalf("ContentLength field %d want %d", capture.contentLength, len(forwarded))
	}
	if capture.contentLengthHeader != "4" {
		t.Fatalf("Content-Length header %q want %q", capture.contentLengthHeader, "4")
	}
	if capture.transferEncoding != "" {
		t.Fatalf("Transfer-Encoding header %q want empty", capture.transferEncoding)
	}
}

// Test_appsecQuery_unreadableBodyDeleteNotDropped proves an unreadable DELETE is not a drop.
func Test_appsecQuery_unreadableBodyDeleteNotDropped(t *testing.T) {
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
		_, err := client.Query(withTestAddress(newUnreadableDeleteRequest(done)), Policy{FailureAction: configuration.FailureActionBan})
		finished <- err
	}()
	select {
	case err := <-finished:
		if err != nil {
			t.Errorf("Query() on an HTTP/2 DELETE without content-length returned error: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Query() blocked on an HTTP/2 DELETE request body")
	}
}

// Test_appsecQuery_forwardsBodyOnlyForBodyMethods proves a readable body reaches AppSec only on
// methods that legitimately carry one; a GET with a body must not be forwarded as a POST.
func Test_appsecQuery_forwardsBodyOnlyForBodyMethods(t *testing.T) {
	const payload = "hello-appsec-body"
	tests := []struct {
		name        string
		method      string
		wantForward bool
	}{
		{name: "get body is not forwarded", method: http.MethodGet, wantForward: false},
		{name: "head body is not forwarded", method: http.MethodHead, wantForward: false},
		{name: "options body is not forwarded", method: http.MethodOptions, wantForward: false},
		{name: "post body is forwarded", method: http.MethodPost, wantForward: true},
		{name: "put body is forwarded", method: http.MethodPut, wantForward: true},
		{name: "patch body is forwarded", method: http.MethodPatch, wantForward: true},
		{name: "delete body is forwarded", method: http.MethodDelete, wantForward: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			wantMethod, wantBody, wantLength := http.MethodGet, "", ""
			if tt.wantForward {
				wantMethod, wantBody, wantLength = http.MethodPost, payload, strconv.Itoa(len(payload))
			}
			capture := &forwardCaptureRoundTripper{}
			req := httptest.NewRequest(tt.method, "http://localhost/", strings.NewReader(payload))
			if _, err := newForwardCaptureClient(capture).Query(withTestAddress(req), Policy{}); err != nil {
				t.Fatalf("Query() returned error: %v", err)
			}
			if capture.method != wantMethod {
				t.Errorf("AppSec method %q want %q", capture.method, wantMethod)
			}
			if capture.body != wantBody {
				t.Errorf("AppSec body %q want %q", capture.body, wantBody)
			}
			if got := capture.header.Get("Content-Length"); got != wantLength {
				t.Errorf("Content-Length header %q want %q", got, wantLength)
			}
			if got := capture.header.Get(crowdsecAppsecVerbHeader); got != tt.method {
				t.Errorf("%s %q want %q", crowdsecAppsecVerbHeader, got, tt.method)
			}
			origin, err := io.ReadAll(req.Body)
			if err != nil {
				t.Fatalf("origin body: %v", err)
			}
			if string(origin) != payload {
				t.Errorf("origin body %q want %q", origin, payload)
			}
		})
	}
}

// Test_appsecQuery_stripsHopByHopHeaders proves connection-scoped headers never reach the listener.
func Test_appsecQuery_stripsHopByHopHeaders(t *testing.T) {
	hopByHop := []string{
		"Connection", "Keep-Alive", "Proxy-Authenticate", "Proxy-Authorization",
		"Te", "Trailer", "Transfer-Encoding", "Upgrade",
	}
	capture := &forwardCaptureRoundTripper{}
	req := httptest.NewRequest(http.MethodPost, "http://localhost/", strings.NewReader("payload"))
	for _, name := range hopByHop {
		req.Header.Set(name, "probe")
	}
	req.Header.Set("Cookie", "session=keep")
	req.Header.Set("X-Forwarded-For", "1.2.3.4")
	if _, err := newForwardCaptureClient(capture).Query(withTestAddress(req), Policy{}); err != nil {
		t.Fatalf("Query() returned error: %v", err)
	}
	for _, name := range hopByHop {
		if got := capture.header.Get(name); got != "" {
			t.Errorf("hop-by-hop header %s reached AppSec with %q", name, got)
		}
	}
	if got := capture.header.Get("Cookie"); got != "session=keep" {
		t.Errorf("Cookie %q want %q", got, "session=keep")
	}
	if got := capture.header.Get("X-Forwarded-For"); got != "1.2.3.4" {
		t.Errorf("X-Forwarded-For %q want %q", got, "1.2.3.4")
	}
}

// Test_appsecQuery_forwardsHTTPVersion proves Query encodes inbound ProtoMajor/ProtoMinor
// as two ASCII digits on X-Crowdsec-Appsec-Http-Version, and omits the header when ProtoMajor is 0.
func Test_appsecQuery_forwardsHTTPVersion(t *testing.T) {
	tests := []struct {
		name       string
		protoMajor int
		protoMinor int
		want       string
	}{
		{name: "http1.1 encodes as 11", protoMajor: 1, protoMinor: 1, want: "11"},
		{name: "http2 encodes as 20", protoMajor: 2, protoMinor: 0, want: "20"},
		{name: "http3 encodes as 30", protoMajor: 3, protoMinor: 0, want: "30"},
		{name: "protoMajor 0 omits header", protoMajor: 0, protoMinor: 0, want: ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			capture := &forwardCaptureRoundTripper{}
			req := httptest.NewRequest(http.MethodGet, "http://localhost/", nil)
			req.ProtoMajor = tt.protoMajor
			req.ProtoMinor = tt.protoMinor
			if _, err := newForwardCaptureClient(capture).Query(withTestAddress(req), Policy{}); err != nil {
				t.Fatalf("Query() returned error: %v", err)
			}
			got := capture.header.Get(crowdsecAppsecHTTPVersionHeader)
			if got != tt.want {
				t.Errorf("%s %q want %q", crowdsecAppsecHTTPVersionHeader, got, tt.want)
			}
		})
	}
}

// Test_isHopByHopHeader checks the RFC 7230 section 6.1 set and that end-to-end headers pass.
func Test_isHopByHopHeader(t *testing.T) {
	tests := []struct {
		name string
		want bool
	}{
		{name: "Connection", want: true},
		{name: "keep-alive", want: true},
		{name: "Proxy-Authenticate", want: true},
		{name: "Proxy-Authorization", want: true},
		{name: "TE", want: true},
		{name: "Trailer", want: true},
		{name: "Transfer-Encoding", want: true},
		{name: "Upgrade", want: true},
		{name: "Content-Type", want: false},
		{name: "Cookie", want: false},
		{name: "Content-Length", want: false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := isHopByHopHeader(tt.name); got != tt.want {
				t.Errorf("isHopByHopHeader(%q) = %v, want %v", tt.name, got, tt.want)
			}
		})
	}
}

// Test_isMethodWithForwardableBody proves the readable-forward set stays wider than the drop set.
func Test_isMethodWithForwardableBody(t *testing.T) {
	tests := []struct {
		method      string
		wantForward bool
		wantDropSet bool
	}{
		{method: http.MethodPost, wantForward: true, wantDropSet: true},
		{method: http.MethodPut, wantForward: true, wantDropSet: true},
		{method: http.MethodPatch, wantForward: true, wantDropSet: true},
		{method: http.MethodDelete, wantForward: true, wantDropSet: false},
		{method: http.MethodGet, wantForward: false, wantDropSet: false},
		{method: http.MethodHead, wantForward: false, wantDropSet: false},
		{method: http.MethodOptions, wantForward: false, wantDropSet: false},
	}
	for _, tt := range tests {
		t.Run(tt.method, func(t *testing.T) {
			if got := isMethodWithForwardableBody(tt.method); got != tt.wantForward {
				t.Errorf("isMethodWithForwardableBody(%q) = %v, want %v", tt.method, got, tt.wantForward)
			}
			if got := isMethodWithBody(tt.method); got != tt.wantDropSet {
				t.Errorf("isMethodWithBody(%q) = %v, want %v", tt.method, got, tt.wantDropSet)
			}
		})
	}
}

func Test_appsecQuery_originFormURIUsesConstructorScheme(t *testing.T) {
	gotURI := ""
	gotHost := ""
	appsecServer := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
		gotURI = r.Header.Get(crowdsecAppsecURIHeader)
		gotHost = r.Header.Get(crowdsecAppsecHostHeader)
		rw.WriteHeader(http.StatusOK)
		_, _ = rw.Write([]byte(`{"action":"allow"}`))
	}))
	defer appsecServer.Close()
	appsecURL, _ := url.Parse(appsecServer.URL)
	httpReq := httptest.NewRequest(http.MethodGet, "/foo?q=1", nil)
	httpReq.Host = "app.example"
	httpReq.URL.Scheme = ""
	httpReq.URL.Host = ""
	httpReq.Header.Set("X-Forwarded-Proto", "https")
	_, err := newQueryClient(appsecURL, appsecServer.Client()).Query(clientrequest.New(httpReq, "1.2.3.4", net.ParseIP("1.2.3.4")), Policy{})
	if err != nil {
		t.Fatalf("Query() returned error: %v", err)
	}
	if gotURI != "https://app.example/foo?q=1" {
		t.Fatalf("X-Crowdsec-Appsec-Uri %q", gotURI)
	}
	if gotHost != "app.example" {
		t.Fatalf("X-Crowdsec-Appsec-Host %q", gotHost)
	}
}

func Test_appsecQuery_oversizedForbiddenResponseBlocks(t *testing.T) {
	appsecServer := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, _ *http.Request) {
		rw.WriteHeader(http.StatusForbidden)
		_, _ = io.WriteString(rw, strings.Repeat("x", int(appsecResponseBodyLimit)+1))
	}))
	defer appsecServer.Close()
	appsecURL, _ := url.Parse(appsecServer.URL)
	decision, err := newQueryClient(appsecURL, appsecServer.Client()).Query(buildTestRequest(), Policy{})
	if err == nil {
		t.Fatal("Query() expected error, got nil")
	}
	if decision != nil {
		t.Fatalf("Query() returned decision: %#v", decision)
	}
}
