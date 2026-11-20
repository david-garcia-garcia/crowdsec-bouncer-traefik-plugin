package modsecurity

import (
	"bytes"
	"context"
	"errors"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pkg/admission"
	"github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pkg/configuration"
	"github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pkg/logger"
	"github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pkg/wafhop"
)

func newTestClient(t *testing.T, cfg *configuration.Config) *Client {
	t.Helper()
	client, err := New(cfg, slog.Default(), "test", "n", "k")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(client.Close)
	return client
}

func getRequest(target string) *http.Request {
	return httptest.NewRequest(http.MethodGet, target, nil)
}

// mustAllow fails unless Inspect answered allow (nil response, nil error).
func mustAllow(t *testing.T, client *Client, req *http.Request, action string) {
	t.Helper()
	resp, err := client.Inspect(req, action)
	if err != nil || resp != nil {
		t.Fatalf("want allow, got resp=%v err=%v", resp, err)
	}
}

// mustBlock fails unless Inspect answered a block, and returns the client response WriteBlock wrote.
func mustBlock(t *testing.T, client *Client, req *http.Request) *httptest.ResponseRecorder {
	t.Helper()
	resp, err := client.Inspect(req, configuration.FailureActionPassthrough)
	if err != nil || resp == nil {
		t.Fatalf("want block, got resp=%v err=%v", resp, err)
	}
	rw := httptest.NewRecorder()
	rw.Header().Set("X-Remediation", "ban:modsec")
	WriteBlock(rw, resp)
	return rw
}

// mustFail fails unless Inspect answered nil with an error matching want.
func mustFail(t *testing.T, client *Client, req *http.Request, action string, want error) {
	t.Helper()
	resp, err := client.Inspect(req, action)
	if resp != nil || !errors.Is(err, want) {
		t.Fatalf("want %v, got resp=%v err=%v", want, resp, err)
	}
}

func TestInspect_cleanGETAllows(t *testing.T) {
	sidecar := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Host != "example.com:443" {
			t.Errorf("Host=%q want example.com:443", r.Host)
		}
		if r.Header.Get("X-Real-IP") != "" {
			t.Error("plugin must not set X-Real-IP")
		}
		_, _ = w.Write([]byte("ok-body"))
	}))
	defer sidecar.Close()
	client := newTestClient(t, testModsecConfig(sidecar.URL))
	req := getRequest("http://example.com:443/")
	req.Host = "example.com:443"
	mustAllow(t, client, req, configuration.FailureActionBan)
}

func TestWriteBlock_copiesEndToEndHeadersAndBody(t *testing.T) {
	sidecar := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Connection", "close")
		w.Header().Set("Server", "crs")
		w.Header().Set("X-Block", "yes")
		http.Error(w, "blocked-by-crs", http.StatusForbidden)
	}))
	defer sidecar.Close()
	client := newTestClient(t, testModsecConfig(sidecar.URL))
	rw := mustBlock(t, client, getRequest("http://example.com/?test=../etc"))
	if rw.Code != http.StatusForbidden {
		t.Fatalf("status=%d want 403", rw.Code)
	}
	if rw.Header().Get("Connection") == "close" || rw.Header().Get("Server") == "crs" {
		t.Fatalf("hop-by-hop and Server must not be copied, headers=%v", rw.Header())
	}
	if rw.Header().Get("X-Block") != "yes" {
		t.Fatal("application header must be copied")
	}
	if rw.Header().Get("X-Remediation") != "ban:modsec" {
		t.Fatal("a header the bouncer set before WriteBlock must survive")
	}
	if !strings.Contains(rw.Body.String(), "blocked-by-crs") {
		t.Fatalf("body=%q must be the sidecar page", rw.Body.String())
	}
}

func TestInspect_sidecar3xxIsBlockNotFollowed(t *testing.T) {
	followed := 0
	sidecar := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/next" {
			followed++
			return
		}
		http.Redirect(w, r, "/next", http.StatusFound)
	}))
	defer sidecar.Close()
	client := newTestClient(t, testModsecConfig(sidecar.URL))
	if rw := mustBlock(t, client, getRequest("http://example.com/")); rw.Code != http.StatusFound {
		t.Fatalf("status=%d want 302", rw.Code)
	}
	if followed != 0 {
		t.Fatal("plugin must not follow sidecar redirect")
	}
}

func TestInspect_sidecar5xxIsUnavailable(t *testing.T) {
	sidecar := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "sidecar-5xx-marker", http.StatusServiceUnavailable)
	}))
	defer sidecar.Close()
	client := newTestClient(t, testModsecConfig(sidecar.URL))
	mustFail(t, client, getRequest("http://example.com/"), configuration.FailureActionPassthrough, ErrUnavailable)
}

func TestInspect_sidecarTransportErrorIsUnavailable(t *testing.T) {
	client := newTestClient(t, testModsecConfig("http://127.0.0.1:1"))
	mustFail(t, client, getRequest("http://example.com/"), configuration.FailureActionPassthrough, ErrUnavailable)
}

// An inbound cancel during the sidecar call is the shared client-disconnected outcome.
func TestInspect_inboundCancelIsClientDisconnected(t *testing.T) {
	started := make(chan struct{})
	sidecar := httptest.NewServer(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		close(started)
		<-r.Context().Done()
	}))
	defer sidecar.Close()
	cfg := testModsecConfig(sidecar.URL)
	cfg.ModsecHTTPTimeoutSeconds = 30
	client := newTestClient(t, cfg)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		_, err := client.Inspect(getRequest("http://example.com/").WithContext(ctx), configuration.FailureActionBan)
		done <- err
	}()
	<-started
	cancel()
	if err := <-done; !errors.Is(err, wafhop.ErrClientDisconnected) {
		t.Fatalf("err=%v want wafhop.ErrClientDisconnected", err)
	}
}

func TestInspect_gateSkipsSidecarAfterTripAndLogsOnce(t *testing.T) {
	sidecarHits := 0
	sidecar := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		sidecarHits++
		http.Error(w, "down", http.StatusInternalServerError)
	}))
	defer sidecar.Close()
	cfg := testModsecConfig(sidecar.URL)
	cfg.ModsecUnhealthyBackOffPeriodSecs = 30
	logger.ResetDebounceForTest()
	var logs bytes.Buffer
	client, err := New(cfg, slog.New(slog.NewTextHandler(&logs, &slog.HandlerOptions{Level: slog.LevelDebug})), "test", "n", "k")
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	for range admission.TripFailures {
		mustFail(t, client, getRequest("http://example.com/"), configuration.FailureActionBan, ErrUnavailable)
	}
	for range 3 {
		mustFail(t, client, getRequest("http://example.com/"), configuration.FailureActionBan, ErrGateSkip)
	}
	if sidecarHits != admission.TripFailures {
		t.Fatalf("sidecar hits=%d want %d", sidecarHits, admission.TripFailures)
	}
	if got := strings.Count(logs.String(), MsgBackoffStarted); got != 1 {
		t.Fatalf("%q lines=%d want 1 for three skipped requests\n%s", MsgBackoffStarted, got, logs.String())
	}
	if got := strings.Count(logs.String(), MsgUnavailable); got != 1 {
		t.Fatalf("%q lines=%d want 1 (debounced)\n%s", MsgUnavailable, got, logs.String())
	}
}

// More canceled requests than the failure budget: none of them may count as a sidecar failure.
func TestInspect_inboundCancelDoesNotTripGate(t *testing.T) {
	var mu sync.Mutex
	hits := 0
	block := true
	started := make(chan struct{}, 1)
	sidecar := httptest.NewServer(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		mu.Lock()
		hits++
		blocking := block
		mu.Unlock()
		if blocking {
			started <- struct{}{}
			<-r.Context().Done()
		}
	}))
	defer sidecar.Close()
	cfg := testModsecConfig(sidecar.URL)
	cfg.ModsecHTTPTimeoutSeconds = 30
	cfg.ModsecUnhealthyBackOffPeriodSecs = 30
	client := newTestClient(t, cfg)
	for i := range admission.TripFailures + 1 {
		ctx, cancel := context.WithCancel(context.Background())
		done := make(chan error, 1)
		go func() {
			_, err := client.Inspect(getRequest("http://example.com/").WithContext(ctx), configuration.FailureActionBan)
			done <- err
		}()
		<-started
		cancel()
		if err := <-done; !errors.Is(err, wafhop.ErrClientDisconnected) {
			t.Fatalf("cancel #%d err=%v want wafhop.ErrClientDisconnected", i+1, err)
		}
	}
	mu.Lock()
	block = false
	mu.Unlock()
	mustAllow(t, client, getRequest("http://example.com/"), configuration.FailureActionBan)
	mu.Lock()
	defer mu.Unlock()
	if want := admission.TripFailures + 2; hits != want {
		t.Fatalf("sidecar hits=%d want %d", hits, want)
	}
}

// A GET with a body is inspected like a POST: CRS rules 920170/920171 decide, not the plugin.
func TestInspect_getWithBodyReachesSidecar(t *testing.T) {
	var gotBody string
	var gotLength int64
	sidecar := httptest.NewServer(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		gotBody, gotLength = string(body), r.ContentLength
	}))
	defer sidecar.Close()
	client := newTestClient(t, testModsecConfig(sidecar.URL))
	mustAllow(t, client, httptest.NewRequest(http.MethodGet, "http://example.com/", strings.NewReader("x")), configuration.FailureActionBan)
	if gotBody != "x" || gotLength != 1 {
		t.Fatalf("sidecar body=%q length=%d want x and 1", gotBody, gotLength)
	}
}

func TestInspect_doesNotAppendRemoteAddrToXFF(t *testing.T) {
	var gotXFF string
	sidecar := httptest.NewServer(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		gotXFF = r.Header.Get("X-Forwarded-For")
	}))
	defer sidecar.Close()
	client := newTestClient(t, testModsecConfig(sidecar.URL))
	req := getRequest("http://example.com/")
	req.Header.Set("X-Forwarded-For", "203.0.113.9")
	req.RemoteAddr = "192.0.2.1:1234"
	mustAllow(t, client, req, configuration.FailureActionPassthrough)
	if gotXFF != "203.0.113.9" {
		t.Fatalf("XFF=%q; plugin must not append RemoteAddr", gotXFF)
	}
}

func TestInspect_bodyOverLimitIsTooLargeWithoutSidecar(t *testing.T) {
	sidecarHits := 0
	sidecar := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		sidecarHits++
	}))
	defer sidecar.Close()
	cfg := testModsecConfig(sidecar.URL)
	cfg.ModsecBodyLimit = 4
	client := newTestClient(t, cfg)
	mustAllow(t, client, httptest.NewRequest(http.MethodPost, "http://example.com/", strings.NewReader("1234")), configuration.FailureActionBan)
	mustFail(t, client, httptest.NewRequest(http.MethodPost, "http://example.com/", strings.NewReader("12345")), configuration.FailureActionBan, ErrBodyTooLarge)
	if sidecarHits != 1 {
		t.Fatalf("sidecar hits=%d want 1 (only the body at the limit)", sidecarHits)
	}
}

func TestInspect_restoresBodyForNext(t *testing.T) {
	sidecar := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	defer sidecar.Close()
	client := newTestClient(t, testModsecConfig(sidecar.URL))
	req := httptest.NewRequest(http.MethodPost, "http://example.com/", strings.NewReader("payload"))
	mustAllow(t, client, req, configuration.FailureActionPassthrough)
	got, _ := io.ReadAll(req.Body)
	if string(got) != "payload" {
		t.Fatalf("restored body=%q want payload", got)
	}
}

// A streamed HTTP/2 body is never buffered (gRPC would hang). A POST cannot be inspected, so a
// non-passthrough failure action makes it unavailable; passthrough and a GET are inspected on headers alone.
func TestInspect_unreadableBodyFollowsAppsecRule(t *testing.T) {
	sidecarBodies := []string{}
	sidecar := httptest.NewServer(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		got, _ := io.ReadAll(r.Body)
		sidecarBodies = append(sidecarBodies, string(got))
	}))
	defer sidecar.Close()
	client := newTestClient(t, testModsecConfig(sidecar.URL))
	streamed := func(method string) *http.Request {
		req := httptest.NewRequest(method, "http://example.com/", nil)
		req.ProtoMajor = 2
		req.ContentLength = -1
		req.Body = io.NopCloser(&blockingReader{})
		return req
	}
	mustFail(t, client, streamed(http.MethodPost), configuration.FailureActionBan, ErrUnavailable)
	mustFail(t, client, streamed(http.MethodPost), configuration.FailureActionCaptcha, ErrUnavailable)
	mustAllow(t, client, streamed(http.MethodPost), configuration.FailureActionPassthrough)
	mustAllow(t, client, streamed(http.MethodGet), configuration.FailureActionBan)
	if len(sidecarBodies) != 2 || sidecarBodies[0] != "" || sidecarBodies[1] != "" {
		t.Fatalf("sidecar must get headers only, bodies=%q", sidecarBodies)
	}
}

// A client that resets mid-upload is the shared client-disconnected outcome, not a sidecar failure.
func TestInspect_clientGoneMidBodyIsClientDisconnected(t *testing.T) {
	client := newTestClient(t, testModsecConfig("http://127.0.0.1:1"))
	req := httptest.NewRequest(http.MethodPost, "http://example.com/", nil)
	req.Body = io.NopCloser(io.MultiReader(strings.NewReader("part"), &errReader{err: io.ErrUnexpectedEOF}))
	mustFail(t, client, req, configuration.FailureActionBan, wafhop.ErrClientDisconnected)
}

// The sidecar copy carries no hop-by-hop header, so an HTTPS sidecar speaking HTTP/2 accepts a WebSocket handshake.
func TestInspect_sidecarCopyOmitsHopByHop(t *testing.T) {
	var seen http.Header
	sidecar := httptest.NewServer(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		seen = r.Header.Clone()
	}))
	defer sidecar.Close()
	client := newTestClient(t, testModsecConfig(sidecar.URL))
	req := getRequest("http://example.com/ws")
	req.Header.Set("Connection", "Upgrade")
	req.Header.Set("Upgrade", "websocket")
	req.Header.Set("Sec-WebSocket-Key", "dGhlIHNhbXBsZSBub25jZQ==")
	mustAllow(t, client, req, configuration.FailureActionBan)
	if seen.Get("Upgrade") != "" || seen.Get("Sec-WebSocket-Key") == "" {
		t.Fatalf("sidecar headers=%v", seen)
	}
	if req.Header.Get("Upgrade") != "websocket" {
		t.Fatal("the inbound request keeps its Upgrade header for next")
	}
}

type blockingReader struct{}

func (*blockingReader) Read([]byte) (int, error) {
	select {}
}

type errReader struct{ err error }

func (e *errReader) Read([]byte) (int, error) { return 0, e.err }

// TestInspect_unreadableBodyWhileBackingOffIsGateSkip proves a streamed body is a gate skip, not the
// failure action, while the sidecar is backing off: the same rule as AppSec.
func TestInspect_unreadableBodyWhileBackingOffIsGateSkip(t *testing.T) {
	sidecar := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "down", http.StatusServiceUnavailable)
	}))
	defer sidecar.Close()
	cfg := testModsecConfig(sidecar.URL)
	cfg.ModsecUnhealthyBackOffPeriodSecs = 30
	client := newTestClient(t, cfg)
	for range admission.TripFailures {
		mustFail(t, client, getRequest("http://example.com/"), configuration.FailureActionBan, ErrUnavailable)
	}
	mustFail(t, client, getRequest("http://example.com/"), configuration.FailureActionBan, ErrGateSkip)
	streamed := httptest.NewRequest(http.MethodPost, "http://example.com/", nil)
	streamed.ProtoMajor = 2
	streamed.ContentLength = -1
	streamed.Body = io.NopCloser(&blockingReader{})
	mustFail(t, client, streamed, configuration.FailureActionBan, ErrGateSkip)
}

// TestInspect_hangHonorsModsecTimeout mirrors TestQuery_HangHonorsAppsecOverride: a sidecar that never
// answers is ErrUnavailable after modsecHttpTimeoutSeconds, not after a default timeout.
func TestInspect_hangHonorsModsecTimeout(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = listener.Close() })
	cfg := testModsecConfig("http://" + listener.Addr().String())
	cfg.ModsecHTTPTimeoutSeconds = 1
	client := newTestClient(t, cfg)
	started := time.Now()
	mustFail(t, client, getRequest("http://example.com/"), configuration.FailureActionPassthrough, ErrUnavailable)
	if elapsed := time.Since(started); elapsed >= 4*time.Second {
		t.Fatalf("Inspect took %v, want about the 1s timeout", elapsed)
	}
}
