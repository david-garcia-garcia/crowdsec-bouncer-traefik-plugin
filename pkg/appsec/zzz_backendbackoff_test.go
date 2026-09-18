package appsec

import (
	"context"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/david-garcia-garcia/traefik-middleware-utilities/backendbackoff"
	"github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pkg/configuration"
	"github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pkg/reclaim"
)

// attachTestGate puts a one-failure Gate on client and freezes jitter.
func attachTestGate(t *testing.T, client *Client) *backendbackoff.Gate {
	t.Helper()
	gate, err := backendbackoff.New(backendbackoff.Config{
		FailureRatio: 0.30,
		TripFailures: 1,
		BaseCooldown: time.Second,
		MaxCooldown:  time.Second,
		Jitter:       0,
		TTL:          time.Minute,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(gate.Close)
	client.gate = gate
	return gate
}

func TestQuery_GateSkipDoesNotHitAppSec(t *testing.T) {
	var hits int64
	server := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, _ *http.Request) {
		atomic.AddInt64(&hits, 1)
		rw.WriteHeader(http.StatusInternalServerError)
	}))
	t.Cleanup(server.Close)
	parsed, _ := url.Parse(server.URL)
	client := newQueryClient(parsed, server.Client())
	attachTestGate(t, client)

	req, _ := http.NewRequest(http.MethodGet, "http://localhost/", nil)
	if _, err := client.Query("1.2.3.4", req, Policy{FailureAction: configuration.FailureActionBan}); err == nil {
		t.Fatal("first 500 must apply FailureAction")
	}
	if atomic.LoadInt64(&hits) != 1 {
		t.Fatalf("first Query hits=%d, want 1", atomic.LoadInt64(&hits))
	}

	if _, err := client.Query("1.2.3.4", req, Policy{FailureAction: configuration.FailureActionBan}); err == nil {
		t.Fatal("denied Query must apply FailureAction")
	} else if !strings.Contains(err.Error(), "appsecQuery:skipped") {
		t.Fatalf("skip error %q", err)
	} else if strings.Contains(err.Error(), "unreachable") {
		t.Fatalf("skip must not reuse unreachable: %v", err)
	}
	if atomic.LoadInt64(&hits) != 1 {
		t.Fatalf("denied Query must not hit AppSec, hits=%d", atomic.LoadInt64(&hits))
	}
}

func TestQuery_SuccessReportRecovers(t *testing.T) {
	var hits int64
	var serveOK atomic.Bool
	server := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, _ *http.Request) {
		atomic.AddInt64(&hits, 1)
		if !serveOK.Load() {
			rw.WriteHeader(http.StatusInternalServerError)
			return
		}
		rw.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(server.Close)
	parsed, _ := url.Parse(server.URL)
	client := newQueryClient(parsed, server.Client())
	gate := attachTestGate(t, client)
	req, _ := http.NewRequest(http.MethodGet, "http://localhost/", nil)

	if _, err := client.Query("1.2.3.4", req, Policy{FailureAction: configuration.FailureActionBan}); err == nil {
		t.Fatal("first 500 expected")
	}
	now := time.Now().Add(2 * time.Second)
	gate.SetNowForTest(func() time.Time { return now })
	serveOK.Store(true)

	if _, err := client.Query("1.2.3.4", req, Policy{FailureAction: configuration.FailureActionPassthrough}); err != nil {
		t.Fatalf("HALF-OPEN success: %v", err)
	}
	if _, err := client.Query("1.2.3.4", req, Policy{FailureAction: configuration.FailureActionPassthrough}); err != nil {
		t.Fatalf("recovered Query: %v", err)
	}
	if atomic.LoadInt64(&hits) != 3 {
		t.Fatalf("hits=%d, want 3 (fail, recover, follow-up)", atomic.LoadInt64(&hits))
	}
}

func TestQuery_CloseDeniesLaterAllow(t *testing.T) {
	var hits int64
	server := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, _ *http.Request) {
		atomic.AddInt64(&hits, 1)
		rw.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(server.Close)
	parsed, _ := url.Parse(server.URL)
	client := newQueryClient(parsed, server.Client())
	attachTestGate(t, client)
	client.Close()

	req, _ := http.NewRequest(http.MethodGet, "http://localhost/", nil)
	if _, err := client.Query("1.2.3.4", req, Policy{FailureAction: configuration.FailureActionBan}); err == nil || !strings.Contains(err.Error(), "appsecQuery:skipped") {
		t.Fatalf("closed gate must skip, err %v", err)
	}
	if atomic.LoadInt64(&hits) != 0 {
		t.Fatalf("closed gate must not hit AppSec, hits=%d", atomic.LoadInt64(&hits))
	}
}

func TestQuery_DeniedPassthroughDoesNotHitAppSec(t *testing.T) {
	var hits int64
	server := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, _ *http.Request) {
		atomic.AddInt64(&hits, 1)
		rw.WriteHeader(http.StatusInternalServerError)
	}))
	t.Cleanup(server.Close)
	parsed, _ := url.Parse(server.URL)
	client := newQueryClient(parsed, server.Client())
	attachTestGate(t, client)
	req, _ := http.NewRequest(http.MethodGet, "http://localhost/", nil)
	if _, err := client.Query("1.2.3.4", req, Policy{FailureAction: configuration.FailureActionBan}); err == nil {
		t.Fatal("trip expected")
	}

	decision, err := client.Query("1.2.3.4", req, Policy{FailureAction: configuration.FailureActionPassthrough})
	if err != nil {
		t.Fatalf("denied passthrough must allow, err %v", err)
	}
	if decision == nil || decision.Action != ActionAllow {
		t.Fatalf("denied passthrough want allow, got %#v", decision)
	}
	if atomic.LoadInt64(&hits) != 1 {
		t.Fatalf("denied passthrough must not hit AppSec, hits=%d", atomic.LoadInt64(&hits))
	}
}

func TestQuery_ReadBodyReportsSuccess(t *testing.T) {
	var hits int64
	client := NewTestClient(&url.URL{Scheme: "http", Host: "appsec.example"}, &http.Client{Transport: countingFailBody{hits: &hits}}, slog.Default())
	attachTestGate(t, client)
	req, _ := http.NewRequest(http.MethodGet, "http://localhost/", nil)

	if _, err := client.Query("1.2.3.4", req, Policy{FailureAction: configuration.FailureActionBan}); err == nil || !strings.Contains(err.Error(), "appsecQuery:readBody") {
		t.Fatalf("read-body FailureAction expected, err %v", err)
	}
	if _, err := client.Query("1.2.3.4", req, Policy{FailureAction: configuration.FailureActionBan}); err == nil || !strings.Contains(err.Error(), "appsecQuery:readBody") {
		t.Fatalf("success Report must keep the Gate admitting, err %v", err)
	}
	if atomic.LoadInt64(&hits) != 2 {
		t.Fatalf("read-body success Report must not trip, hits=%d", atomic.LoadInt64(&hits))
	}
}

type countingFailBody struct {
	hits *int64
}

func (c countingFailBody) RoundTrip(req *http.Request) (*http.Response, error) {
	atomic.AddInt64(c.hits, 1)
	return &http.Response{
		StatusCode: http.StatusOK,
		Body:       failReadCloser{},
		Header:     make(http.Header),
		Request:    req,
	}, nil
}

func TestQuery_UnreadableBodyBanNeverAllows(t *testing.T) {
	var hits int64
	server := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, _ *http.Request) {
		atomic.AddInt64(&hits, 1)
		rw.WriteHeader(http.StatusInternalServerError)
	}))
	t.Cleanup(server.Close)
	parsed, _ := url.Parse(server.URL)
	client := newQueryClient(parsed, server.Client())
	attachTestGate(t, client)
	req, _ := http.NewRequest(http.MethodGet, "http://localhost/", nil)
	if _, err := client.Query("1.2.3.4", req, Policy{FailureAction: configuration.FailureActionBan}); err == nil {
		t.Fatal("trip expected")
	}

	done := make(chan struct{})
	t.Cleanup(func() { close(done) })
	_, err := client.Query("1.2.3.4", newStreamingRequest(done), Policy{FailureAction: configuration.FailureActionBan})
	if err == nil {
		t.Fatal("unreadable-body ban must drop")
	}
	if !strings.Contains(err.Error(), "unreadableBody") {
		t.Fatalf("unreadable-body path must not Allow, got %v", err)
	}
	if strings.Contains(err.Error(), "appsecQuery:skipped") {
		t.Fatalf("unreadable-body ban must not call Allow: %v", err)
	}
	if atomic.LoadInt64(&hits) != 1 {
		t.Fatalf("unreadable-body ban must not hit AppSec, hits=%d", atomic.LoadInt64(&hits))
	}
}

func TestOpen_BackoffKnobDoesNotSplitClient(t *testing.T) {
	reclaim.ResetForTestWith(0)
	t.Cleanup(func() { reclaim.ResetForTest() })

	ctx := context.Background()
	firstCfg := testAppsecConfig("127.0.0.1:1")
	first, err := Open(ctx, firstCfg, slog.Default(), "first", "test")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(first.Close)
	if first.gate == nil {
		t.Fatal("AppSec Client must own a Gate")
	}
	secondCfg := testAppsecConfig("127.0.0.1:1")
	secondCfg.BackendBackoffTripFailures = 9
	second, err := Open(ctx, secondCfg, slog.Default(), "second", "test")
	if err != nil {
		t.Fatal(err)
	}
	if first != second {
		t.Fatal("backoff knobs must not split the AppSec Client")
	}
}

func TestQuery_UnreadableBodyPassthroughAllowsGET(t *testing.T) {
	var hits int64
	server := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
		atomic.AddInt64(&hits, 1)
		if req.Method != http.MethodGet {
			t.Errorf("passthrough unreadable body must GET, got %s", req.Method)
		}
		rw.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(server.Close)
	parsed, _ := url.Parse(server.URL)
	client := newQueryClient(parsed, server.Client())
	attachTestGate(t, client)
	done := make(chan struct{})
	t.Cleanup(func() { close(done) })
	if _, err := client.Query("1.2.3.4", newStreamingRequest(done), Policy{FailureAction: configuration.FailureActionPassthrough}); err != nil {
		t.Fatalf("headers-only GET: %v", err)
	}
	if atomic.LoadInt64(&hits) != 1 {
		t.Fatalf("passthrough unreadable body must Allow the GET, hits=%d", atomic.LoadInt64(&hits))
	}
}
