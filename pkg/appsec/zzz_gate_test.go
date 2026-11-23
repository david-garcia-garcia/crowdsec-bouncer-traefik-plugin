package appsec

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pkg/admission"
	"github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pkg/configuration"
	logger "github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pkg/logger"
)

func gatedAppsecClient(t *testing.T, host string, period int64) *Client {
	t.Helper()
	cfg := testAppsecConfig(host)
	cfg.AppsecUnhealthyBackOffPeriodSecs = period
	client, err := New(cfg, logger.New("ERROR", ""), "test", "n", "k")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(client.Close)
	return client
}

func TestNew_defaultBackoffBuildsGate(t *testing.T) {
	cfg := configuration.New()
	cfg.AppsecEnabled = true
	cfg.AppsecHost = "127.0.0.1:1"
	cfg.AppsecScheme = "http"
	cfg.AppsecTLSInsecureVerify = true
	client, err := New(cfg, logger.New("ERROR", ""), "test", "n", "k")
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	if cfg.AppsecUnhealthyBackOffPeriodSecs != 10 {
		t.Fatalf("period=%d want 10", cfg.AppsecUnhealthyBackOffPeriodSecs)
	}
	if client.GateForTest() == nil {
		t.Fatal("default AppSec backoff 10 must build a gate")
	}
}

func TestNew_zeroBackoffDisablesGate(t *testing.T) {
	client := gatedAppsecClient(t, "127.0.0.1:1", 0)
	if client.GateForTest() != nil {
		t.Fatal("appsecUnhealthyBackOffPeriodSecs 0 must not build a gate")
	}
}

func TestQuery_gateSkipDoesNotCallAppSecOrFailureAction(t *testing.T) {
	hits := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		hits++
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()
	u, _ := url.Parse(srv.URL)
	client := gatedAppsecClient(t, u.Host, 30)

	for i := range admission.TripFailures {
		_, err := client.Query(buildTestRequest(), Policy{FailureAction: configuration.FailureActionBan}, nil)
		if err == nil {
			t.Fatalf("admitted 500 #%d must apply FailureAction", i+1)
		}
		if errors.Is(err, ErrGateSkip) {
			t.Fatalf("500 #%d is an admitted miss, not a gate skip", i+1)
		}
	}

	_, skipErr := client.Query(buildTestRequest(), Policy{FailureAction: configuration.FailureActionBan}, nil)
	if !errors.Is(skipErr, ErrGateSkip) {
		t.Fatalf("tripped gate want ErrGateSkip, got %v", skipErr)
	}
	if hits != admission.TripFailures {
		t.Fatalf("AppSec hits=%d want %d", hits, admission.TripFailures)
	}
}

func TestQuery_admittedMissStillUsesFailureAction(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()
	u, _ := url.Parse(srv.URL)
	client := gatedAppsecClient(t, u.Host, 30)

	_, err := client.Query(buildTestRequest(), Policy{FailureAction: configuration.FailureActionPassthrough}, nil)
	if err != nil {
		t.Fatalf("admitted 500 passthrough: %v", err)
	}
	_, banErr := client.Query(buildTestRequest(), Policy{FailureAction: configuration.FailureActionBan}, nil)
	if banErr == nil || errors.Is(banErr, ErrGateSkip) {
		t.Fatalf("admitted miss must use FailureAction, got %v", banErr)
	}
}

func Test_appsecQuery_hopCancelDoesNotTripGate(t *testing.T) {
	// More canceled hops than the failure budget: none of them may count as an AppSec failure.
	var mu sync.Mutex
	hits := 0
	block := true
	started := make(chan struct{}, 1)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		hits++
		blocking := block
		mu.Unlock()
		if blocking {
			started <- struct{}{}
			<-r.Context().Done()
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()
	u, _ := url.Parse(srv.URL)
	cfg := testAppsecConfig(u.Host)
	cfg.AppsecHTTPTimeoutSeconds = 30
	cfg.AppsecUnhealthyBackOffPeriodSecs = 30
	client, err := New(cfg, logger.New("ERROR", ""), "test", "n", "k")
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	for i := range admission.TripFailures + 1 {
		ctx, cancel := context.WithCancel(context.Background())
		httpReq := httptest.NewRequest(http.MethodGet, "http://localhost/", nil).WithContext(ctx)
		done := make(chan error, 1)
		go func() {
			_, hopErr := client.Query(withTestAddress(httpReq), Policy{FailureAction: configuration.FailureActionBan}, nil)
			done <- hopErr
		}()
		<-started
		cancel()
		if hopErr := <-done; !errors.Is(hopErr, ErrClientDisconnected) {
			t.Fatalf("hop cancel #%d want ErrClientDisconnected, got %v", i+1, hopErr)
		}
	}
	mu.Lock()
	block = false
	mu.Unlock()
	_, laterErr := client.Query(buildTestRequest(), Policy{FailureAction: configuration.FailureActionBan}, nil)
	if laterErr != nil {
		t.Fatalf("later hop after cancels must reach AppSec, got %v", laterErr)
	}
	mu.Lock()
	defer mu.Unlock()
	if want := admission.TripFailures + 2; hits != want {
		t.Fatalf("AppSec hits=%d want %d", hits, want)
	}
}

func TestQuery_backoffLogsStartedAndEndedOnce(t *testing.T) {
	healthy := false
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		if healthy {
			w.WriteHeader(http.StatusOK)
			return
		}
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()
	u, _ := url.Parse(srv.URL)
	cfg := testAppsecConfig(u.Host)
	cfg.AppsecUnhealthyBackOffPeriodSecs = 10
	var logs bytes.Buffer
	client, err := New(cfg, slog.New(slog.NewTextHandler(&logs, &slog.HandlerOptions{Level: slog.LevelDebug})), "test", "n", "k")
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	now := time.Now()
	client.GateForTest().Inner().SetNowForTest(func() time.Time { return now })
	pol := Policy{FailureAction: configuration.FailureActionPassthrough}

	for range admission.TripFailures {
		_, _ = client.Query(buildTestRequest(), pol, nil)
	}
	for i := range 3 {
		if _, skipErr := client.Query(buildTestRequest(), pol, nil); !errors.Is(skipErr, ErrGateSkip) {
			t.Fatalf("request %d want ErrGateSkip, got %v", i, skipErr)
		}
	}
	healthy = true
	now = now.Add(11 * time.Second)
	if _, probeErr := client.Query(buildTestRequest(), pol, nil); probeErr != nil {
		t.Fatalf("probe: %v", probeErr)
	}
	_, _ = client.Query(buildTestRequest(), pol, nil)

	if got := strings.Count(logs.String(), MsgBackoffStarted); got != 1 {
		t.Fatalf("%q lines=%d want 1\n%s", MsgBackoffStarted, got, logs.String())
	}
	if got := strings.Count(logs.String(), MsgBackoffEnded); got != 1 {
		t.Fatalf("%q lines=%d want 1\n%s", MsgBackoffEnded, got, logs.String())
	}
}

// trippedAppsecClient returns a gated client whose AppSec answered 500 TripFailures times, so the gate is backing off.
// Later calls get status from next.
func trippedAppsecClient(t *testing.T, next *int) (*Client, *int) {
	t.Helper()
	hits := new(int)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		*hits++
		if *hits <= admission.TripFailures {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		w.WriteHeader(*next)
	}))
	t.Cleanup(srv.Close)
	u, _ := url.Parse(srv.URL)
	client := gatedAppsecClient(t, u.Host, 30)
	for range admission.TripFailures {
		_, _ = client.Query(buildTestRequest(), Policy{FailureAction: configuration.FailureActionPassthrough}, nil)
	}
	if _, err := client.Query(buildTestRequest(), Policy{FailureAction: configuration.FailureActionBan}, nil); !errors.Is(err, ErrGateSkip) {
		t.Fatalf("gate must be backing off, got %v", err)
	}
	return client, hits
}

// TestQuery_bodyReadTimeoutWhileBackingOffIsNotAGateSkip proves a stalled body without Content-Length
// is ErrBodyReadTimeout even while AppSec is backing off: the read happens before admission, and the
// deadline blocks the request whatever the gate says.
func TestQuery_bodyReadTimeoutWhileBackingOffIsNotAGateSkip(t *testing.T) {
	status := http.StatusOK
	client, hits := trippedAppsecClient(t, &status)
	client.bodyReadTimeout = 50 * time.Millisecond
	hitsBefore := *hits
	req := newStreamingTestRequest(http.MethodPost)
	defer func() { _ = req.Body.Close() }()
	_, err := client.Query(withTestAddress(req), Policy{FailureAction: configuration.FailureActionPassthrough}, nil)
	if !errors.Is(err, ErrBodyReadTimeout) {
		t.Fatalf("stalled body while backing off want ErrBodyReadTimeout, got %v", err)
	}
	if *hits != hitsBefore {
		t.Fatalf("AppSec called %d times for a stalled body, want 0", *hits-hitsBefore)
	}
}

// TestQuery_admissionErrorUsesFailureAction proves a gate that cannot answer (closed on reclaim) applies
// the failure action like any other AppSec outage, and never bans under passthrough.
func TestQuery_admissionErrorUsesFailureAction(t *testing.T) {
	hits := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		hits++
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()
	u, _ := url.Parse(srv.URL)
	client := gatedAppsecClient(t, u.Host, 30)
	client.GateForTest().Close()

	decision, err := client.Query(buildTestRequest(), Policy{FailureAction: configuration.FailureActionPassthrough}, nil)
	if err != nil || decision == nil || decision.Action != ActionAllow {
		t.Fatalf("passthrough want allow, got %+v %v", decision, err)
	}
	if _, err := client.Query(buildTestRequest(), Policy{FailureAction: configuration.FailureActionCaptcha}, nil); !errors.Is(err, ErrFailureCaptcha) {
		t.Fatalf("captcha want ErrFailureCaptcha, got %v", err)
	}
	if _, err := client.Query(buildTestRequest(), Policy{FailureAction: configuration.FailureActionBan}, nil); err == nil || errors.Is(err, ErrGateSkip) {
		t.Fatalf("ban want a failure error, got %v", err)
	}
	if hits != 0 {
		t.Fatalf("AppSec hits=%d want 0", hits)
	}
}

// TestQuery_bodyReadErrorDoesNotHoldProbe proves a client body error after the cooldown does not take
// the half-open probe: the body is read before admission, so the next request is the probe.
func TestQuery_bodyReadErrorDoesNotHoldProbe(t *testing.T) {
	status := http.StatusOK
	client, hits := trippedAppsecClient(t, &status)
	later := time.Now().Add(31 * time.Second)
	client.GateForTest().Inner().SetNowForTest(func() time.Time { return later })

	if _, err := client.Query(withTestAddress(newReadablePostWithFailingBody(errors.New("i/o timeout"))), Policy{FailureAction: configuration.FailureActionBan}, nil); err == nil || errors.Is(err, ErrGateSkip) {
		t.Fatalf("body read error want a client error, got %v", err)
	}
	decision, err := client.Query(buildTestRequest(), Policy{FailureAction: configuration.FailureActionBan}, nil)
	if err != nil || decision == nil || decision.Action != ActionAllow {
		t.Fatalf("next request must be the probe and pass, got %+v %v", decision, err)
	}
	if *hits != admission.TripFailures+1 {
		t.Fatalf("AppSec hits=%d want %d", *hits, admission.TripFailures+1)
	}
	if client.GateForTest().BackingOff() {
		t.Fatal("a successful probe must end the backoff")
	}
}
