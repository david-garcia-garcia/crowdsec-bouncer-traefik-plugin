package appsec

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sync/atomic"
	"testing"
	"time"

	"github.com/maxlerebourg/crowdsec-bouncer-traefik-plugin/pkg/configuration"
	"github.com/maxlerebourg/crowdsec-bouncer-traefik-plugin/pkg/health"
	logger "github.com/maxlerebourg/crowdsec-bouncer-traefik-plugin/pkg/logger"
)

func Test_appsecQuery_backoffSkipsHTTP(t *testing.T) {
	var hits int32
	appsecServer := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, _ *http.Request) {
		atomic.AddInt32(&hits, 1)
		rw.WriteHeader(http.StatusInternalServerError)
	}))
	defer appsecServer.Close()
	appsecURL, _ := url.Parse(appsecServer.URL)
	client := newQueryClient(appsecURL, appsecServer.Client())
	client.failureTracker = health.New(time.Minute, 0, 1, logger.New("ERROR", ""))
	req := httptest.NewRequest(http.MethodGet, "http://localhost/", nil)

	if _, err := client.Query("1.2.3.4", req, Policy{FailureAction: configuration.FailureActionBan}); err == nil {
		t.Fatal("first 500 expected an error")
	}
	if atomic.LoadInt32(&hits) != 1 {
		t.Fatalf("first query hits=%d want 1", hits)
	}
	if _, err := client.Query("1.2.3.4", req, Policy{FailureAction: configuration.FailureActionBan}); err == nil {
		t.Fatal("backoff query expected an error")
	}
	if atomic.LoadInt32(&hits) != 1 {
		t.Fatalf("backoff must skip HTTP, hits=%d", hits)
	}
}

func Test_appsecQuery_unreadableBodyDoesNotRecordFailure(t *testing.T) {
	var hits int32
	appsecServer := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, _ *http.Request) {
		atomic.AddInt32(&hits, 1)
		rw.WriteHeader(http.StatusOK)
	}))
	defer appsecServer.Close()
	appsecURL, _ := url.Parse(appsecServer.URL)
	client := newQueryClient(appsecURL, appsecServer.Client())
	tracker := health.New(time.Minute, 0, 1, logger.New("ERROR", ""))
	client.failureTracker = tracker
	done := make(chan struct{})
	defer close(done)

	_, err := client.Query("1.2.3.4", newStreamingRequest(done), Policy{FailureAction: configuration.FailureActionBan})
	if err == nil {
		t.Fatal("unreadable body with ban expected an error")
	}
	if tracker.IsUnhealthy() {
		t.Fatal("unreadable body must not trip the Tracker")
	}
	if atomic.LoadInt32(&hits) != 0 {
		t.Fatalf("unreadable body ban must not call AppSec, hits=%d", hits)
	}
}

func Test_appsecQuery_backoffPassthrough(t *testing.T) {
	var hits int32
	appsecServer := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, _ *http.Request) {
		atomic.AddInt32(&hits, 1)
		rw.WriteHeader(http.StatusBadGateway)
	}))
	defer appsecServer.Close()
	appsecURL, _ := url.Parse(appsecServer.URL)
	client := newQueryClient(appsecURL, appsecServer.Client())
	client.failureTracker = health.New(time.Minute, 0, 1, logger.New("ERROR", ""))
	req := httptest.NewRequest(http.MethodGet, "http://localhost/", nil)

	_, err := client.Query("1.2.3.4", req, Policy{FailureAction: configuration.FailureActionPassthrough})
	if err != nil {
		t.Fatalf("first unreachable passthrough: %v", err)
	}
	decision, err := client.Query("1.2.3.4", req, Policy{FailureAction: configuration.FailureActionPassthrough})
	if err != nil {
		t.Fatalf("backoff passthrough: %v", err)
	}
	if decision == nil || decision.Action != ActionAllow {
		t.Fatalf("backoff passthrough want allow, got %#v", decision)
	}
	if atomic.LoadInt32(&hits) != 1 {
		t.Fatalf("backoff must skip HTTP, hits=%d", hits)
	}
}

func TestIdentityHex_BackoffKnobsSplitAppsecIdentity(t *testing.T) {
	a := configuration.New()
	b := configuration.New()
	a.CrowdsecAppsecHost = "appsec:7422"
	b.CrowdsecAppsecHost = "appsec:7422"
	b.AppsecFailureBackoffBucketThreshold = 9
	if IdentityHex(a) == IdentityHex(b) {
		t.Fatal("AppSec identity must include backoff knobs")
	}
}

func Test_appsecQuery_backoffCaptcha(t *testing.T) {
	appsecServer := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, _ *http.Request) {
		rw.WriteHeader(http.StatusInternalServerError)
	}))
	defer appsecServer.Close()
	appsecURL, _ := url.Parse(appsecServer.URL)
	client := newQueryClient(appsecURL, appsecServer.Client())
	client.failureTracker = health.New(time.Minute, 0, 1, logger.New("ERROR", ""))
	req := httptest.NewRequest(http.MethodGet, "http://localhost/", nil)
	_, _ = client.Query("1.2.3.4", req, Policy{FailureAction: configuration.FailureActionBan})
	_, err := client.Query("1.2.3.4", req, Policy{FailureAction: configuration.FailureActionCaptcha})
	if !errors.Is(err, ErrFailureCaptcha) {
		t.Fatalf("backoff captcha want ErrFailureCaptcha, got %v", err)
	}
}
