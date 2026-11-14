package bouncer

import (
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pkg/appsec"
	"github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pkg/configuration"
	"github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pkg/httprule"
	"github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pkg/lapi"
	"github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pkg/logger"
)

// neverEndingBody is a client stream that sends nothing until Close (the AppSec deadline fallback).
type neverEndingBody struct {
	closed    chan struct{}
	closeOnce sync.Once
}

// newNeverEndingBody returns an open neverEndingBody.
func newNeverEndingBody() *neverEndingBody {
	return &neverEndingBody{closed: make(chan struct{})}
}

// Read blocks until Close, then reports the body closed by the handler.
func (b *neverEndingBody) Read(_ []byte) (int, error) {
	<-b.closed
	return 0, io.ErrClosedPipe
}

// Close unblocks Read. Safe from the deadline timer and from test cleanup.
func (b *neverEndingBody) Close() error {
	b.closeOnce.Do(func() { close(b.closed) })
	return nil
}

// newStreamingUploadRequest is an HTTP/2 POST to /stream whose body never ends and has no Content-Length.
func newStreamingUploadRequest(t *testing.T) *http.Request {
	t.Helper()
	body := newNeverEndingBody()
	t.Cleanup(func() { _ = body.Close() })
	req := httptest.NewRequest(http.MethodPost, "http://example.com/stream", body)
	req.ProtoMajor = 2
	req.ContentLength = -1
	return req
}

// newBodyTimeoutBouncer binds an AppSec Client (1 s body read deadline) that counts listener calls.
func newBodyTimeoutBouncer(t *testing.T, failureAction string, log *slog.Logger) (*Bouncer, *lapi.Client, *bool, *int32) {
	t.Helper()
	var appsecHits int32
	appsecServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		atomic.AddInt32(&appsecHits, 1)
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(appsecServer.Close)
	appsecURL, err := url.Parse(appsecServer.URL)
	if err != nil {
		t.Fatal(err)
	}
	cfg := configuration.New()
	cfg.AppsecEnabled = true
	cfg.AppsecScheme = appsecURL.Scheme
	cfg.AppsecHost = appsecURL.Host
	cfg.AppsecBodyReadTimeoutSeconds = 1
	appsecClient, err := appsec.New(cfg, logger.New("ERROR", ""), "test", "body-timeout", "test")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(appsecClient.Close)

	b, passed := testBypassOriginBouncer(t)
	b.log = log
	b.appsecFailureAction = failureAction
	b.remediationCustomHeader = "X-Remediation"
	lapiClient, _ := lapi.NewTestClient(logger.New("ERROR", ""))
	lapi.AttachTestMetricsReporter(lapiClient)
	bindTestLAPI(b, lapiClient)
	bindTestAppSec(b, appsecClient)
	return b, lapiClient, passed, &appsecHits
}

// assertBodyTimeoutBan checks the ban status, header, and dropped origin of a body-read timeout.
func assertBodyTimeoutBan(t *testing.T, rw *httptest.ResponseRecorder, lapiClient *lapi.Client, passed bool, appsecHits *int32) {
	t.Helper()
	if passed {
		t.Fatal("origin must not run after a body read timeout")
	}
	if got := atomic.LoadInt32(appsecHits); got != 0 {
		t.Fatalf("AppSec listener called %d times, want 0", got)
	}
	if rw.Code != http.StatusForbidden || !strings.Contains(rw.Body.String(), "banned") {
		t.Fatalf("status=%d body=%q, want the ban response", rw.Code, rw.Body.String())
	}
	if got := rw.Header().Get("X-Remediation"); got != "ban:appsec-body-timeout" {
		t.Fatalf("X-Remediation=%q want ban:appsec-body-timeout", got)
	}
	if got := lapiClient.TestDroppedCount(lapi.OriginPluginAppsecBodyTimeout, "ipv4", "ban"); got != 1 {
		t.Fatalf("dropped %s ban=%d want 1", lapi.OriginPluginAppsecBodyTimeout, got)
	}
	if got := lapiClient.TestDroppedCount(lapi.OriginPluginAppsecFailure, "ipv4", "ban"); got != 0 {
		t.Fatalf("dropped %s ban=%d want 0", lapi.OriginPluginAppsecFailure, got)
	}
}

// TestServeAppSec_bodyReadTimeoutBansWhateverFailureAction: passthrough does not let a stalled body
// through and captcha does not serve a captcha; both get the body-timeout ban.
func TestServeAppSec_bodyReadTimeoutBansWhateverFailureAction(t *testing.T) {
	for _, failureAction := range []string{configuration.FailureActionPassthrough, configuration.FailureActionCaptcha, configuration.FailureActionBan} {
		t.Run(failureAction, func(t *testing.T) {
			t.Parallel()
			b, lapiClient, passed, appsecHits := newBodyTimeoutBouncer(t, failureAction, logger.New("ERROR", ""))
			rw := httptest.NewRecorder()
			continueAfterLAPIForTest(b, rw, testClientRequest(newStreamingUploadRequest(t), "203.0.113.10"))
			assertBodyTimeoutBan(t, rw, lapiClient, *passed, appsecHits)
		})
	}
}

// TestServeAppSec_bodyReadTimeoutSupersedesCaptchaRule: a matched captcha action rule loses to the
// body-timeout ban and is reported with warnCaptchaSuperseded.
func TestServeAppSec_bodyReadTimeoutSupersedesCaptchaRule(t *testing.T) {
	log, sink := newTestLogSink(slog.LevelWarn)
	b, lapiClient, passed, appsecHits := newBodyTimeoutBouncer(t, configuration.FailureActionPassthrough, log)
	b.actionRules = mustPathAction(t, "c", "^/stream$", httprule.ActionCaptcha)
	rw := httptest.NewRecorder()
	continueAfterLAPIForTest(b, rw, testClientRequest(newStreamingUploadRequest(t), "203.0.113.10"))
	assertBodyTimeoutBan(t, rw, lapiClient, *passed, appsecHits)
	logged := sink.String()
	if !strings.Contains(logged, "warnCaptchaSuperseded") || !strings.Contains(logged, `"name":"c"`) {
		t.Fatalf("want WARN warnCaptchaSuperseded name=c, got %s", logged)
	}
}

// TestServeAppSec_bypassAppsecDoesNotReadStreamingBody: a bypassAppsec route reaches origin while
// the body is still streaming; AppSec is not called and no deadline applies.
func TestServeAppSec_bypassAppsecDoesNotReadStreamingBody(t *testing.T) {
	b, _, passed, appsecHits := newBodyTimeoutBouncer(t, configuration.FailureActionBan, logger.New("ERROR", ""))
	b.actionRules = mustPathAction(t, "grpc-stream", "^/stream$", httprule.ActionBypassAppsec)
	rw := httptest.NewRecorder()
	started := time.Now()
	continueAfterLAPIForTest(b, rw, testClientRequest(newStreamingUploadRequest(t), "203.0.113.10"))
	if elapsed := time.Since(started); elapsed > 500*time.Millisecond {
		t.Fatalf("bypassAppsec request took %v; the body must not be read", elapsed)
	}
	if !*passed {
		t.Fatal("bypassAppsec route must reach origin")
	}
	if got := atomic.LoadInt32(appsecHits); got != 0 {
		t.Fatalf("AppSec listener called %d times, want 0", got)
	}
}
