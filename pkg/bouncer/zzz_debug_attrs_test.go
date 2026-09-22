package bouncer

import (
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pkg/captcha"
	"github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pkg/configuration"
	"github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pkg/ip"
	"github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pkg/lapi"
	"github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pkg/logger"
)

// testStreamAllowBouncer is a stream bouncer whose cache says none for 203.0.113.10.
func testStreamAllowBouncer(t *testing.T, log *slog.Logger) (*Bouncer, *httptest.ResponseRecorder, *http.Request, *bool) {
	t.Helper()
	lapiClient, _ := lapi.NewTestClient(log)
	lapi.AttachTestInternStore(lapiClient)
	lapiClient.SetStreamHealthyForTest(true)
	clientChecker, err := ip.NewChecker(log, nil)
	if err != nil {
		t.Fatal(err)
	}
	passed := false
	b := &Bouncer{
		enabled:                  true,
		forwardedHeadersInsecure: true,
		forwardedCustomHeader:    "X-Forwarded-For",
		clientPoolStrategy:       &ip.PoolStrategy{Checker: clientChecker},
		captchaClient:            &captcha.Client{},
		log:                      log,
		next: http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
			passed = true
		}),
	}
	bindTestLAPI(b, lapiClient, configuration.StreamMode)
	req := httptest.NewRequest(http.MethodGet, "http://example.com/protected", nil)
	req.RemoteAddr = "127.0.0.1:1"
	req.Header.Set("X-Forwarded-For", "203.0.113.10")
	return b, httptest.NewRecorder(), req, &passed
}

// TestHunt_ServeHTTPInfoAllowOmitsDebug fails if INFO stream allow emits Debug or Trace records.
func TestHunt_ServeHTTPInfoAllowOmitsDebug(t *testing.T) {
	log, sink := newTestLogSink(slog.LevelInfo)
	b, rw, req, passed := testStreamAllowBouncer(t, log)
	b.ServeHTTP(rw, req)
	if !*passed {
		t.Fatal("origin must run on stream cache none")
	}
	logged := sink.String()
	if strings.Contains(logged, `"level":"DEBUG"`) || strings.Contains(logged, `"msg":"ServeHTTP"`) {
		t.Fatalf("INFO allow emitted Debug or hot-path ServeHTTP: %s", logged)
	}
}

// TestHunt_ServeHTTPDebugAllowOmitsTrace fails if DEBUG still emits per-request ServeHTTP.
func TestHunt_ServeHTTPDebugAllowOmitsTrace(t *testing.T) {
	log, sink := newTestLogSink(slog.LevelDebug)
	b, rw, req, passed := testStreamAllowBouncer(t, log)
	b.ServeHTTP(rw, req)
	if !*passed {
		t.Fatal("origin must run on stream cache none")
	}
	logged := sink.String()
	if strings.Contains(logged, `"msg":"ServeHTTP"`) {
		t.Fatalf("DEBUG allow emitted hot-path ServeHTTP: %s", logged)
	}
}

// TestHunt_ServeHTTPTraceUsesAttributes fails if ServeHTTP still Sprintfs ip into msg.
func TestHunt_ServeHTTPTraceUsesAttributes(t *testing.T) {
	log, sink := newTestLogSink(logger.LevelTrace)
	b, rw, req, passed := testStreamAllowBouncer(t, log)
	b.ServeHTTP(rw, req)
	if !*passed {
		t.Fatal("origin must run on stream cache none")
	}
	logged := sink.String()
	if !strings.Contains(logged, `"msg":"ServeHTTP"`) {
		t.Fatalf("want msg ServeHTTP, got %s", logged)
	}
	if strings.Contains(logged, "ServeHTTP ip:") {
		t.Fatalf("interpolated ServeHTTP msg: %s", logged)
	}
	if !strings.Contains(logged, `"ip":"203.0.113.10"`) {
		t.Fatalf("want ip attribute, got %s", logged)
	}
	if !strings.Contains(logged, `"isTrusted":false`) {
		t.Fatalf("want isTrusted attribute, got %s", logged)
	}
}
