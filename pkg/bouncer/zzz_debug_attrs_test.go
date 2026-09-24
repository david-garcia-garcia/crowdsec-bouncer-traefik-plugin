package bouncer

import (
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pkg/configuration"
	"github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pkg/decisionscope"
	"github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pkg/decisionstore"
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
		log:                      log,
		next: http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
			passed = true
		}),
	}
	bindTestLAPI(b, lapiClient)
	req := httptest.NewRequest(http.MethodGet, "http://example.com/protected", nil)
	req.RemoteAddr = "127.0.0.1:1"
	req.Header.Set("X-Forwarded-For", "203.0.113.10")
	return b, httptest.NewRecorder(), req, &passed
}

// testStreamBanBouncer is a stream bouncer with an Ip ban on 203.0.113.10 and optional mapped headers.
func testStreamBanBouncer(t *testing.T, log *slog.Logger, scopeHeaders map[string]string) (*Bouncer, *http.Request, *bool) {
	t.Helper()
	lapiClient, _ := lapi.NewTestClient(log)
	store := lapi.AttachTestInternStore(lapiClient)
	lapiClient.SetStreamHealthyForTest(true)
	lapi.SeedLiveSnapshotForTest(store, "203.0.113.10", decisionscope.BannedValue, "crowdsec", 60)
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
		decisionScopeHeaders:     scopeHeaders,
		log:                      log,
		remediationStatusCode:    http.StatusForbidden,
		next: http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
			passed = true
		}),
	}
	bindTestLAPI(b, lapiClient)
	req := httptest.NewRequest(http.MethodGet, "http://example.com/protected", nil)
	req.RemoteAddr = "127.0.0.1:1"
	req.Header.Set("X-Forwarded-For", "203.0.113.10")
	return b, req, &passed
}

// jsonLinesWithMsg are slog JSON lines whose msg equals the stem.
func jsonLinesWithMsg(logged, msg string) []string {
	var lines []string
	for _, line := range strings.Split(logged, "\n") {
		if line == "" {
			continue
		}
		var rec struct {
			Msg string `json:"msg"`
		}
		if json.Unmarshal([]byte(line), &rec) != nil || rec.Msg != msg {
			continue
		}
		lines = append(lines, line)
	}
	return lines
}

// remediatingServeHTTPTrace is the store-hit ServeHTTP TRACE (has remediation, not the first breadcrumb).
func remediatingServeHTTPTrace(t *testing.T, logged string) string {
	t.Helper()
	for _, line := range jsonLinesWithMsg(logged, "ServeHTTP") {
		if strings.Contains(line, `"remediation":`) {
			return line
		}
	}
	t.Fatalf("want remediating ServeHTTP TRACE, got %s", logged)
	return ""
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

// TestHunt_ServeHTTPTraceRemediatingIncludesPresentScopes fails if remediating TRACE still says cache=hit or omits mapped scopes.
func TestHunt_ServeHTTPTraceRemediatingIncludesPresentScopes(t *testing.T) {
	log, sink := newTestLogSink(logger.LevelTrace)
	b, req, passed := testStreamBanBouncer(t, log, map[string]string{
		decisionscope.ScopeCountry: "CF-IPCountry",
		decisionscope.ScopeAS:      "CF-ASN",
	})
	req.Header.Set("CF-IPCountry", "FR")
	req.Header.Set("CF-ASN", "13335")
	b.ServeHTTP(httptest.NewRecorder(), req)
	if *passed {
		t.Fatal("origin must not run on store-hit ban")
	}
	record := remediatingServeHTTPTrace(t, sink.String())
	if !strings.Contains(record, `"ip":"203.0.113.10"`) {
		t.Fatalf("want ip attribute, got %s", record)
	}
	if !strings.Contains(record, `"remediation":"t"`) {
		t.Fatalf("want remediation letter, got %s", record)
	}
	if strings.Contains(record, `"cache"`) {
		t.Fatalf("remediating TRACE must not include cache, got %s", record)
	}
	if !strings.Contains(record, `"scopes":{"AS":"13335","Country":"FR"}`) {
		t.Fatalf("want scopes group with Country and AS, got %s", record)
	}
}

// TestHunt_ServeHTTPTraceRemediatingOmitsMissingHeaders fails if a missing Country header still appears under scopes.
func TestHunt_ServeHTTPTraceRemediatingOmitsMissingHeaders(t *testing.T) {
	log, sink := newTestLogSink(logger.LevelTrace)
	b, req, passed := testStreamBanBouncer(t, log, map[string]string{
		decisionscope.ScopeCountry: "CF-IPCountry",
	})
	b.ServeHTTP(httptest.NewRecorder(), req)
	if *passed {
		t.Fatal("origin must not run on store-hit ban")
	}
	record := remediatingServeHTTPTrace(t, sink.String())
	if strings.Contains(record, `"Country"`) {
		t.Fatalf("missing Country header must not appear under scopes, got %s", record)
	}
}

// TestHunt_ServeHTTPTraceRemediatingInventNoScopeKeys fails if remediating TRACE invents scope keys with no mapped headers.
func TestHunt_ServeHTTPTraceRemediatingInventNoScopeKeys(t *testing.T) {
	log, sink := newTestLogSink(logger.LevelTrace)
	b, req, passed := testStreamBanBouncer(t, log, nil)
	b.ServeHTTP(httptest.NewRecorder(), req)
	if *passed {
		t.Fatal("origin must not run on store-hit ban")
	}
	record := remediatingServeHTTPTrace(t, sink.String())
	if !strings.Contains(record, `"ip":"203.0.113.10"`) || !strings.Contains(record, `"remediation":"t"`) {
		t.Fatalf("want ip and remediation, got %s", record)
	}
	if strings.Contains(record, `"cache"`) {
		t.Fatalf("remediating TRACE must not include cache, got %s", record)
	}
	if strings.Contains(record, `"scopes"`) {
		t.Fatalf("no mapped headers must not invent scopes, got %s", record)
	}
}

// TestHunt_ServeHTTPLiveLookupTraceIncludesScopes fails if LiveLookup TRACE omits present scopes or still says cache.
func TestHunt_ServeHTTPLiveLookupTraceIncludesScopes(t *testing.T) {
	log, sink := newTestLogSink(logger.LevelTrace)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("scope") != "" {
			_, _ = w.Write([]byte("null"))
			return
		}
		if r.URL.Query().Get("ip") == "" {
			w.WriteHeader(http.StatusOK)
			return
		}
		_ = json.NewEncoder(w).Encode([]lapi.Decision{{
			Value: r.URL.Query().Get("ip"), Type: "ban", Duration: "1h", Origin: "CAPI", Scope: "ip",
		}})
	}))
	t.Cleanup(srv.Close)
	parsed, err := url.Parse(srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	store := decisionstore.NewMemory(log)
	client, err := lapi.New(&configuration.Config{
		LapiHTTPTimeoutSeconds:           10,
		LapiHost:                         parsed.Host,
		LapiKey:                          "test-key",
		LapiMetricsUpdateIntervalSeconds: 0,
		LapiMode:                         configuration.LiveMode,
		LapiPath:                         "/",
		LapiScheme:                       parsed.Scheme,
		LapiTLSInsecureVerify:            true,
	}, log, "test", store, "live-trace", "live-trace")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(client.Close)
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
		decisionScopeHeaders: map[string]string{
			decisionscope.ScopeCountry: "CF-IPCountry",
			decisionscope.ScopeAS:      "CF-ASN",
		},
		log:                   log,
		remediationStatusCode: http.StatusForbidden,
		subscribeLAPI:         true,
		next: http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
			passed = true
		}),
	}
	b.lapiBound.Store(client)
	req := httptest.NewRequest(http.MethodGet, "http://example.com/protected", nil)
	req.RemoteAddr = "127.0.0.1:1"
	req.Header.Set("X-Forwarded-For", "203.0.113.10")
	req.Header.Set("CF-IPCountry", "FR")
	req.Header.Set("CF-ASN", "13335")
	b.ServeHTTP(httptest.NewRecorder(), req)
	if passed {
		t.Fatal("origin must not run on LiveLookup ban")
	}
	var record string
	for _, line := range jsonLinesWithMsg(sink.String(), "ServeHTTP:LiveLookup") {
		if strings.Contains(line, `"isBanned"`) {
			record = line
			break
		}
	}
	if record == "" {
		t.Fatalf("want ServeHTTP:LiveLookup TRACE, got %s", sink.String())
	}
	if !strings.Contains(record, `"ip":"203.0.113.10"`) {
		t.Fatalf("want ip attribute, got %s", record)
	}
	if !strings.Contains(record, `"isBanned":"t"`) {
		t.Fatalf("want isBanned kind, got %s", record)
	}
	if strings.Contains(record, `"cache"`) {
		t.Fatalf("LiveLookup TRACE must not include cache, got %s", record)
	}
	if !strings.Contains(record, `"scopes":{"AS":"13335","Country":"FR"}`) {
		t.Fatalf("want scopes group with Country and AS, got %s", record)
	}
}
