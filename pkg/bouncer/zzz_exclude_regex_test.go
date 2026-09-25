package bouncer

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strings"
	"sync/atomic"
	"testing"
	"text/template"

	"github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pkg/appsec"
	"github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pkg/configuration"
	"github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pkg/decisionscope"
	"github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pkg/decisionstore"
	"github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pkg/ip"
	"github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pkg/lapi"
	logger "github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pkg/logger"
)

const testExcludeHealthPath = "/health"

func mustCompileExclude(t *testing.T, pattern string) *regexp.Regexp {
	t.Helper()
	compiled, err := configuration.CompileExcludeRegex(pattern)
	if err != nil {
		t.Fatal(err)
	}
	return compiled
}

func testExcludeHealthRequest() *http.Request {
	req := httptest.NewRequest(http.MethodGet, "http://example.com"+testExcludeHealthPath, nil)
	req.Host = "example.com"
	req.RemoteAddr = "203.0.113.10:1"
	return req
}

func testExcludeOriginBouncer(t *testing.T) (*Bouncer, *bool) {
	t.Helper()
	log := logger.New("ERROR", "")
	clientChecker, err := ip.NewChecker(log, nil)
	if err != nil {
		t.Fatal(err)
	}
	banTemplate, err := template.New("ban").Parse("banned")
	if err != nil {
		t.Fatal(err)
	}
	passed := false
	b := &Bouncer{
		enabled:                true,
		clientPoolStrategy:     &ip.PoolStrategy{Checker: clientChecker},
		log:                    log,
		remediationStatusCode:  http.StatusForbidden,
		banTemplate:            banTemplate,
		banTemplateContentType: "text/html; charset=utf-8",
		next: http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
			passed = true
		}),
	}
	return b, &passed
}

func TestExcludeMatchString(t *testing.T) {
	tests := []struct {
		name string
		host string
		url  string
		want string
	}{
		{name: "port stripped", host: "example.com:443", url: "http://example.com/health", want: "example.com:///health"},
		{name: "query ignored", host: "example.com", url: "http://example.com/health?a=1", want: "example.com:///health"},
		{name: "empty path is slash", host: "example.com", url: "http://example.com", want: "example.com:///"},
		{name: "ipv6 with port loses brackets", host: "[::1]:443", url: "http://[::1]/health", want: "::1:///health"},
		{name: "bare ipv6 stays as Host wrote it", host: "[::1]", url: "http://[::1]/health", want: "[::1]:///health"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, tt.url, nil)
			req.Host = tt.host
			if got := excludeMatchString(req); got != tt.want {
				t.Fatalf("excludeMatchString=%q want %q", got, tt.want)
			}
		})
	}
}

func TestBouncerNew_compilesExcludeRegex(t *testing.T) {
	log := logger.New("ERROR", "")
	cfg := configuration.New()
	cfg.BouncerAppsecExcludeRegex = `example\.com:///health`
	cfg.BouncerLapiExcludeRegex = `^ok/`
	got, err := New(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}), "test", cfg, false, false, false, log)
	if err != nil {
		t.Fatal(err)
	}
	if got.appsecExcludeRegex == nil || !got.appsecExcludeRegex.MatchString("example.com:///health") {
		t.Fatal("appsecExcludeRegex must compile")
	}
	if got.lapiExcludeRegex == nil || !got.lapiExcludeRegex.MatchString("ok/") {
		t.Fatal("lapiExcludeRegex must compile")
	}
}

func TestBouncerNew_emptyExcludeRegexIsNil(t *testing.T) {
	log := logger.New("ERROR", "")
	cfg := configuration.New()
	cfg.BouncerLapiExcludeRegex = "  "
	got, err := New(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}), "test", cfg, false, false, false, log)
	if err != nil {
		t.Fatal(err)
	}
	if got.lapiExcludeRegex != nil || got.appsecExcludeRegex != nil {
		t.Fatal("empty exclude must stay nil")
	}
}

func TestBouncerNew_invalidExcludeRegex(t *testing.T) {
	log := logger.New("ERROR", "")
	cfg := configuration.New()
	cfg.BouncerLapiExcludeRegex = "("
	_, err := New(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}), "test", cfg, false, false, false, log)
	if err == nil {
		t.Fatal("invalid LAPI exclude must fail New")
	}
	cfg = configuration.New()
	cfg.BouncerAppsecExcludeRegex = "("
	_, err = New(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}), "test", cfg, false, false, false, log)
	if err == nil {
		t.Fatal("invalid AppSec exclude must fail New")
	}
}

func TestServeHTTP_emptyLapiExcludeStillLooksUp(t *testing.T) {
	b, passed := testExcludeOriginBouncer(t)
	lapiClient, store := lapi.NewTestClient(b.log)
	store.Put(decisionstore.Decision{
		Scope: decisionscope.ScopeIP, Value: "203.0.113.10", Kind: decisionscope.BannedValue, DurationSec: 60,
	})
	bindTestLAPI(b, lapiClient)
	rw := httptest.NewRecorder()
	b.ServeHTTP(rw, testExcludeHealthRequest())
	if *passed {
		t.Fatal("empty exclude must still apply the store ban")
	}
	if rw.Code != http.StatusForbidden {
		t.Fatalf("status=%d", rw.Code)
	}
}

func TestServeHTTP_lapiExcludeSkipsStreamStoreAndUnhealthy(t *testing.T) {
	b, passed := testExcludeOriginBouncer(t)
	lapiClient, store := lapi.NewTestClient(b.log)
	store.Put(decisionstore.Decision{
		Scope: decisionscope.ScopeIP, Value: "203.0.113.10", Kind: decisionscope.BannedValue, DurationSec: 60,
	})
	lapiClient.SetStreamHealthyForTest(false)
	bindTestLAPI(b, lapiClient)
	b.lapiExcludeRegex = mustCompileExclude(t, `example\.com:///health`)
	rw := httptest.NewRecorder()
	b.ServeHTTP(rw, testExcludeHealthRequest())
	if !*passed {
		t.Fatal("LAPI exclude must skip store hit and stream-unhealthy failure")
	}
}

func TestServeHTTP_lapiExcludeSkipsLiveAndNoneLookup(t *testing.T) {
	for _, mode := range []string{configuration.LiveMode, configuration.NoneMode} {
		t.Run(mode, func(t *testing.T) {
			var hits int64
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Query().Get("ip") != "" {
					atomic.AddInt64(&hits, 1)
					_ = json.NewEncoder(w).Encode([]lapi.Decision{{
						Value: r.URL.Query().Get("ip"), Type: "ban", Duration: "1h", Origin: "CAPI", Scope: "ip",
					}})
					return
				}
				w.WriteHeader(http.StatusOK)
			}))
			t.Cleanup(srv.Close)
			parsed, err := url.Parse(srv.URL)
			if err != nil {
				t.Fatal(err)
			}
			log := logger.New("ERROR", "")
			store := decisionstore.NewMemory(log)
			lapiClient, err := lapi.New(&configuration.Config{
				LapiHTTPTimeoutSeconds:           10,
				LapiHost:                         parsed.Host,
				LapiKey:                          "test-key",
				LapiMetricsUpdateIntervalSeconds: 0,
				LapiMode:                         mode,
				LapiPath:                         "/",
				LapiScheme:                       parsed.Scheme,
				LapiTLSInsecureVerify:            true,
			}, log, "test", store, "exclude-live", "exclude-live")
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(lapiClient.Close)
			b, passed := testExcludeOriginBouncer(t)
			b.subscribeLAPI = true
			b.lapiBound.Store(lapiClient)
			b.lapiExcludeRegex = mustCompileExclude(t, `example\.com:///health`)
			b.ServeHTTP(httptest.NewRecorder(), testExcludeHealthRequest())
			if !*passed {
				t.Fatal("LAPI exclude must skip LiveLookup")
			}
			if atomic.LoadInt64(&hits) != 0 {
				t.Fatalf("LiveLookup hits=%d want 0", hits)
			}
		})
	}
}

func TestServeHTTP_appsecExcludeSkipsQuery(t *testing.T) {
	var hits int64
	appsecServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		atomic.AddInt64(&hits, 1)
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"action":"allow"}`))
	}))
	t.Cleanup(appsecServer.Close)
	appsecURL, err := url.Parse(appsecServer.URL)
	if err != nil {
		t.Fatal(err)
	}
	b, passed := testExcludeOriginBouncer(t)
	bindTestAppSec(b, appsec.NewTestClient(appsecURL, appsecServer.Client(), logger.New("ERROR", "")))
	b.appsecExcludeRegex = mustCompileExclude(t, `^example\.com:///health$`)
	b.ServeHTTP(httptest.NewRecorder(), testExcludeHealthRequest())
	if !*passed {
		t.Fatal("AppSec exclude must call next")
	}
	if atomic.LoadInt64(&hits) != 0 {
		t.Fatalf("AppSec Query hits=%d want 0", hits)
	}
}

func TestServeHTTP_lapiExcludeDoesNotSkipAppsec(t *testing.T) {
	var hits int64
	appsecServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		atomic.AddInt64(&hits, 1)
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"action":"allow"}`))
	}))
	t.Cleanup(appsecServer.Close)
	appsecURL, err := url.Parse(appsecServer.URL)
	if err != nil {
		t.Fatal(err)
	}
	b, passed := testExcludeOriginBouncer(t)
	lapiClient, store := lapi.NewTestClient(b.log)
	store.Put(decisionstore.Decision{
		Scope: decisionscope.ScopeIP, Value: "203.0.113.10", Kind: decisionscope.BannedValue, DurationSec: 60,
	})
	bindTestLAPI(b, lapiClient)
	bindTestAppSec(b, appsec.NewTestClient(appsecURL, appsecServer.Client(), logger.New("ERROR", "")))
	b.lapiExcludeRegex = mustCompileExclude(t, `example\.com:///health`)
	b.ServeHTTP(httptest.NewRecorder(), testExcludeHealthRequest())
	if !*passed {
		t.Fatal("LAPI exclude still reaches the pass path")
	}
	if atomic.LoadInt64(&hits) != 1 {
		t.Fatalf("AppSec Query hits=%d want 1", hits)
	}
}

func TestServeHTTP_forcedBStillBansBeforeLapiExclude(t *testing.T) {
	b, lapiClient, passed := testForcedDecisionBouncer(t, nil, nil, nil, true)
	b.lapiExcludeRegex = mustCompileExclude(t, `example\.com:///protected`)
	rw := httptest.NewRecorder()
	b.ServeHTTP(rw, testForcedDecisionRequest("b"))
	if *passed {
		t.Fatal("forced b must still ban")
	}
	if rw.Code != http.StatusForbidden || rw.Body.String() == "" {
		t.Fatalf("status=%d body=%q", rw.Code, rw.Body.String())
	}
	if got := lapiClient.TestDroppedCount(lapi.OriginPluginForcedDecision, "ipv4", "ban"); got != 1 {
		t.Fatalf("dropped origin=%d", got)
	}
}

func TestServeHTTP_forcedCStillCaptchasAfterLapiExclude(t *testing.T) {
	client := testCaptchaClient(t, "/fast.js", "", "", nil)
	b, _, passed := testForcedDecisionBouncer(t, nil, client, nil, true)
	b.lapiExcludeRegex = mustCompileExclude(t, `example\.com:///protected`)
	rw := httptest.NewRecorder()
	b.ServeHTTP(rw, testForcedDecisionRequest("c"))
	if *passed {
		t.Fatal("forced c after LAPI exclude must not reach origin")
	}
	if rw.Body.String() == "banned" {
		t.Fatal("store ban must not apply after LAPI exclude")
	}
	if !strings.Contains(rw.Body.String(), "CAPTCHA_CHALLENGE_PAGE") {
		t.Fatalf("want captcha page, got %q", rw.Body.String())
	}
}

func TestServeHTTP_trustedIPStillSkipsPlugin(t *testing.T) {
	b, passed := testExcludeOriginBouncer(t)
	trusted, err := ip.NewChecker(b.log, []string{"203.0.113.10"})
	if err != nil {
		t.Fatal(err)
	}
	b.clientPoolStrategy = &ip.PoolStrategy{Checker: trusted}
	lapiClient, store := lapi.NewTestClient(b.log)
	store.Put(decisionstore.Decision{
		Scope: decisionscope.ScopeIP, Value: "203.0.113.10", Kind: decisionscope.BannedValue, DurationSec: 60,
	})
	bindTestLAPI(b, lapiClient)
	b.lapiExcludeRegex = mustCompileExclude(t, `^nomatch$`)
	b.ServeHTTP(httptest.NewRecorder(), testExcludeHealthRequest())
	if !*passed {
		t.Fatal("trusted client must skip the whole plugin")
	}
}

func TestServeHTTP_portStrippedFromHost(t *testing.T) {
	b, passed := testExcludeOriginBouncer(t)
	lapiClient, store := lapi.NewTestClient(b.log)
	store.Put(decisionstore.Decision{
		Scope: decisionscope.ScopeIP, Value: "203.0.113.10", Kind: decisionscope.BannedValue, DurationSec: 60,
	})
	bindTestLAPI(b, lapiClient)
	b.lapiExcludeRegex = mustCompileExclude(t, `^example\.com:///health$`)
	req := testExcludeHealthRequest()
	req.Host = "example.com:443"
	b.ServeHTTP(httptest.NewRecorder(), req)
	if !*passed {
		t.Fatal("port-stripped host must match LAPI exclude")
	}
}

func TestServeHTTP_queryStringNotInMatchString(t *testing.T) {
	var hits int64
	appsecServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		atomic.AddInt64(&hits, 1)
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"action":"allow"}`))
	}))
	t.Cleanup(appsecServer.Close)
	appsecURL, err := url.Parse(appsecServer.URL)
	if err != nil {
		t.Fatal(err)
	}
	b, passed := testExcludeOriginBouncer(t)
	bindTestAppSec(b, appsec.NewTestClient(appsecURL, appsecServer.Client(), logger.New("ERROR", "")))
	b.appsecExcludeRegex = mustCompileExclude(t, `^example\.com:///health$`)
	req := httptest.NewRequest(http.MethodGet, "http://example.com/health?a=1", nil)
	req.Host = "example.com"
	req.RemoteAddr = "203.0.113.10:1"
	b.ServeHTTP(httptest.NewRecorder(), req)
	if !*passed {
		t.Fatal("query must not be in the match string")
	}
	if atomic.LoadInt64(&hits) != 0 {
		t.Fatalf("AppSec Query hits=%d want 0", hits)
	}
}
