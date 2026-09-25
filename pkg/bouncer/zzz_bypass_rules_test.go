package bouncer

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"text/template"

	"github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pkg/appsec"
	"github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pkg/configuration"
	"github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pkg/decisionscope"
	"github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pkg/decisionstore"
	"github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pkg/httprule"
	"github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pkg/ip"
	"github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pkg/lapi"
	logger "github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pkg/logger"
)

const testBypassHealthPath = "/health"

func mustCompileBypass(t *testing.T, rules []httprule.Rule) *httprule.Set {
	t.Helper()
	set, err := httprule.New(rules)
	if err != nil {
		t.Fatal(err)
	}
	return set
}

func pathBypass(path string) []httprule.Rule {
	return []httprule.Rule{{Path: path}}
}

func testBypassHealthRequest() *http.Request {
	req := httptest.NewRequest(http.MethodGet, "http://example.com"+testBypassHealthPath, nil)
	req.Host = "example.com"
	req.RemoteAddr = "203.0.113.10:1"
	return req
}

func testBypassOriginBouncer(t *testing.T) (*Bouncer, *bool) {
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

func TestBouncerNew_compilesBypassRules(t *testing.T) {
	log := logger.New("ERROR", "")
	cfg := configuration.New()
	cfg.BouncerAppsecBypassRules = pathBypass("^/healthz$")
	cfg.BouncerLapiBypassRules = pathBypass("^/ok/")
	got, err := New(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}), "test", cfg, false, false, false, log)
	if err != nil {
		t.Fatal(err)
	}
	appsecReq := httptest.NewRequest(http.MethodGet, "http://example.com/healthz", nil)
	if !got.appsecBypassRules.Match(appsecReq) {
		t.Fatal("appsecBypassRules must compile")
	}
	lapiReq := httptest.NewRequest(http.MethodGet, "http://example.com/ok/x", nil)
	if !got.lapiBypassRules.Match(lapiReq) {
		t.Fatal("lapiBypassRules must compile")
	}
}

func TestBouncerNew_emptyBypassRulesMatchNothing(t *testing.T) {
	log := logger.New("ERROR", "")
	cfg := configuration.New()
	got, err := New(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}), "test", cfg, false, false, false, log)
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodGet, "http://example.com/health", nil)
	if got.lapiBypassRules.Match(req) || got.appsecBypassRules.Match(req) {
		t.Fatal("empty bypass lists must match nothing")
	}
}

func TestBouncerNew_invalidBypassRules(t *testing.T) {
	log := logger.New("ERROR", "")
	cfg := configuration.New()
	cfg.BouncerLapiBypassRules = pathBypass("(")
	_, err := New(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}), "test", cfg, false, false, false, log)
	if err == nil {
		t.Fatal("invalid LAPI bypass must fail New")
	}
	cfg = configuration.New()
	cfg.BouncerAppsecBypassRules = pathBypass("(")
	_, err = New(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}), "test", cfg, false, false, false, log)
	if err == nil {
		t.Fatal("invalid AppSec bypass must fail New")
	}
}

func TestServeHTTP_emptyLapiBypassStillLooksUp(t *testing.T) {
	b, passed := testBypassOriginBouncer(t)
	lapiClient, store := lapi.NewTestClient(b.log)
	store.Put(decisionstore.Decision{
		Scope: decisionscope.ScopeIP, Value: "203.0.113.10", Kind: decisionscope.BannedValue, DurationSec: 60,
	})
	bindTestLAPI(b, lapiClient)
	rw := httptest.NewRecorder()
	b.ServeHTTP(rw, testBypassHealthRequest())
	if *passed {
		t.Fatal("empty bypass must still apply the store ban")
	}
	if rw.Code != http.StatusForbidden {
		t.Fatalf("status=%d", rw.Code)
	}
}

func TestServeHTTP_nonMatchingLapiBypassStillLooksUp(t *testing.T) {
	b, passed := testBypassOriginBouncer(t)
	lapiClient, store := lapi.NewTestClient(b.log)
	store.Put(decisionstore.Decision{
		Scope: decisionscope.ScopeIP, Value: "203.0.113.10", Kind: decisionscope.BannedValue, DurationSec: 60,
	})
	bindTestLAPI(b, lapiClient)
	b.lapiBypassRules = mustCompileBypass(t, pathBypass("^/nomatch$"))
	rw := httptest.NewRecorder()
	b.ServeHTTP(rw, testBypassHealthRequest())
	if *passed {
		t.Fatal("non-matching LAPI bypass must still apply the store ban")
	}
	if rw.Code != http.StatusForbidden {
		t.Fatalf("status=%d", rw.Code)
	}
}

func TestServeHTTP_lapiBypassSkipsUnboundLAPIFailure(t *testing.T) {
	b, passed := testBypassOriginBouncer(t)
	b.subscribeLAPI = true
	b.startupBlock = false
	b.lapiFailureAction = configuration.FailureActionBan
	b.lapiBypassRules = mustCompileBypass(t, pathBypass("^/health$"))
	rw := httptest.NewRecorder()
	b.ServeHTTP(rw, testBypassHealthRequest())
	if !*passed {
		t.Fatal("LAPI bypass must skip missing-subscribed-LAPI failure")
	}
	if rw.Code != http.StatusOK {
		t.Fatalf("status=%d", rw.Code)
	}
}

func TestServeHTTP_lapiBypassSkipsStreamStoreAndUnhealthy(t *testing.T) {
	b, passed := testBypassOriginBouncer(t)
	lapiClient, store := lapi.NewTestClient(b.log)
	store.Put(decisionstore.Decision{
		Scope: decisionscope.ScopeIP, Value: "203.0.113.10", Kind: decisionscope.BannedValue, DurationSec: 60,
	})
	lapiClient.SetStreamHealthyForTest(false)
	bindTestLAPI(b, lapiClient)
	b.lapiBypassRules = mustCompileBypass(t, pathBypass("^/health$"))
	rw := httptest.NewRecorder()
	b.ServeHTTP(rw, testBypassHealthRequest())
	if !*passed {
		t.Fatal("LAPI bypass must skip store hit and stream-unhealthy failure")
	}
}

func TestServeHTTP_lapiBypassSkipsLiveAndNoneLookup(t *testing.T) {
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
			}, log, "test", store, "bypass-live", "bypass-live")
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(lapiClient.Close)
			b, passed := testBypassOriginBouncer(t)
			b.subscribeLAPI = true
			b.lapiBound.Store(lapiClient)
			b.lapiBypassRules = mustCompileBypass(t, pathBypass("^/health$"))
			b.ServeHTTP(httptest.NewRecorder(), testBypassHealthRequest())
			if !*passed {
				t.Fatal("LAPI bypass must skip LiveLookup")
			}
			if atomic.LoadInt64(&hits) != 0 {
				t.Fatalf("LiveLookup hits=%d want 0", hits)
			}
		})
	}
}

func TestServeHTTP_appsecBypassSkipsQuery(t *testing.T) {
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
	b, passed := testBypassOriginBouncer(t)
	bindTestAppSec(b, appsec.NewTestClient(appsecURL, appsecServer.Client(), logger.New("ERROR", "")))
	b.appsecBypassRules = mustCompileBypass(t, pathBypass("^/health$"))
	b.ServeHTTP(httptest.NewRecorder(), testBypassHealthRequest())
	if !*passed {
		t.Fatal("AppSec bypass must call next")
	}
	if atomic.LoadInt64(&hits) != 0 {
		t.Fatalf("AppSec Query hits=%d want 0", hits)
	}
}

func TestServeHTTP_nonMatchingAppsecBypassStillQueries(t *testing.T) {
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
	b, passed := testBypassOriginBouncer(t)
	bindTestAppSec(b, appsec.NewTestClient(appsecURL, appsecServer.Client(), logger.New("ERROR", "")))
	b.appsecBypassRules = mustCompileBypass(t, pathBypass("^/nomatch$"))
	b.ServeHTTP(httptest.NewRecorder(), testBypassHealthRequest())
	if !*passed {
		t.Fatal("non-matching AppSec bypass must call next")
	}
	if atomic.LoadInt64(&hits) != 1 {
		t.Fatalf("AppSec Query hits=%d want 1", hits)
	}
}

func TestServeHTTP_lapiBypassDoesNotSkipAppsec(t *testing.T) {
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
	b, passed := testBypassOriginBouncer(t)
	lapiClient, store := lapi.NewTestClient(b.log)
	store.Put(decisionstore.Decision{
		Scope: decisionscope.ScopeIP, Value: "203.0.113.10", Kind: decisionscope.BannedValue, DurationSec: 60,
	})
	bindTestLAPI(b, lapiClient)
	bindTestAppSec(b, appsec.NewTestClient(appsecURL, appsecServer.Client(), logger.New("ERROR", "")))
	b.lapiBypassRules = mustCompileBypass(t, pathBypass("^/health$"))
	b.ServeHTTP(httptest.NewRecorder(), testBypassHealthRequest())
	if !*passed {
		t.Fatal("LAPI bypass still reaches the pass path")
	}
	if atomic.LoadInt64(&hits) != 1 {
		t.Fatalf("AppSec Query hits=%d want 1", hits)
	}
}

func TestServeHTTP_appsecBypassDoesNotSkipLapi(t *testing.T) {
	b, passed := testBypassOriginBouncer(t)
	lapiClient, store := lapi.NewTestClient(b.log)
	store.Put(decisionstore.Decision{
		Scope: decisionscope.ScopeIP, Value: "203.0.113.10", Kind: decisionscope.BannedValue, DurationSec: 60,
	})
	bindTestLAPI(b, lapiClient)
	b.appsecBypassRules = mustCompileBypass(t, pathBypass("^/health$"))
	rw := httptest.NewRecorder()
	b.ServeHTTP(rw, testBypassHealthRequest())
	if *passed {
		t.Fatal("AppSec bypass must not skip LAPI lookup")
	}
	if rw.Code != http.StatusForbidden {
		t.Fatalf("status=%d", rw.Code)
	}
}

func TestServeHTTP_forcedBStillBansBeforeLapiBypass(t *testing.T) {
	b, lapiClient, passed := testForcedDecisionBouncer(t, nil, nil, nil, true)
	b.lapiBypassRules = mustCompileBypass(t, pathBypass("^/protected$"))
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

func TestServeHTTP_forcedCStillCaptchasAfterLapiBypass(t *testing.T) {
	client := testCaptchaClient(t, "/fast.js", "", "", nil)
	b, _, passed := testForcedDecisionBouncer(t, nil, client, nil, true)
	b.lapiBypassRules = mustCompileBypass(t, pathBypass("^/protected$"))
	rw := httptest.NewRecorder()
	b.ServeHTTP(rw, testForcedDecisionRequest("c"))
	if *passed {
		t.Fatal("forced c after LAPI bypass must not reach origin")
	}
	if rw.Body.String() == "banned" {
		t.Fatal("store ban must not apply after LAPI bypass")
	}
	if !strings.Contains(rw.Body.String(), "CAPTCHA_CHALLENGE_PAGE") {
		t.Fatalf("want captcha page, got %q", rw.Body.String())
	}
}

func TestServeHTTP_trustedIPStillSkipsPlugin(t *testing.T) {
	b, passed := testBypassOriginBouncer(t)
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
	b.lapiBypassRules = mustCompileBypass(t, pathBypass("^/nomatch$"))
	b.ServeHTTP(httptest.NewRecorder(), testBypassHealthRequest())
	if !*passed {
		t.Fatal("trusted client must skip the whole plugin")
	}
}

func TestServeHTTP_unanchoredPathMatchesSubstring(t *testing.T) {
	b, passed := testBypassOriginBouncer(t)
	lapiClient, store := lapi.NewTestClient(b.log)
	store.Put(decisionstore.Decision{
		Scope: decisionscope.ScopeIP, Value: "203.0.113.10", Kind: decisionscope.BannedValue, DurationSec: 60,
	})
	bindTestLAPI(b, lapiClient)
	b.lapiBypassRules = mustCompileBypass(t, pathBypass("health"))
	req := httptest.NewRequest(http.MethodGet, "http://example.com/unhealthy", nil)
	req.Host = "example.com"
	req.RemoteAddr = "203.0.113.10:1"
	b.ServeHTTP(httptest.NewRecorder(), req)
	if !*passed {
		t.Fatal("unanchored health must skip LAPI on /unhealthy")
	}
}

func TestServeHTTP_hostIsNotInPathMatch(t *testing.T) {
	b, passed := testBypassOriginBouncer(t)
	lapiClient, store := lapi.NewTestClient(b.log)
	store.Put(decisionstore.Decision{
		Scope: decisionscope.ScopeIP, Value: "203.0.113.10", Kind: decisionscope.BannedValue, DurationSec: 60,
	})
	bindTestLAPI(b, lapiClient)
	b.lapiBypassRules = mustCompileBypass(t, pathBypass("example.com://health"))
	rw := httptest.NewRecorder()
	b.ServeHTTP(rw, testBypassHealthRequest())
	if *passed {
		t.Fatal("host://path must not match req.URL.Path /health")
	}
	if rw.Code != http.StatusForbidden {
		t.Fatalf("status=%d", rw.Code)
	}
}

func TestServeHTTP_queryStringNotInPath(t *testing.T) {
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
	b, passed := testBypassOriginBouncer(t)
	bindTestAppSec(b, appsec.NewTestClient(appsecURL, appsecServer.Client(), logger.New("ERROR", "")))
	b.appsecBypassRules = mustCompileBypass(t, pathBypass("^/health$"))
	req := httptest.NewRequest(http.MethodGet, "http://example.com/health?a=1", nil)
	req.Host = "example.com"
	req.RemoteAddr = "203.0.113.10:1"
	b.ServeHTTP(httptest.NewRecorder(), req)
	if !*passed {
		t.Fatal("query must not be in the path")
	}
	if atomic.LoadInt64(&hits) != 0 {
		t.Fatalf("AppSec Query hits=%d want 0", hits)
	}
}
