package bouncer

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"testing"
	"text/template"
	"time"

	"github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pkg/captcha"
	"github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pkg/configuration"
	"github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pkg/decisionscope"
	"github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pkg/decisionstore"
	"github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pkg/httprule"
	"github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pkg/lapi"
	logger "github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pkg/logger"
)

const retryAfterTestIP = "203.0.113.10"

// newRetryAfterStreamBouncer is a stream-mode router that answers bans with statusCode, plus its memory store.
func newRetryAfterStreamBouncer(t *testing.T, statusCode int, remap map[string]map[string]string) (*Bouncer, *bool, *decisionstore.Store) {
	t.Helper()
	lapiClient, store := lapi.NewTestClient(logger.New("ERROR", ""))
	lapiClient.SetStreamHealthyForTest(true)
	b, passed := testRemapStreamBouncer(t, lapiClient, remap)
	b.remediationStatusCode = statusCode
	b.remediationCustomHeader = "X-Remediation"
	return b, passed, store
}

// putRetryAfterTestDecision stores a stream decision for retryAfterTestIP whose TTL and decision duration are durationSec.
func putRetryAfterTestDecision(store *decisionstore.Store, kind, origin string, durationSec int64) {
	store.Put(decisionstore.Decision{
		Scope: decisionscope.ScopeIP, Value: retryAfterTestIP, Kind: kind, Origin: origin,
		DurationSec: durationSec, DecisionDurationSec: durationSec,
	})
}

// serveRetryAfterRequest runs the whole ServeHTTP for method on target from retryAfterTestIP.
func serveRetryAfterRequest(b *Bouncer, method, target string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(method, "http://example.com"+target, nil)
	req.RemoteAddr = retryAfterTestIP + ":1"
	rw := httptest.NewRecorder()
	b.ServeHTTP(rw, req)
	return rw
}

// assertRetryAfterBetween fails unless the response is 429 with an integer Retry-After from minSeconds to maxSeconds.
func assertRetryAfterBetween(t *testing.T, rw *httptest.ResponseRecorder, minSeconds, maxSeconds int64) {
	t.Helper()
	if rw.Code != http.StatusTooManyRequests {
		t.Fatalf("status %d, want %d (body %q)", rw.Code, http.StatusTooManyRequests, rw.Body.String())
	}
	header := rw.Header().Get("Retry-After")
	seconds, err := strconv.ParseInt(header, 10, 64)
	if err != nil || seconds < minSeconds || seconds > maxSeconds {
		t.Fatalf("Retry-After %q, want an integer from %d to %d", header, minSeconds, maxSeconds)
	}
}

// assertNoRetryAfter fails unless the response is status without Retry-After.
func assertNoRetryAfter(t *testing.T, rw *httptest.ResponseRecorder, status int) {
	t.Helper()
	if rw.Code != status {
		t.Fatalf("status %d, want %d (body %q)", rw.Code, status, rw.Body.String())
	}
	if header, ok := rw.Header()["Retry-After"]; ok {
		t.Fatalf("Retry-After %q, want none", header)
	}
}

func TestRetryAfter_streamBanAnswered429(t *testing.T) {
	b, _, store := newRetryAfterStreamBouncer(t, http.StatusTooManyRequests, nil)
	putRetryAfterTestDecision(store, decisionscope.BannedValue, "crowdsec", 3600)
	assertRetryAfterBetween(t, serveRetryAfterRequest(b, http.MethodGet, "/"), 1, 3600)
}

func TestRetryAfter_streamBanAnswered403HasNone(t *testing.T) {
	b, _, store := newRetryAfterStreamBouncer(t, http.StatusForbidden, nil)
	putRetryAfterTestDecision(store, decisionscope.BannedValue, "crowdsec", 3600)
	assertNoRetryAfter(t, serveRetryAfterRequest(b, http.MethodGet, "/"), http.StatusForbidden)
}

func TestRetryAfter_headBanCarriesHeaderWithoutBody(t *testing.T) {
	b, _, store := newRetryAfterStreamBouncer(t, http.StatusTooManyRequests, nil)
	putRetryAfterTestDecision(store, decisionscope.BannedValue, "crowdsec", 3600)
	rw := serveRetryAfterRequest(b, http.MethodHead, "/")
	assertRetryAfterBetween(t, rw, 1, 3600)
	if rw.Body.Len() != 0 {
		t.Fatalf("HEAD body %q, want empty", rw.Body.String())
	}
}

func TestRetryAfter_streamRangeBanHasNone(t *testing.T) {
	b, _, store := newRetryAfterStreamBouncer(t, http.StatusTooManyRequests, nil)
	if err := store.ApplyRangeBatch(map[string]string{"203.0.113.0/24": decisionscope.BannedValue}, nil); err != nil {
		t.Fatal(err)
	}
	assertNoRetryAfter(t, serveRetryAfterRequest(b, http.MethodGet, "/"), http.StatusTooManyRequests)
}

func TestRetryAfter_lapiCaptchaServedAsBan(t *testing.T) {
	for name, bindCaptcha := range map[string]func(*Bouncer){
		"unsubscribed": func(b *Bouncer) { bindTestCaptcha(b, nil) },
		"unusable client": func(b *Bouncer) {
			b.subscribeCaptcha = true
			b.captchaBound.Store(&captcha.Client{})
		},
	} {
		t.Run(name, func(t *testing.T) {
			b, _, store := newRetryAfterStreamBouncer(t, http.StatusTooManyRequests, nil)
			bindCaptcha(b)
			putRetryAfterTestDecision(store, decisionscope.CaptchaValue, "crowdsec", 600)
			assertRetryAfterBetween(t, serveRetryAfterRequest(b, http.MethodGet, "/"), 1, 600)
		})
	}
}

func TestRetryAfter_captchaChallengeHasNone(t *testing.T) {
	b, _, store := newRetryAfterStreamBouncer(t, http.StatusTooManyRequests, nil)
	bindTestCaptcha(b, testCaptchaClient(t, "/fast.js", "", "", nil))
	putRetryAfterTestDecision(store, decisionscope.CaptchaValue, "crowdsec", 600)
	rw := serveRetryAfterRequest(b, http.MethodGet, "/")
	if rw.Header().Get("X-Remediation") != "captcha:lapi:crowdsec" {
		t.Fatalf("X-Remediation %q, want the challenge page", rw.Header().Get("X-Remediation"))
	}
	assertNoRetryAfter(t, rw, rw.Code)
}

func TestRetryAfter_captchaRuleLosingToLapiBan(t *testing.T) {
	b, _, store := newRetryAfterStreamBouncer(t, http.StatusTooManyRequests, nil)
	bindTestCaptcha(b, testCaptchaClient(t, "/fast.js", "", "", nil))
	b.actionRules = mustPathAction(t, "challenge", "^/", httprule.ActionCaptcha)
	putRetryAfterTestDecision(store, decisionscope.BannedValue, "crowdsec", 3600)
	assertRetryAfterBetween(t, serveRetryAfterRequest(b, http.MethodGet, "/"), 1, 3600)
}

func TestRetryAfter_actionRuleBanHasNoneEvenWithStoredBan(t *testing.T) {
	b, _, store := newRetryAfterStreamBouncer(t, http.StatusTooManyRequests, nil)
	b.actionRules = mustPathAction(t, "deny", "^/", httprule.ActionBan)
	putRetryAfterTestDecision(store, decisionscope.BannedValue, "crowdsec", 3600)
	rw := serveRetryAfterRequest(b, http.MethodGet, "/")
	if rw.Header().Get("X-Remediation") != "ban:rules" {
		t.Fatalf("X-Remediation %q, want the action-rule ban", rw.Header().Get("X-Remediation"))
	}
	assertNoRetryAfter(t, rw, http.StatusTooManyRequests)
}

func TestRetryAfter_remapBanToCaptchaServedAsBan(t *testing.T) {
	b, _, store := newRetryAfterStreamBouncer(t, http.StatusTooManyRequests, map[string]map[string]string{"CAPI": {"ban": "captcha"}})
	putRetryAfterTestDecision(store, decisionscope.BannedValue, "CAPI", 3600)
	assertRetryAfterBetween(t, serveRetryAfterRequest(b, http.MethodGet, "/"), 1, 3600)
}

func TestRetryAfter_banKeptOnBypassCaptchaRequest(t *testing.T) {
	b, _, store := newRetryAfterStreamBouncer(t, http.StatusTooManyRequests, map[string]map[string]string{"CAPI": {"ban": "captcha"}})
	bindTestCaptcha(b, testCaptchaClient(t, "/fast.js", "", "", nil))
	b.actionRules = apiBypassCaptchaRules(t)
	putRetryAfterTestDecision(store, decisionscope.BannedValue, "CAPI", 3600)
	rw := serveRetryAfterRequest(b, http.MethodGet, "/api/items")
	if rw.Header().Get("X-Remediation") != "ban:lapi:CAPI" {
		t.Fatalf("X-Remediation %q, want the kept LAPI ban", rw.Header().Get("X-Remediation"))
	}
	assertRetryAfterBetween(t, rw, 1, 3600)
}

func TestRetryAfter_lapiFailureActionBanHasNone(t *testing.T) {
	b, _, _ := newRetryAfterStreamBouncer(t, http.StatusTooManyRequests, nil)
	bindTestLAPI(b, nil)
	b.subscribeLAPI = true
	assertNoRetryAfter(t, serveRetryAfterRequest(b, http.MethodGet, "/"), http.StatusTooManyRequests)
}

func TestRetryAfter_unhealthyStreamBanHasNone(t *testing.T) {
	b, _, _ := newRetryAfterStreamBouncer(t, http.StatusTooManyRequests, nil)
	b.loadedLAPI().SetStreamHealthyForTest(false)
	assertNoRetryAfter(t, serveRetryAfterRequest(b, http.MethodGet, "/"), http.StatusTooManyRequests)
}

func TestRetryAfter_cacheFailureBanHasNone(t *testing.T) {
	log := logger.New("ERROR", "")
	store := decisionstore.NewRedis(log, "127.0.0.1:1", nil, "", "", "retry-after")
	t.Cleanup(store.Close)
	lapiClient, err := lapi.New(&configuration.Config{
		LapiHTTPTimeoutSeconds: 10,
		LapiHost:               "127.0.0.1:1",
		LapiKey:                "test-key",
		LapiMode:               configuration.LiveMode,
		LapiPath:               "/",
		LapiScheme:             "http",
	}, log, "test", store, "retry-after-cache-fail", "retry-after-cache-fail")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(lapiClient.Close)
	b, _ := testRemapStreamBouncer(t, lapiClient, nil)
	lapiClient.SetCrowdsecModeForTest(configuration.LiveMode)
	b.remediationStatusCode = http.StatusTooManyRequests
	b.remediationCustomHeader = "X-Remediation"
	b.redisUnreachableBlock = true
	rw := serveRetryAfterRequest(b, http.MethodGet, "/")
	if rw.Header().Get("X-Remediation") != "ban:cache-fail" {
		t.Fatalf("X-Remediation %q, want the cache-failure ban", rw.Header().Get("X-Remediation"))
	}
	assertNoRetryAfter(t, rw, http.StatusTooManyRequests)
}

func TestRetryAfter_appsecBanWithStatus429HasNone(t *testing.T) {
	banTemplate, err := template.New("ban").Parse("banned")
	if err != nil {
		t.Fatal(err)
	}
	b, appsecServer := testBouncerWithAppsec(t, func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusForbidden)
		_, _ = w.Write([]byte(`{"action":"ban","http_status":429}`))
	}, banTemplate)
	defer appsecServer.Close()
	b.remediationStatusCode = http.StatusTooManyRequests
	rw := httptest.NewRecorder()
	continueAfterLAPIForTest(b, rw, testClientRequest(httptest.NewRequest(http.MethodGet, "http://example.com/login", nil), retryAfterTestIP))
	assertNoRetryAfter(t, rw, http.StatusTooManyRequests)
}

// newRetryAfterLiveBouncer is a live-mode router answering bans with 429 whose LAPI bans every queried IP for duration.
func newRetryAfterLiveBouncer(t *testing.T, duration string, defaultDecisionSeconds int64) *Bouncer {
	t.Helper()
	log := logger.New("ERROR", "")
	lapiServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("ip") == "" {
			_, _ = w.Write([]byte("null"))
			return
		}
		_ = json.NewEncoder(w).Encode([]lapi.Decision{{
			Value: r.URL.Query().Get("ip"), Type: "ban", Duration: duration, Origin: "crowdsec", Scope: "ip",
		}})
	}))
	t.Cleanup(lapiServer.Close)
	lapiURL, err := url.Parse(lapiServer.URL)
	if err != nil {
		t.Fatal(err)
	}
	lapiClient, err := lapi.New(&configuration.Config{
		LapiHTTPTimeoutSeconds: 10,
		LapiHost:               lapiURL.Host,
		LapiKey:                "test-key",
		LapiMode:               configuration.LiveMode,
		LapiPath:               "/",
		LapiScheme:             lapiURL.Scheme,
	}, log, "test", decisionstore.NewMemory(log), "retry-after-live", "retry-after-live")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(lapiClient.Close)
	b, _ := testRemapStreamBouncer(t, lapiClient, nil)
	lapiClient.SetCrowdsecModeForTest(configuration.LiveMode)
	b.remediationStatusCode = http.StatusTooManyRequests
	b.defaultDecisionSeconds = defaultDecisionSeconds
	return b
}

func TestRetryAfter_liveMissBanCarriesLapiDuration(t *testing.T) {
	b := newRetryAfterLiveBouncer(t, "90m", 60)
	assertRetryAfterBetween(t, serveRetryAfterRequest(b, http.MethodGet, "/"), 5399, 5400)
}

func TestRetryAfter_liveCachedBanReportsDecisionEndNotCacheEnd(t *testing.T) {
	b := newRetryAfterLiveBouncer(t, "4h", 60)
	serveRetryAfterRequest(b, http.MethodGet, "/")
	if decisionLeft, err := decisionLeftForTest(b.loadedLAPI().LookupRemediation(retryAfterTestIP, nil, nil)); err != nil || decisionLeft <= 60*time.Second {
		t.Fatalf("memo left %v err %v, want the memo to hold the 4h decision end", decisionLeft, err)
	}
	assertRetryAfterBetween(t, serveRetryAfterRequest(b, http.MethodGet, "/"), 61, 14400)
}

func TestRetryAfterSecondsRoundsUp(t *testing.T) {
	for decisionLeft, want := range map[time.Duration]string{
		time.Nanosecond:         "1",
		1200 * time.Millisecond: "2",
		3 * time.Second:         "3",
		time.Hour:               "3600",
	} {
		if got := retryAfterSeconds(decisionLeft); got != want {
			t.Errorf("retryAfterSeconds(%v) = %q, want %q", decisionLeft, got, want)
		}
	}
}

// decisionLeftForTest keeps the time left and error of one LookupRemediation.
func decisionLeftForTest(_, _ string, _ uint16, decisionLeft time.Duration, err error) (time.Duration, error) {
	return decisionLeft, err
}
