package bouncer

import (
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"text/template"

	"github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pkg/admission"
	"github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pkg/appsec"
	"github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pkg/configuration"
	"github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pkg/httprule"
	"github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pkg/ip"
	logger "github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pkg/logger"
	"github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pkg/modsecurity"
)

func testModsecBouncer(t *testing.T, failureAction string, rules []httprule.ActionRule) (*Bouncer, *bool) {
	t.Helper()
	log := logger.New("ERROR", "")
	clientChecker, err := ip.NewChecker(log, nil)
	if err != nil {
		t.Fatal(err)
	}
	banTemplate, err := template.New("ban").Parse("banned {{ .RemediationReason }}")
	if err != nil {
		t.Fatal(err)
	}
	passed := false
	set, compileErr := httprule.NewActionSet(rules)
	if compileErr != nil {
		t.Fatal(compileErr)
	}
	b := &Bouncer{
		enabled:                  true,
		actionRules:              set,
		forwardedHeadersInsecure: true,
		forwardedCustomHeader:    "X-Forwarded-For",
		trustedClients:           &ip.PoolStrategy{Checker: clientChecker},
		log:                      log,
		modsecFailureAction:      configuration.EffectiveModsecFailureAction(failureAction),
		remediationCustomHeader:  "X-Remediation",
		remediationStatusCode:    http.StatusForbidden,
		banTemplate:              banTemplate,
		banTemplateContentType:   "text/html; charset=utf-8",
		next: http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
			passed = true
		}),
	}
	return b, &passed
}

func testModsecRequest(path string) *http.Request {
	req := httptest.NewRequest(http.MethodGet, "http://example.com"+path, nil)
	req.RemoteAddr = "127.0.0.1:1"
	req.Header.Set("X-Forwarded-For", "203.0.113.40")
	return req
}

// modsecWithSidecar binds a ModSec client to a sidecar handler, with an optional backoff period.
func modsecWithSidecar(t *testing.T, handler http.HandlerFunc, backoffSecs int64) *modsecurity.Client {
	t.Helper()
	sidecar := httptest.NewServer(handler)
	t.Cleanup(sidecar.Close)
	cfg := configuration.New()
	cfg.ModsecEnabled = true
	cfg.ModsecURL = sidecar.URL
	cfg.ModsecBodyLimit = 8
	cfg.ModsecUnhealthyBackOffPeriodSecs = backoffSecs
	client, err := modsecurity.New(cfg, slog.Default(), "test", "n", "k")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(client.Close)
	return client
}

func blockingModsec(t *testing.T) *modsecurity.Client {
	t.Helper()
	return modsecWithSidecar(t, func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.RawQuery, "../etc") {
			http.Error(w, "crs-page", http.StatusForbidden)
		}
	}, 0)
}

func failingModsec(t *testing.T, backoffSecs int64, hits *int) *modsecurity.Client {
	t.Helper()
	return modsecWithSidecar(t, func(w http.ResponseWriter, _ *http.Request) {
		*hits++
		http.Error(w, "down", http.StatusServiceUnavailable)
	}, backoffSecs)
}

func TestServeHTTP_modsecBlockRelaysSidecarPage(t *testing.T) {
	b, passed := testModsecBouncer(t, configuration.FailureActionPassthrough, nil)
	bindTestModSec(b, blockingModsec(t))
	rw := httptest.NewRecorder()
	b.ServeHTTP(rw, testModsecRequest("/?test=../etc"))
	if *passed {
		t.Fatal("ModSec block must not reach origin")
	}
	if rw.Code != http.StatusForbidden || !strings.Contains(rw.Body.String(), "crs-page") {
		t.Fatalf("status=%d body=%q want the sidecar 403 page", rw.Code, rw.Body.String())
	}
	if rw.Header().Get("X-Remediation") != "ban:modsec" {
		t.Fatalf("header=%q want ban:modsec", rw.Header().Get("X-Remediation"))
	}
}

func TestServeHTTP_modsecAllowReachesOrigin(t *testing.T) {
	b, passed := testModsecBouncer(t, configuration.FailureActionBan, nil)
	bindTestModSec(b, blockingModsec(t))
	rw := httptest.NewRecorder()
	b.ServeHTTP(rw, testModsecRequest("/clean"))
	if !*passed || rw.Header().Get("X-Remediation") != "" {
		t.Fatalf("allow must reach origin without a remediation header, passed=%v header=%q", *passed, rw.Header().Get("X-Remediation"))
	}
}

func TestServeHTTP_modsecSkipDoesNotInspect(t *testing.T) {
	b, passed := testModsecBouncer(t, configuration.FailureActionPassthrough, []httprule.ActionRule{{
		Name:   "skip-waf",
		Action: []string{httprule.ActionBypassModsec},
		Rule:   httprule.Rule{Path: "^/skip$"},
	}})
	bindTestModSec(b, blockingModsec(t))
	rw := httptest.NewRecorder()
	b.ServeHTTP(rw, testModsecRequest("/skip?test=../etc"))
	if !*passed {
		t.Fatal("bypassModsec must continue to origin")
	}
	if rw.Header().Get("X-Remediation") != "" {
		t.Fatal("skip must omit remediation header")
	}
}

func TestServeHTTP_missingModsecUsesFailureAction(t *testing.T) {
	passB, passPassed := testModsecBouncer(t, configuration.FailureActionPassthrough, nil)
	bindTestModSec(passB, nil)
	passB.subscribeModsec = true
	passB.ServeHTTP(httptest.NewRecorder(), testModsecRequest("/"))
	if !*passPassed {
		t.Fatal("missing ModSec with passthrough must reach origin")
	}

	banB, banPassed := testModsecBouncer(t, configuration.FailureActionBan, nil)
	bindTestModSec(banB, nil)
	banB.subscribeModsec = true
	rw := httptest.NewRecorder()
	banB.ServeHTTP(rw, testModsecRequest("/"))
	assertModsecFailureBan(t, rw, *banPassed)
}

func TestServeHTTP_modsecSidecarDownUsesFailureAction(t *testing.T) {
	hits := 0
	passB, passPassed := testModsecBouncer(t, configuration.FailureActionPassthrough, nil)
	bindTestModSec(passB, failingModsec(t, 0, &hits))
	passRW := httptest.NewRecorder()
	passB.ServeHTTP(passRW, testModsecRequest("/"))
	if !*passPassed || passRW.Header().Get("X-Remediation") != "" || strings.Contains(passRW.Body.String(), "down") {
		t.Fatalf("passthrough must reach origin untouched, passed=%v header=%q", *passPassed, passRW.Header().Get("X-Remediation"))
	}

	banB, banPassed := testModsecBouncer(t, configuration.FailureActionBan, nil)
	bindTestModSec(banB, failingModsec(t, 0, &hits))
	banRW := httptest.NewRecorder()
	banB.ServeHTTP(banRW, testModsecRequest("/"))
	assertModsecFailureBan(t, banRW, *banPassed)
}

// After the gate trips, ModSec is skipped like AppSec: no sidecar call and no failure action.
func TestServeHTTP_modsecGateSkipPassesWithoutFailureAction(t *testing.T) {
	hits := 0
	b, passed := testModsecBouncer(t, configuration.FailureActionBan, nil)
	bindTestModSec(b, failingModsec(t, 30, &hits))
	for i := range admission.TripFailures {
		rw := httptest.NewRecorder()
		*passed = false
		b.ServeHTTP(rw, testModsecRequest("/"))
		if *passed || rw.Header().Get("X-Remediation") != "ban:modsec-failure" {
			t.Fatalf("failure #%d before the trip must apply ban, passed=%v header=%q", i+1, *passed, rw.Header().Get("X-Remediation"))
		}
	}
	*passed = false
	rw := httptest.NewRecorder()
	b.ServeHTTP(rw, testModsecRequest("/"))
	if !*passed || rw.Header().Get("X-Remediation") != "" {
		t.Fatalf("gate skip must reach origin without a remediation header, passed=%v header=%q", *passed, rw.Header().Get("X-Remediation"))
	}
	if hits != admission.TripFailures {
		t.Fatalf("sidecar hits=%d want %d", hits, admission.TripFailures)
	}
}

func TestServeHTTP_modsecBodyOverLimitIs413(t *testing.T) {
	b, passed := testModsecBouncer(t, configuration.FailureActionPassthrough, nil)
	bindTestModSec(b, blockingModsec(t))
	req := httptest.NewRequest(http.MethodPost, "http://example.com/", strings.NewReader("123456789"))
	req.RemoteAddr = "127.0.0.1:1"
	rw := httptest.NewRecorder()
	b.ServeHTTP(rw, req)
	if *passed || rw.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("passed=%v status=%d want 413", *passed, rw.Code)
	}
}

func TestServeHTTP_appsecGateSkipStillRunsModsec(t *testing.T) {
	hits := 0
	appsecSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		hits++
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer appsecSrv.Close()
	u, _ := url.Parse(appsecSrv.URL)
	cfg := configuration.New()
	cfg.AppsecEnabled = true
	cfg.AppsecHost = u.Host
	cfg.AppsecScheme = "http"
	cfg.AppsecTLSInsecureVerify = true
	cfg.AppsecUnhealthyBackOffPeriodSecs = 30
	appsecClient, err := appsec.New(cfg, logger.New("ERROR", ""), "test", "n", "k")
	if err != nil {
		t.Fatal(err)
	}
	defer appsecClient.Close()
	for range admission.TripFailures {
		req := testClientRequest(httptest.NewRequest(http.MethodGet, "http://example.com/", nil), "203.0.113.40")
		_, _ = appsecClient.Query(req, appsec.Policy{FailureAction: configuration.FailureActionBan})
	}

	b, passed := testModsecBouncer(t, configuration.FailureActionPassthrough, nil)
	b.appsecFailureAction = configuration.FailureActionBan
	bindTestAppSec(b, appsecClient)
	bindTestModSec(b, blockingModsec(t))
	rw := httptest.NewRecorder()
	b.ServeHTTP(rw, testModsecRequest("/?test=../etc"))
	if *passed {
		t.Fatal("AppSec skip must still let ModSec block")
	}
	if rw.Code != http.StatusForbidden || rw.Header().Get("X-Remediation") != "ban:modsec" {
		t.Fatalf("status=%d header=%q want 403 ban:modsec", rw.Code, rw.Header().Get("X-Remediation"))
	}
	if hits != admission.TripFailures {
		t.Fatalf("AppSec hits=%d want %d", hits, admission.TripFailures)
	}
}

func assertModsecFailureBan(t *testing.T, rw *httptest.ResponseRecorder, passed bool) {
	t.Helper()
	if passed {
		t.Fatal("ban failure action must not reach origin")
	}
	if rw.Code != http.StatusForbidden {
		t.Fatalf("status=%d want 403", rw.Code)
	}
	if rw.Header().Get("X-Remediation") != "ban:modsec-failure" {
		t.Fatalf("header=%q want ban:modsec-failure", rw.Header().Get("X-Remediation"))
	}
	if rw.Body.String() != "banned "+configuration.ReasonMODSEC {
		t.Fatalf("body=%q want the ban template with reason %s", rw.Body.String(), configuration.ReasonMODSEC)
	}
}
