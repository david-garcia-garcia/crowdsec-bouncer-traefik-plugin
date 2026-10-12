package bouncer

import (
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"text/template"

	"github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pkg/appsec"
	"github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pkg/configuration"
	"github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pkg/httprule"
	"github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pkg/ip"
	logger "github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pkg/logger"
	"github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pkg/modsecurity"
)

func testModsecBouncer(t *testing.T, failMode string, rules []httprule.ActionRule) (*Bouncer, *bool) {
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
		modsecFailMode:           configuration.EffectiveModsecFailMode(failMode),
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

func blockingModsec(t *testing.T) *modsecurity.Client {
	t.Helper()
	sidecar := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.RawQuery, "../etc") {
			http.Error(w, "blocked", http.StatusForbidden)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(sidecar.Close)
	cfg := configuration.New()
	cfg.ModsecEnabled = true
	cfg.ModsecURL = sidecar.URL
	client, err := modsecurity.New(cfg, slog.Default(), "test", "n", "k")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(client.Close)
	return client
}

func TestServeHTTP_modsecAfterAppSecAllow(t *testing.T) {
	b, passed := testModsecBouncer(t, configuration.ModsecFailModeOpen, nil)
	bindTestModSec(b, blockingModsec(t))
	rw := httptest.NewRecorder()
	b.ServeHTTP(rw, testModsecRequest("/?test=../etc"))
	if *passed {
		t.Fatal("ModSec block must not reach origin")
	}
	if rw.Code != http.StatusForbidden {
		t.Fatalf("status=%d want 403", rw.Code)
	}
	if rw.Header().Get("X-Remediation") != "ban:modsec" {
		t.Fatalf("header=%q want ban:modsec", rw.Header().Get("X-Remediation"))
	}
}

func TestServeHTTP_modsecSkipDoesNotInspect(t *testing.T) {
	b, passed := testModsecBouncer(t, configuration.ModsecFailModeOpen, []httprule.ActionRule{{
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

func TestServeHTTP_missingModsecUsesFailMode(t *testing.T) {
	openB, openPassed := testModsecBouncer(t, configuration.ModsecFailModeOpen, nil)
	bindTestModSec(openB, nil)
	openB.subscribeModsec = true
	openB.ServeHTTP(httptest.NewRecorder(), testModsecRequest("/"))
	if !*openPassed {
		t.Fatal("missing ModSec fail-open must reach origin")
	}

	closeB, closePassed := testModsecBouncer(t, configuration.ModsecFailModeClose, nil)
	bindTestModSec(closeB, nil)
	closeB.subscribeModsec = true
	rw := httptest.NewRecorder()
	closeB.ServeHTTP(rw, testModsecRequest("/"))
	if *closePassed || rw.Code != http.StatusBadGateway {
		t.Fatalf("missing ModSec fail-close passed=%v status=%d", *closePassed, rw.Code)
	}
	if rw.Header().Get("X-Remediation") != "" {
		t.Fatal("fail-close 502 must omit remediation header")
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
	cfg.AppsecUnhealthyFailureThreshold = 1
	appsecClient, err := appsec.New(cfg, logger.New("ERROR", ""), "test", "n", "k")
	if err != nil {
		t.Fatal(err)
	}
	defer appsecClient.Close()
	req := testClientRequest(httptest.NewRequest(http.MethodGet, "http://example.com/", nil), "203.0.113.40")
	_, _ = appsecClient.Query(req, appsec.Policy{FailureAction: configuration.FailureActionBan})

	b, passed := testModsecBouncer(t, configuration.ModsecFailModeOpen, nil)
	bindTestAppSec(b, appsecClient)
	bindTestModSec(b, blockingModsec(t))
	rw := httptest.NewRecorder()
	b.ServeHTTP(rw, testModsecRequest("/?test=../etc"))
	if *passed {
		t.Fatal("AppSec skip must still let ModSec block")
	}
	if rw.Code != http.StatusForbidden {
		t.Fatalf("status=%d want 403", rw.Code)
	}
	if rw.Header().Get("X-Remediation") != "ban:modsec" {
		t.Fatalf("header=%q want ban:modsec", rw.Header().Get("X-Remediation"))
	}
	if hits != 1 {
		t.Fatalf("AppSec hits=%d want 1", hits)
	}
}
