package crowdsecconnection

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	cache "github.com/maxlerebourg/crowdsec-bouncer-traefik-plugin/pkg/cache"
	"github.com/maxlerebourg/crowdsec-bouncer-traefik-plugin/pkg/configuration"
	"github.com/maxlerebourg/crowdsec-bouncer-traefik-plugin/pkg/decisionscope"
	logger "github.com/maxlerebourg/crowdsec-bouncer-traefik-plugin/pkg/logger"
)

func Test_appsecQuery_failureActionOn500(t *testing.T) {
	appsecServer := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, _ *http.Request) {
		rw.WriteHeader(http.StatusInternalServerError)
	}))
	defer appsecServer.Close()
	appsecURL, _ := url.Parse(appsecServer.URL)
	conn := appsecConn(appsecURL, appsecServer.Client())
	req := httptest.NewRequest(http.MethodGet, "http://localhost/", nil)

	decision, err := conn.AppsecQuery("1.2.3.4", req, AppsecPolicy{FailureAction: configuration.FailureActionBan})
	if err == nil {
		t.Fatal("ban on 500 expected an error")
	}
	if decision != nil {
		t.Fatalf("ban on 500 returned decision %#v", decision)
	}

	decision, err = conn.AppsecQuery("1.2.3.4", req, AppsecPolicy{FailureAction: configuration.FailureActionPassthrough})
	if err != nil {
		t.Fatalf("passthrough on 500: %v", err)
	}
	if decision == nil || decision.Action != AppsecActionAllow {
		t.Fatalf("passthrough on 500 want allow, got %#v", decision)
	}

	_, err = conn.AppsecQuery("1.2.3.4", req, AppsecPolicy{FailureAction: configuration.FailureActionCaptcha})
	if !errors.Is(err, ErrFailureCaptcha) {
		t.Fatalf("captcha on 500 want ErrFailureCaptcha, got %v", err)
	}
}

func Test_appsecQuery_failureActionOnUnreachable(t *testing.T) {
	appsecServer := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, _ *http.Request) {
		rw.WriteHeader(http.StatusOK)
	}))
	appsecURL, _ := url.Parse(appsecServer.URL)
	conn := appsecConn(appsecURL, appsecServer.Client())
	appsecServer.Close()
	req := httptest.NewRequest(http.MethodGet, "http://localhost/", nil)

	_, err := conn.AppsecQuery("1.2.3.4", req, AppsecPolicy{FailureAction: configuration.FailureActionBan})
	if err == nil {
		t.Fatal("ban on unreachable expected an error")
	}

	decision, err := conn.AppsecQuery("1.2.3.4", req, AppsecPolicy{FailureAction: configuration.FailureActionPassthrough})
	if err != nil {
		t.Fatalf("passthrough on unreachable: %v", err)
	}
	if decision == nil || decision.Action != AppsecActionAllow {
		t.Fatalf("passthrough on unreachable want allow, got %#v", decision)
	}
}

func Test_liveLookup_lapiErrorIsNotABan(t *testing.T) {
	lapi := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, _ *http.Request) {
		rw.WriteHeader(http.StatusInternalServerError)
	}))
	defer lapi.Close()
	lapiURL, _ := url.Parse(lapi.URL)
	cacheClient := &cache.Client{}
	cacheClient.New(logger.New("ERROR", ""), false, "", nil, "", "", "")
	conn := &CrowdsecConnection{
		crowdsecScheme: lapiURL.Scheme,
		crowdsecHost:   lapiURL.Host,
		crowdsecPath:   "/",
		crowdsecMode:   configuration.LiveMode,
		httpClient:     lapi.Client(),
		cacheClient:    cacheClient,
		log:            logger.New("ERROR", ""),
	}
	value, err := conn.LiveLookup("1.2.3.4", nil)
	if err == nil {
		t.Fatal("live LAPI 500 expected an error")
	}
	if decisionscope.IsActiveRemediation(value) {
		t.Fatalf("live LAPI error must not look like a ban, got %q", value)
	}
}
