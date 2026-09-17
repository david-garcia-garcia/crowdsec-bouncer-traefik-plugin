package lapi

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	cache "github.com/maxlerebourg/crowdsec-bouncer-traefik-plugin/pkg/cache"
	"github.com/maxlerebourg/crowdsec-bouncer-traefik-plugin/pkg/configuration"
	"github.com/maxlerebourg/crowdsec-bouncer-traefik-plugin/pkg/decisionscope"
	logger "github.com/maxlerebourg/crowdsec-bouncer-traefik-plugin/pkg/logger"
)

func Test_liveLookup_lapiErrorIsNotABan(t *testing.T) {
	lapi := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, _ *http.Request) {
		rw.WriteHeader(http.StatusInternalServerError)
	}))
	defer lapi.Close()
	lapiURL, _ := url.Parse(lapi.URL)
	cacheClient := &cache.Client{}
	cacheClient.New(logger.New("ERROR", ""), false, "", nil, "", "", "")
	client := &Client{
		crowdsecScheme: lapiURL.Scheme,
		crowdsecHost:   lapiURL.Host,
		crowdsecPath:   "/",
		crowdsecMode:   configuration.LiveMode,
		httpClient:     lapi.Client(),
		cacheClient:    cacheClient,
		log:            logger.New("ERROR", ""),
	}
	value, err := client.LiveLookup("1.2.3.4", nil)
	if err == nil {
		t.Fatal("live LAPI 500 expected an error")
	}
	if decisionscope.IsActiveRemediation(value) {
		t.Fatalf("live LAPI error must not look like a ban, got %q", value)
	}
}
