package lapi

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

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
		cacheClient:    cacheClient,
		log:            logger.New("ERROR", ""),
	}
	attachTestTransport(client, lapi.Client(), "")
	value, err := client.LiveLookup("1.2.3.4", nil, 0)
	if err == nil {
		t.Fatal("live LAPI 500 expected an error")
	}
	if decisionscope.IsActiveRemediation(value) {
		t.Fatalf("live LAPI error must not look like a ban, got %q", value)
	}
}

func TestLiveLookup_PerRouterTTLLastWrites(t *testing.T) {
	lapi := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, _ *http.Request) {
		_, _ = rw.Write([]byte("[]"))
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
		cacheClient:    cacheClient,
		log:            logger.New("ERROR", ""),
	}
	attachTestTransport(client, lapi.Client(), "")
	if _, err := client.LiveLookup("1.2.3.4", nil, 60); err != nil {
		t.Fatal(err)
	}
	if _, err := client.LiveLookup("1.2.3.4", nil, 1); err != nil {
		t.Fatal(err)
	}
	if _, err := cacheClient.Get("1.2.3.4"); err != nil {
		t.Fatal("last write must still be cached immediately")
	}
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if _, err := cacheClient.Get("1.2.3.4"); err != nil {
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatal("last-written 1s live TTL did not expire")
}
