package lapi

import (
	"net"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pkg/decisionscope"
	logger "github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pkg/logger"
)

func TestStreamPutItemStoresLAPIKind(t *testing.T) {
	client, _ := NewTestClient(logger.New("ERROR", ""))
	stored, ok := client.streamPutItem(Decision{Type: "ban", Scope: "ip", Value: "203.0.113.10", Origin: "CAPI"}, 60)
	if !ok || stored.Kind != decisionscope.BannedValue || stored.Origin != "CAPI" {
		t.Fatalf("CAPI ban must store ban, got %#v ok=%v", stored, ok)
	}
	stored, ok = client.streamPutItem(Decision{Type: "captcha", Scope: "ip", Value: "203.0.113.13", Origin: "crowdsec"}, 60)
	if !ok || stored.Kind != decisionscope.CaptchaValue {
		t.Fatalf("captcha must store captcha, got %#v ok=%v", stored, ok)
	}
}

func TestHandleStreamCacheRangeStoresLAPIKind(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, _ *http.Request) {
		if _, err := rw.Write([]byte(`{"new":[{"id":1,"origin":"CAPI","type":"ban","scope":"Range","value":"10.0.0.0/8","duration":"1h","scenario":"scan"}],"deleted":[]}`)); err != nil {
			t.Errorf("stream stub write: %v", err)
		}
	}))
	t.Cleanup(server.Close)
	client := newTestStreamPoller(t, server)
	if err := client.handleStreamCache(); err != nil {
		t.Fatalf("range poll: %v", err)
	}
	kind, origin, _, err := client.LookupRemediation("10.1.2.3", net.ParseIP("10.1.2.3"), nil)
	if err != nil || kind != decisionscope.BannedValue || origin != "CAPI" {
		t.Fatalf("CAPI Range ban must store ban, got kind=%q origin=%q err=%v", kind, origin, err)
	}
}

func TestLiveLookupStoresLAPIKind(t *testing.T) {
	server := testLiveScopeLAPI(t, testLiveBanBody("Ip", "1.2.3.4"), nil)
	client := newTestLiveClient(t, server)
	kind, origin, err := client.LiveLookup("1.2.3.4", nil, 0)
	if err == nil {
		t.Fatal("active live remediation returns the banned error")
	}
	if kind != decisionscope.BannedValue || origin != "CAPI" {
		t.Fatalf("live CAPI ban must stay ban, got kind=%q origin=%q", kind, origin)
	}
}

func TestStrongestLiveDecisionUsesLAPIType(t *testing.T) {
	client := &Client{}
	picked := client.strongestLiveDecision([]Decision{
		{Type: "ban", Origin: "CAPI", Duration: "1h"},
		{Type: "ban", Origin: "crowdsec", Duration: "1h"},
	})
	if picked == nil || picked.Origin != "CAPI" {
		t.Fatalf("first LAPI ban wins, got %#v", picked)
	}
	captchaThenBan := client.strongestLiveDecision([]Decision{
		{Type: "captcha", Origin: "CAPI", Duration: "1h"},
		{Type: "ban", Origin: "crowdsec", Duration: "1h"},
	})
	if captchaThenBan == nil || captchaThenBan.Origin != "crowdsec" {
		t.Fatalf("raw ban still beats captcha, got %#v", captchaThenBan)
	}
}
