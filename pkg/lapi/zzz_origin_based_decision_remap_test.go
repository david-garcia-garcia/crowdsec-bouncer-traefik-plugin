package lapi

import (
	"net"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pkg/decisionscope"
	logger "github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pkg/logger"
)

func TestOriginBasedDecisionRemapEdges(t *testing.T) {
	table := map[string]map[string]string{
		"CAPI":                 {"ban": decisionscope.CaptchaValue},
		"lists":                {"ban": decisionscope.CaptchaValue},
		"lists:firehol_level1": {"ban": decisionscope.CaptchaValue},
	}
	tests := []struct {
		origin string
		want   bool
	}{
		{origin: "CAPI", want: true},
		{origin: "lists", want: true},
		{origin: "lists:tor-exit", want: true},
		{origin: "lists:firehol_level1", want: true},
		{origin: "cscli", want: false},
		{origin: "crowdsec", want: false},
		{origin: "", want: false},
		{origin: "capi", want: false},
	}
	for _, tc := range tests {
		got := originBasedDecisionRemapEdges(tc.origin, table) != nil
		if got != tc.want {
			t.Errorf("originBasedDecisionRemapEdges(%q) present=%v, want %v", tc.origin, got, tc.want)
		}
	}
	if originBasedDecisionRemapEdges("CAPI", nil) != nil {
		t.Fatal("empty table must not match")
	}
	oneList := map[string]map[string]string{"lists:firehol_level1": {"ban": decisionscope.CaptchaValue}}
	if originBasedDecisionRemapEdges("lists:tor-exit", oneList) != nil {
		t.Fatal("lists:firehol_level1 must not match lists:tor-exit")
	}
	if originBasedDecisionRemapEdges("lists:firehol_level1", oneList) == nil {
		t.Fatal("lists:firehol_level1 must match itself")
	}
}

func TestCopyOriginBasedDecisionRemapTrimsBlanks(t *testing.T) {
	got := copyOriginBasedDecisionRemap(map[string]map[string]string{
		" CAPI ": {" Ban ": " Captcha "},
		"":       {"ban": "captcha"},
		"cscli":  {"ban": "ban"},
	})
	if len(got) != 1 || got["CAPI"]["ban"] != decisionscope.CaptchaValue {
		t.Fatalf("got %#v", got)
	}
	if copyOriginBasedDecisionRemap(nil) != nil {
		t.Fatal("nil in must stay nil")
	}
	pass := copyOriginBasedDecisionRemap(map[string]map[string]string{"crowdsec": {"captcha": "pass"}})
	kind, ok := pass["crowdsec"]["captcha"]
	if !ok || kind != "" {
		t.Fatalf("pass must store empty kind, got %#v", pass)
	}
}

func TestRemediationKind(t *testing.T) {
	client := &Client{originBasedDecisionRemap: copyOriginBasedDecisionRemap(map[string]map[string]string{
		"CAPI":                 {"ban": "captcha"},
		"lists:firehol_level1": {"ban": "captcha"},
	})}
	if got := client.remediationKind("ban", "CAPI"); got != decisionscope.CaptchaValue {
		t.Fatalf("CAPI ban kind %q", got)
	}
	if got := client.remediationKind("ban", MetricsOrigin("lists", "firehol_level1")); got != decisionscope.CaptchaValue {
		t.Fatalf("listed list ban kind %q", got)
	}
	if got := client.remediationKind("ban", MetricsOrigin("lists", "tor-exit")); got != decisionscope.BannedValue {
		t.Fatalf("other list ban kind %q", got)
	}
	if got := client.remediationKind("ban", "cscli"); got != decisionscope.BannedValue {
		t.Fatalf("cscli ban kind %q", got)
	}
	if got := client.remediationKind("captcha", "CAPI"); got != decisionscope.CaptchaValue {
		t.Fatalf("captcha type kind %q", got)
	}
	if got := client.remediationKind("mfa", "CAPI"); got != "" {
		t.Fatalf("unknown type kind %q", got)
	}
	empty := &Client{}
	if got := empty.remediationKind("ban", "CAPI"); got != decisionscope.BannedValue {
		t.Fatalf("empty remap CAPI ban kind %q", got)
	}
}

func TestRemediationKind_OneHopDoesNotChain(t *testing.T) {
	client := &Client{originBasedDecisionRemap: copyOriginBasedDecisionRemap(map[string]map[string]string{
		"CAPI": {"ban": "captcha", "captcha": "pass"},
	})}
	if got := client.remediationKind("ban", "CAPI"); got != decisionscope.CaptchaValue {
		t.Fatalf("ban must stay captcha, not chain to pass, got %q", got)
	}
	if got := client.remediationKind("captcha", "CAPI"); got != "" {
		t.Fatalf("captcha must remap to pass, got %q", got)
	}
}

func TestRemediationKind_CaptchaToPass(t *testing.T) {
	client := &Client{originBasedDecisionRemap: copyOriginBasedDecisionRemap(map[string]map[string]string{
		"crowdsec": {"captcha": "pass"},
	})}
	if got := client.remediationKind("captcha", "crowdsec"); got != "" {
		t.Fatalf("captcha pass kind %q", got)
	}
	if got := client.remediationKind("ban", "crowdsec"); got != decisionscope.BannedValue {
		t.Fatalf("ban must stay ban, got %q", got)
	}
}

func TestStreamPutItemOriginBasedDecisionRemap(t *testing.T) {
	client, _ := NewTestClient(logger.New("ERROR", ""))
	client.originBasedDecisionRemap = copyOriginBasedDecisionRemap(map[string]map[string]string{
		"CAPI":                 {"ban": "captcha"},
		"lists:firehol_level1": {"ban": "captcha"},
		"crowdsec":             {"captcha": "pass"},
	})
	stored, ok := client.streamPutItem(Decision{Type: "ban", Scope: "ip", Value: "203.0.113.10", Origin: "CAPI"}, 60)
	if !ok || stored.Kind != decisionscope.CaptchaValue || stored.Origin != "CAPI" {
		t.Fatalf("CAPI put %#v ok=%v", stored, ok)
	}
	stored, ok = client.streamPutItem(Decision{Type: "ban", Scope: "ip", Value: "203.0.113.11", Origin: "lists", Scenario: "firehol_level1"}, 60)
	if !ok || stored.Kind != decisionscope.CaptchaValue || stored.Origin != "lists:firehol_level1" {
		t.Fatalf("list put %#v ok=%v", stored, ok)
	}
	stored, ok = client.streamPutItem(Decision{Type: "ban", Scope: "ip", Value: "203.0.113.12", Origin: "cscli"}, 60)
	if !ok || stored.Kind != decisionscope.BannedValue {
		t.Fatalf("cscli put %#v ok=%v", stored, ok)
	}
	_, ok = client.streamPutItem(Decision{Type: "captcha", Scope: "ip", Value: "203.0.113.13", Origin: "crowdsec"}, 60)
	if ok {
		t.Fatal("captcha→pass must skip store")
	}
}

func TestStrongestLiveDecisionOriginBasedDecisionRemap(t *testing.T) {
	client := &Client{originBasedDecisionRemap: copyOriginBasedDecisionRemap(map[string]map[string]string{
		"CAPI": {"ban": "captcha"},
	})}
	items := []Decision{
		{Type: "ban", Origin: "CAPI", Duration: "1h"},
		{Type: "ban", Origin: "crowdsec", Duration: "1h"},
	}
	picked := client.strongestLiveDecision(items)
	if picked == nil || picked.Origin != "crowdsec" {
		t.Fatalf("want crowdsec ban, got %#v", picked)
	}
	onlyCAPI := client.strongestLiveDecision([]Decision{{Type: "ban", Origin: "CAPI", Duration: "1h"}})
	if onlyCAPI == nil || onlyCAPI.Origin != "CAPI" {
		t.Fatalf("want CAPI fallback, got %#v", onlyCAPI)
	}
	if client.remediationKind(onlyCAPI.Type, MetricsOrigin(onlyCAPI.Origin, onlyCAPI.Scenario)) != decisionscope.CaptchaValue {
		t.Fatal("listed-only pick must still remap to captcha")
	}
	client.originBasedDecisionRemap = copyOriginBasedDecisionRemap(map[string]map[string]string{
		"crowdsec": {"captcha": "pass"},
	})
	passOnly := client.strongestLiveDecision([]Decision{{Type: "captcha", Origin: "crowdsec", Duration: "1h"}})
	if passOnly != nil {
		t.Fatalf("pass-only live pick must be nil, got %#v", passOnly)
	}
}

func TestHandleStreamCacheRangeOriginBasedDecisionRemap(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, _ *http.Request) {
		if _, err := rw.Write([]byte(`{"new":[{"id":1,"origin":"CAPI","type":"ban","scope":"Range","value":"10.0.0.0/8","duration":"1h","scenario":"scan"}],"deleted":[]}`)); err != nil {
			t.Errorf("stream stub write: %v", err)
		}
	}))
	t.Cleanup(server.Close)
	client := newTestStreamPoller(t, server)
	client.originBasedDecisionRemap = copyOriginBasedDecisionRemap(map[string]map[string]string{
		"CAPI": {"ban": "captcha"},
	})
	if err := client.handleStreamCache(); err != nil {
		t.Fatalf("range poll: %v", err)
	}
	kind, origin, _, err := client.LookupRemediation("10.1.2.3", net.ParseIP("10.1.2.3"), nil)
	if err != nil || kind != decisionscope.CaptchaValue || origin != "CAPI" {
		t.Fatalf("listed Range ban must store captcha, got kind=%q origin=%q err=%v", kind, origin, err)
	}
}

func TestLiveLookupOriginBasedDecisionRemap(t *testing.T) {
	server := testLiveScopeLAPI(t, testLiveBanBody("Ip", "1.2.3.4"), nil)
	client := newTestLiveClient(t, server)
	client.originBasedDecisionRemap = copyOriginBasedDecisionRemap(map[string]map[string]string{
		"CAPI": {"ban": "captcha"},
	})
	kind, origin, err := client.LiveLookup("1.2.3.4", nil, 0)
	if err == nil {
		t.Fatal("active live remediation returns the banned error")
	}
	if kind != decisionscope.CaptchaValue || origin != "CAPI" {
		t.Fatalf("listed live ban must remap to captcha, got kind=%q origin=%q", kind, origin)
	}
}
