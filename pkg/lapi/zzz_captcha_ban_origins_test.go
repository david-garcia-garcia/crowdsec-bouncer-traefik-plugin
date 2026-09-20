package lapi

import (
	"testing"

	"github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pkg/decisionscope"
	logger "github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pkg/logger"
)

func TestCaptchaBanOriginListed(t *testing.T) {
	listed := []string{"CAPI", "lists", "lists:firehol_level1"}
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
		if got := captchaBanOriginListed(tc.origin, listed); got != tc.want {
			t.Errorf("captchaBanOriginListed(%q) = %v, want %v", tc.origin, got, tc.want)
		}
	}
	if captchaBanOriginListed("CAPI", nil) {
		t.Fatal("empty list must not match")
	}
	oneList := []string{"lists:firehol_level1"}
	if captchaBanOriginListed("lists:tor-exit", oneList) {
		t.Fatal("lists:firehol_level1 must not match lists:tor-exit")
	}
	if !captchaBanOriginListed("lists:firehol_level1", oneList) {
		t.Fatal("lists:firehol_level1 must match itself")
	}
}

func TestCopyCaptchaBanOriginsTrimsBlanks(t *testing.T) {
	got := copyCaptchaBanOrigins([]string{" CAPI ", "", "lists:firehol_level1"})
	if len(got) != 2 || got[0] != "CAPI" || got[1] != "lists:firehol_level1" {
		t.Fatalf("got %#v", got)
	}
	if copyCaptchaBanOrigins(nil) != nil {
		t.Fatal("nil in must stay nil")
	}
}

func TestRemediationKindForOrigin(t *testing.T) {
	client := &Client{captchaBanOrigins: []string{"CAPI", "lists:firehol_level1"}}
	if got := client.remediationKindForOrigin("ban", "CAPI"); got != decisionscope.CaptchaValue {
		t.Fatalf("CAPI ban kind %q", got)
	}
	if got := client.remediationKindForOrigin("ban", MetricsOrigin("lists", "firehol_level1")); got != decisionscope.CaptchaValue {
		t.Fatalf("listed list ban kind %q", got)
	}
	if got := client.remediationKindForOrigin("ban", MetricsOrigin("lists", "tor-exit")); got != decisionscope.BannedValue {
		t.Fatalf("other list ban kind %q", got)
	}
	if got := client.remediationKindForOrigin("ban", "cscli"); got != decisionscope.BannedValue {
		t.Fatalf("cscli ban kind %q", got)
	}
	if got := client.remediationKindForOrigin("captcha", "CAPI"); got != decisionscope.CaptchaValue {
		t.Fatalf("captcha type kind %q", got)
	}
	if got := client.remediationKindForOrigin("mfa", "CAPI"); got != "" {
		t.Fatalf("unknown type kind %q", got)
	}
	empty := &Client{}
	if got := empty.remediationKindForOrigin("ban", "CAPI"); got != decisionscope.BannedValue {
		t.Fatalf("empty list CAPI ban kind %q", got)
	}
}

func TestStreamPutItemCaptchaBanOrigins(t *testing.T) {
	client, _ := NewTestClient(logger.New("ERROR", ""))
	client.captchaBanOrigins = []string{"CAPI", "lists:firehol_level1"}
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
}

func TestStrongestLiveDecisionCaptchaBanOrigins(t *testing.T) {
	client := &Client{captchaBanOrigins: []string{"CAPI"}}
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
	if client.remediationKindForOrigin(onlyCAPI.Type, MetricsOrigin(onlyCAPI.Origin, onlyCAPI.Scenario)) != decisionscope.CaptchaValue {
		t.Fatal("listed-only pick must still remap to captcha")
	}
}
