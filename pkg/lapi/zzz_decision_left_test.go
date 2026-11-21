package lapi

import (
	"net"
	"testing"
	"time"

	"github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pkg/decisionscope"
	"github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pkg/decisionstore"
	logger "github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pkg/logger"
)

// testLiveDecisionBody is a one-decision LAPI answer for scope and value with decisionType and duration.
func testLiveDecisionBody(decisionType, scope, value, duration string) string {
	return `[{"id":1,"origin":"crowdsec","type":"` + decisionType + `","scope":"` + scope + `","value":"` + value + `","duration":"` + duration + `","scenario":"test"}]`
}

func TestStreamPutItemCarriesDecisionDuration(t *testing.T) {
	client, _ := NewTestClient(logger.New("ERROR", ""))
	stored, ok := client.streamPutItem(Decision{Type: "ban", Scope: "ip", Value: "203.0.113.10", Origin: "crowdsec"}, 3600)
	if !ok || stored.DurationSec != 3600 || stored.DecisionDurationSec != 3600 {
		t.Fatalf("stream put %#v ok=%v, want TTL and decision duration 3600", stored, ok)
	}
}

func TestLiveMemoKeepsDecisionDurationPastCacheTTL(t *testing.T) {
	client := newTestLiveClient(t, testLiveScopeLAPI(t, testLiveDecisionBody("ban", "Ip", "1.2.3.4", "4h"), nil))
	kind, _, decisionLeft, _ := client.LiveLookup("1.2.3.4", nil, 60)
	if kind != decisionscope.BannedValue || decisionLeft != 4*time.Hour {
		t.Fatalf("live lookup kind %q left %v, want ban with 4h", kind, decisionLeft)
	}
	slot := client.decisionStore.PublishedMemoryMapForTest()["1.2.3.4"]
	now := decisionstore.ElapsedNow()
	if slot.ExpiresAt > now+60 || slot.DecisionEnd < now+14399 {
		t.Fatalf("memo ExpiresAt %d DecisionEnd %d at now %d, want TTL 60 and decision 14400", slot.ExpiresAt, slot.DecisionEnd, now)
	}
	memoKind, _, _, memoLeft, err := client.LookupRemediation("1.2.3.4", net.ParseIP("1.2.3.4"), nil)
	if err != nil || memoKind != decisionscope.BannedValue || memoLeft <= 60*time.Second {
		t.Fatalf("memo lookup kind %q left %v err %v, want ban with left > 60s", memoKind, memoLeft, err)
	}
}

func TestLiveLookupHeaderBanOverIPCaptchaReturnsHeaderDuration(t *testing.T) {
	client := newTestLiveClient(t, testLiveScopeLAPI(t, testLiveDecisionBody("captcha", "Ip", "1.2.3.4", "10m"), map[string]string{
		"country": testLiveDecisionBody("ban", "country", "FR", "2h"),
	}))
	kind, _, decisionLeft, _ := client.LiveLookup("1.2.3.4", map[string]string{"country": "FR"}, 60)
	if kind != decisionscope.BannedValue || decisionLeft != 2*time.Hour {
		t.Fatalf("live lookup kind %q left %v, want the Country ban's 2h", kind, decisionLeft)
	}
	headerKind, _, _, headerLeft, err := client.LookupRemediation("203.0.113.99", net.ParseIP("203.0.113.99"), map[string]string{decisionscope.ScopeCountry: "FR"})
	if err != nil || headerKind != decisionscope.BannedValue || headerLeft <= 60*time.Second {
		t.Fatalf("header memo kind %q left %v err %v, want ban with left > 60s", headerKind, headerLeft, err)
	}
}

func TestLiveLookupCleanOrFailedHasNoDecisionLeft(t *testing.T) {
	for name, ipBody := range map[string]string{"clean": "null", "failed": ""} {
		t.Run(name, func(t *testing.T) {
			client := newTestLiveClient(t, testLiveScopeLAPI(t, ipBody, nil))
			kind, _, decisionLeft, _ := client.LiveLookup("1.2.3.4", nil, 60)
			if decisionscope.IsActiveRemediation(kind) || decisionLeft != 0 {
				t.Fatalf("kind %q left %v, want no remediation and no time left", kind, decisionLeft)
			}
			if slot := client.decisionStore.PublishedMemoryMapForTest()["1.2.3.4"]; slot.DecisionEnd != 0 {
				t.Fatalf("memo DecisionEnd %d, want 0", slot.DecisionEnd)
			}
		})
	}
}
