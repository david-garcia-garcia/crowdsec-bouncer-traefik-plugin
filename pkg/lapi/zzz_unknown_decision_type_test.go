package lapi

import (
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pkg/decisionscope"
	"github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pkg/logger"
)

// TestStreamPutItemUnknownTypeStoresBan proves challenge and allow store as ban, not skip.
func TestStreamPutItemUnknownTypeStoresBan(t *testing.T) {
	client, _ := NewTestClient(logger.New("ERROR", ""))
	for _, decisionType := range []string{"challenge", "allow"} {
		stored, ok := client.streamPutItem(Decision{
			Type: decisionType, Scope: "ip", Value: "203.0.113.50", Origin: "crowdsec",
		}, 60)
		if !ok || stored.Kind != decisionscope.BannedValue {
			t.Fatalf("%s must store ban, got %#v ok=%v", decisionType, stored, ok)
		}
	}
}

// TestStrongestLiveDecisionUnknownTypeIsBan proves unknown types win as ban over captcha.
func TestStrongestLiveDecisionUnknownTypeIsBan(t *testing.T) {
	client := &Client{}
	picked := client.strongestLiveDecision([]Decision{
		{Type: "challenge", Origin: "crowdsec", Duration: "1h"},
	})
	if picked == nil || picked.Type != "challenge" {
		t.Fatalf("challenge must win as ban, got %#v", picked)
	}
	allowThenCaptcha := client.strongestLiveDecision([]Decision{
		{Type: "allow", Origin: "cscli", Duration: "1h"},
		{Type: "captcha", Origin: "crowdsec", Duration: "1h"},
	})
	if allowThenCaptcha == nil || allowThenCaptcha.Type != "allow" {
		t.Fatalf("allow must outrank captcha as ban, got %#v", allowThenCaptcha)
	}
}

// TestLiveLookupUnknownTypeBans proves a challenge-only live list remediates as ban.
func TestLiveLookupUnknownTypeBans(t *testing.T) {
	body := `[{"id":1,"origin":"CAPI","type":"challenge","scope":"Ip","value":"1.2.3.4","duration":"1h","scenario":"test"}]`
	server := testLiveScopeLAPI(t, body, nil)
	client := newTestLiveClient(t, server)
	kind, origin, err := client.LiveLookup("1.2.3.4", nil, 0)
	if err == nil {
		t.Fatal("challenge must remediate")
	}
	if kind != decisionscope.BannedValue || origin != "CAPI" {
		t.Fatalf("live challenge must be ban, got kind=%q origin=%q", kind, origin)
	}
}

// TestLiveLookupEmptyListStaysNone proves an empty live list is no-remediation.
func TestLiveLookupEmptyListStaysNone(t *testing.T) {
	server := testLiveScopeLAPI(t, "[]", nil)
	client := newTestLiveClient(t, server)
	kind, _, err := client.LiveLookup("1.2.3.4", nil, 0)
	if err != nil {
		t.Fatalf("empty list: %v", err)
	}
	if kind != decisionscope.NoBannedValue {
		t.Fatalf("empty list kind %q, want %q", kind, decisionscope.NoBannedValue)
	}
}

// TestHandleStreamCacheRangeUnknownTypeStoresBan proves a Range allow stores as ban.
func TestHandleStreamCacheRangeUnknownTypeStoresBan(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, _ *http.Request) {
		if _, err := rw.Write([]byte(`{"new":[{"id":1,"origin":"CAPI","type":"allow","scope":"Range","value":"10.0.0.0/8","duration":"1h","scenario":"scan"}],"deleted":[]}`)); err != nil {
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
		t.Fatalf("Range allow must store ban, got kind=%q origin=%q err=%v", kind, origin, err)
	}
}

// TestIngestUnknownTypeLogsAtTrace proves handleStreamCache:unknownType is TRACE, not Info or Debug.
func TestIngestUnknownTypeLogsAtTrace(t *testing.T) {
	const stem = "handleStreamCache:unknownType"
	for _, tc := range []struct {
		level slog.Level
		want  bool
	}{
		{slog.LevelInfo, false},
		{slog.LevelDebug, false},
		{logger.LevelTrace, true},
	} {
		t.Run(tc.level.String(), func(t *testing.T) {
			log, sink := newTestLogSink(tc.level)
			client, _ := NewTestClient(log)
			if _, ok := client.streamPutItem(Decision{
				Type: "challenge", Scope: "ip", Value: "203.0.113.50", Origin: "crowdsec",
			}, 60); !ok {
				t.Fatal("challenge must store")
			}
			logged := sink.String()
			if got := strings.Contains(logged, stem); got != tc.want {
				t.Fatalf("%s at %s: got %v want %v\n%s", stem, tc.level, got, tc.want, logged)
			}
		})
	}
}
