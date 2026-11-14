package lapi

import (
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pkg/configuration"
	"github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pkg/decisionscope"
	"github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pkg/logger"
	"github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pkg/reclaim"
)

// TestStreamPutItemUnknownTypeStoresBan proves challenge and throttle store as ban, not skip, by default.
func TestStreamPutItemUnknownTypeStoresBan(t *testing.T) {
	client, _ := NewTestClient(logger.New("ERROR", ""))
	for _, decisionType := range []string{"challenge", "throttle"} {
		stored, ok := client.streamPutItem(Decision{
			Type: decisionType, Scope: "ip", Value: "203.0.113.50", Origin: "crowdsec",
		}, 60)
		if !ok || stored.Kind != decisionscope.BannedValue {
			t.Fatalf("%s must store ban, got %#v ok=%v", decisionType, stored, ok)
		}
	}
}

// TestStrongestLiveDecisionUnknownTypeIsBan proves unknown types win as ban over captcha by default.
func TestStrongestLiveDecisionUnknownTypeIsBan(t *testing.T) {
	client := &Client{}
	picked := client.strongestLiveDecision([]Decision{
		{Type: "challenge", Origin: "crowdsec", Duration: "1h"},
	})
	if picked == nil || picked.Type != "challenge" {
		t.Fatalf("challenge must win as ban, got %#v", picked)
	}
	throttleThenCaptcha := client.strongestLiveDecision([]Decision{
		{Type: "throttle", Origin: "cscli", Duration: "1h"},
		{Type: "captcha", Origin: "crowdsec", Duration: "1h"},
	})
	if throttleThenCaptcha == nil || throttleThenCaptcha.Type != "throttle" {
		t.Fatalf("throttle must outrank captcha as ban, got %#v", throttleThenCaptcha)
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

// TestHandleStreamCacheRangeUnknownTypeStoresBan proves a Range throttle stores as ban by default.
func TestHandleStreamCacheRangeUnknownTypeStoresBan(t *testing.T) {
	server := testStreamPollsLAPI(t,
		`{"new":[{"id":1,"origin":"CAPI","type":"throttle","scope":"Range","value":"10.0.0.0/8","duration":"1h","scenario":"scan"}],"deleted":[]}`,
	)
	client := newTestStreamPoller(t, server)
	if err := client.handleStreamCache(); err != nil {
		t.Fatalf("range poll: %v", err)
	}
	kind, origin, _, err := client.LookupRemediation("10.1.2.3", net.ParseIP("10.1.2.3"), nil)
	if err != nil || kind != decisionscope.BannedValue || origin != "CAPI" {
		t.Fatalf("Range throttle must store ban, got kind=%q origin=%q err=%v", kind, origin, err)
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

// TestIngestUnknownTypeTraceCarriesFallback proves the TRACE record names the type and the
// effective fallback, including ignore, and stays at TRACE.
func TestIngestUnknownTypeTraceCarriesFallback(t *testing.T) {
	const stem = "handleStreamCache:unknownType"
	for _, fallback := range []string{"", configuration.LapiRemediationFallbackCaptcha, configuration.LapiRemediationFallbackIgnore} {
		t.Run("fallback="+fallback, func(t *testing.T) {
			log, sink := newTestLogSink(logger.LevelTrace)
			client, _ := NewTestClient(log)
			client.remediationFallback = fallback
			client.streamPutItem(Decision{Type: "throttle", Scope: "ip", Value: "203.0.113.50", Origin: "crowdsec"}, 60)
			wantFallback := `"fallback":"` + configuration.EffectiveLapiRemediationFallback(fallback) + `"`
			for _, line := range strings.Split(strings.TrimSpace(sink.String()), "\n") {
				if !strings.Contains(line, stem) {
					continue
				}
				if !strings.Contains(line, `"level":"DEBUG-4"`) {
					t.Fatalf("%s must be TRACE only, got %s", stem, line)
				}
				if !strings.Contains(line, wantFallback) || !strings.Contains(line, `"type":"throttle"`) {
					t.Fatalf("%s must carry the type and %s, got %s", stem, wantFallback, line)
				}
				return
			}
			t.Fatalf("no %s record:\n%s", stem, sink.String())
		})
	}
}

// testStreamPollsLAPI answers stream poll N with bodies[N]; later polls get an empty delta.
func testStreamPollsLAPI(t *testing.T, bodies ...string) *httptest.Server {
	t.Helper()
	var polls int64
	server := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, _ *http.Request) {
		poll := atomic.AddInt64(&polls, 1) - 1
		body := `{"new":[],"deleted":[]}`
		if poll < int64(len(bodies)) {
			body = bodies[poll]
		}
		if _, err := rw.Write([]byte(body)); err != nil {
			t.Errorf("stream stub write: %v", err)
		}
	}))
	t.Cleanup(server.Close)
	return server
}

// newTestFallbackStreamPoller is a stream poller with an opener fallback and Country in its scope list.
func newTestFallbackStreamPoller(t *testing.T, server *httptest.Server, fallback string) *Client {
	t.Helper()
	client := newTestStreamPoller(t, server)
	client.remediationFallback = fallback
	client.streamScopeSet = map[string]struct{}{"country": {}, "ip": {}, "range": {}}
	client.decisionScopeHeaders = map[string]string{decisionscope.ScopeCountry: "CF-IPCountry"}
	return client
}

// lookupKindForTest is the stored remediation kind LookupRemediation returns for ip and header scopes.
func lookupKindForTest(client *Client, ip string, scopes map[string]string) string {
	kind, _, _, _ := client.LookupRemediation(ip, net.ParseIP(ip), scopes) //nolint:dogsled // only the kind matters here
	return kind
}

// TestStreamNewUnknownTypeFollowsFallback proves stream New Ip, Country, and Range rows of an
// unknown type store as the fallback letter, and are not stored under ignore.
func TestStreamNewUnknownTypeFollowsFallback(t *testing.T) {
	const newThrottle = `{"new":[` +
		`{"id":1,"origin":"crowdsec","type":"throttle","scope":"Ip","value":"203.0.113.7","duration":"1h","scenario":"s"},` +
		`{"id":2,"origin":"crowdsec","type":"throttle","scope":"Country","value":"FR","duration":"1h","scenario":"s"},` +
		`{"id":3,"origin":"crowdsec","type":"throttle","scope":"Range","value":"10.0.0.0/8","duration":"1h","scenario":"s"}` +
		`],"deleted":[]}`
	for _, tc := range []struct {
		fallback string
		want     string
	}{
		{"", decisionscope.BannedValue},
		{configuration.LapiRemediationFallbackBan, decisionscope.BannedValue},
		{configuration.LapiRemediationFallbackCaptcha, decisionscope.CaptchaValue},
		{configuration.LapiRemediationFallbackIgnore, ""},
	} {
		t.Run("fallback="+tc.fallback, func(t *testing.T) {
			client := newTestFallbackStreamPoller(t, testStreamPollsLAPI(t, newThrottle), tc.fallback)
			if err := client.handleStreamCache(); err != nil {
				t.Fatalf("poll: %v", err)
			}
			ipKind := lookupKindForTest(client, "203.0.113.7", nil)
			countryKind := lookupKindForTest(client, "198.51.100.1", map[string]string{decisionscope.ScopeCountry: "FR"})
			rangeKind := lookupKindForTest(client, "10.1.2.3", nil)
			if ipKind != tc.want || countryKind != tc.want || rangeKind != tc.want {
				t.Fatalf("ip=%q country=%q range=%q, want %q for each", ipKind, countryKind, rangeKind, tc.want)
			}
		})
	}
}

// TestStreamNewBanIgnoresFallback proves a ban row stores ban under ignore, and a whitelist row
// for the same Ip does not lift that ban.
func TestStreamNewBanIgnoresFallback(t *testing.T) {
	const banThenWhitelist = `{"new":[` +
		`{"id":1,"origin":"crowdsec","type":"ban","scope":"Ip","value":"203.0.113.7","duration":"1h","scenario":"s"},` +
		`{"id":2,"origin":"cscli","type":"whitelist","scope":"Ip","value":"203.0.113.7","duration":"1h","scenario":"s"}` +
		`],"deleted":[]}`
	client := newTestFallbackStreamPoller(t, testStreamPollsLAPI(t, banThenWhitelist), configuration.LapiRemediationFallbackIgnore)
	if err := client.handleStreamCache(); err != nil {
		t.Fatalf("poll: %v", err)
	}
	kind := lookupKindForTest(client, "203.0.113.7", nil)
	if kind != decisionscope.BannedValue {
		t.Fatalf("ban must survive a whitelist row under ignore, got %q", kind)
	}
}

// TestStreamDeletedUnknownTypeFollowsFallback proves a later Deleted throttle row keeps the Ip
// and Range bans under ignore, and clears them under ban and captcha.
func TestStreamDeletedUnknownTypeFollowsFallback(t *testing.T) {
	const newBans = `{"new":[` +
		`{"id":1,"origin":"crowdsec","type":"ban","scope":"Ip","value":"203.0.113.7","duration":"1h","scenario":"s"},` +
		`{"id":2,"origin":"crowdsec","type":"ban","scope":"Range","value":"10.0.0.0/8","duration":"1h","scenario":"s"}` +
		`],"deleted":[]}`
	const deletedThrottle = `{"new":[],"deleted":[` +
		`{"id":3,"origin":"cscli","type":"throttle","scope":"Ip","value":"203.0.113.7","duration":"0s","scenario":"s"},` +
		`{"id":4,"origin":"cscli","type":"throttle","scope":"Range","value":"10.0.0.0/8","duration":"0s","scenario":"s"}` +
		`]}`
	for _, tc := range []struct {
		fallback string
		want     string
	}{
		{configuration.LapiRemediationFallbackIgnore, decisionscope.BannedValue},
		{configuration.LapiRemediationFallbackBan, ""},
		{configuration.LapiRemediationFallbackCaptcha, ""},
	} {
		t.Run("fallback="+tc.fallback, func(t *testing.T) {
			client := newTestFallbackStreamPoller(t, testStreamPollsLAPI(t, newBans, deletedThrottle), tc.fallback)
			if err := client.handleStreamCache(); err != nil {
				t.Fatalf("first poll: %v", err)
			}
			if err := client.handleStreamCache(); err != nil {
				t.Fatalf("second poll: %v", err)
			}
			ipKind := lookupKindForTest(client, "203.0.113.7", nil)
			rangeKind := lookupKindForTest(client, "10.1.2.3", nil)
			if ipKind != tc.want || rangeKind != tc.want {
				t.Fatalf("ip=%q range=%q, want %q for both", ipKind, rangeKind, tc.want)
			}
		})
	}
}

// TestStreamCountsSkipIgnoredRows proves rows the ignore fallback skips are not counted as written.
func TestStreamCountsSkipIgnoredRows(t *testing.T) {
	const body = `{"new":[` +
		`{"id":1,"origin":"crowdsec","type":"throttle","scope":"Ip","value":"203.0.113.7","duration":"1h","scenario":"s"},` +
		`{"id":2,"origin":"crowdsec","type":"throttle","scope":"Range","value":"10.0.0.0/8","duration":"1h","scenario":"s"}` +
		`],"deleted":[` +
		`{"id":3,"origin":"cscli","type":"throttle","scope":"Ip","value":"203.0.113.8","duration":"0s","scenario":"s"},` +
		`{"id":4,"origin":"cscli","type":"throttle","scope":"Range","value":"172.16.0.0/12","duration":"0s","scenario":"s"}` +
		`]}`
	client := newTestFallbackStreamPoller(t, testStreamPollsLAPI(t, body), configuration.LapiRemediationFallbackIgnore)
	newCount, deletedCount, err := client.fetchAndApplyStreamDecisions()
	if err != nil {
		t.Fatalf("poll: %v", err)
	}
	if newCount != 0 || deletedCount != 0 {
		t.Fatalf("newCount=%d deletedCount=%d, want 0 and 0", newCount, deletedCount)
	}
}

// TestStrongestLiveDecisionFollowsFallback proves the live pick ranks unknown types as the fallback stores them.
func TestStrongestLiveDecisionFollowsFallback(t *testing.T) {
	for _, tc := range []struct {
		name     string
		fallback string
		types    []string
		want     string
	}{
		{"ignore throttle only", configuration.LapiRemediationFallbackIgnore, []string{"throttle"}, ""},
		{"ignore throttle then captcha", configuration.LapiRemediationFallbackIgnore, []string{"throttle", "captcha"}, "captcha"},
		{"ban throttle then captcha", configuration.LapiRemediationFallbackBan, []string{"throttle", "captcha"}, "throttle"},
		{"captcha throttle then ban", configuration.LapiRemediationFallbackCaptcha, []string{"throttle", "ban"}, "ban"},
		{"captcha throttle only", configuration.LapiRemediationFallbackCaptcha, []string{"throttle"}, "throttle"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			client := &Client{remediationFallback: tc.fallback}
			items := make([]Decision, 0, len(tc.types))
			for _, decisionType := range tc.types {
				items = append(items, Decision{Type: decisionType, Origin: "crowdsec", Duration: "1h"})
			}
			picked := client.strongestLiveDecision(items)
			pickedType := ""
			if picked != nil {
				pickedType = picked.Type
			}
			if pickedType != tc.want {
				t.Fatalf("picked %q, want %q", pickedType, tc.want)
			}
		})
	}
}

// TestLiveLookupIgnoredTypeOnlyPasses proves a throttle-only live list is no-remediation under ignore.
func TestLiveLookupIgnoredTypeOnlyPasses(t *testing.T) {
	body := `[{"id":1,"origin":"cscli","type":"throttle","scope":"Ip","value":"1.2.3.4","duration":"1h","scenario":"test"}]`
	client := newTestLiveClient(t, testLiveScopeLAPI(t, body, nil))
	client.remediationFallback = configuration.LapiRemediationFallbackIgnore
	kind, _, err := client.LiveLookup("1.2.3.4", nil, 0)
	if err != nil {
		t.Fatalf("ignored throttle: %v", err)
	}
	if kind != decisionscope.NoBannedValue {
		t.Fatalf("ignored throttle kind %q, want %q", kind, decisionscope.NoBannedValue)
	}
}

// TestOpen_ReadsOpenerRemediationFallback proves lapi.New holds the opener's effective fallback.
func TestOpen_ReadsOpenerRemediationFallback(t *testing.T) {
	reclaim.ResetForTestWith(0)
	t.Cleanup(func() { reclaim.ResetForTest() })
	server, _ := testStreamLAPI(t)
	parsed, err := url.Parse(server.URL)
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		configured string
		want       string
	}{
		{"", configuration.LapiRemediationFallbackBan},
		{configuration.LapiRemediationFallbackIgnore, configuration.LapiRemediationFallbackIgnore},
	} {
		t.Run("configured="+tc.configured, func(t *testing.T) {
			cfg := testStreamConfig(parsed.Host, 0)
			cfg.LapiRemediationFallback = tc.configured
			client := openStreamForTest(t, cfg, "fallback-"+tc.want)
			if client.remediationFallback != tc.want {
				t.Fatalf("remediationFallback = %q, want %q", client.remediationFallback, tc.want)
			}
		})
	}
}
