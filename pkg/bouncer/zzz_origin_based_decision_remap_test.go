package bouncer

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"text/template"

	captcha "github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pkg/captcha"
	"github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pkg/configuration"
	"github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pkg/decisionscope"
	ip "github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pkg/ip"
	"github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pkg/lapi"
	logger "github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pkg/logger"
)

func TestBouncerDecisionRemapEdges(t *testing.T) {
	table := copyOriginBasedDecisionRemap(map[string]map[string]string{
		"CAPI":                 {"ban": "captcha"},
		"lists":                {"ban": "captcha"},
		"lists:firehol_level1": {"ban": "captcha"},
	})
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
		got := bouncerDecisionRemapEdges(tc.origin, table) != nil
		if got != tc.want {
			t.Errorf("bouncerDecisionRemapEdges(%q) present=%v, want %v", tc.origin, got, tc.want)
		}
	}
}

func TestCopyBouncerDecisionRemapTrimsBlanks(t *testing.T) {
	src := make(map[string]map[string]string)
	paddedFrom := make(map[string]string)
	paddedFrom[" Ban "] = " Captcha "
	src[" CAPI "] = paddedFrom
	src[""] = map[string]string{"ban": "captcha"}
	src["cscli"] = map[string]string{"ban": "ban"}
	got := copyOriginBasedDecisionRemap(src)
	if len(got) != 1 || got["CAPI"]["ban"] != decisionscope.CaptchaValue {
		t.Fatalf("got %#v", got)
	}
	if copyOriginBasedDecisionRemap(nil) != nil {
		t.Fatal("nil in must stay nil")
	}
	pass := copyOriginBasedDecisionRemap(map[string]map[string]string{"crowdsec": {"captcha": "pass"}})
	if pass["crowdsec"]["captcha"] != decisionscope.NoBannedValue {
		t.Fatalf("pass must apply as none, got %#v", pass)
	}
}

func TestApplyBouncerDecisionRemap(t *testing.T) {
	b := &Bouncer{bouncerDecisionRemap: copyOriginBasedDecisionRemap(map[string]map[string]string{
		"CAPI":                 {"ban": "captcha"},
		"lists:firehol_level1": {"ban": "captcha"},
		"crowdsec":             {"captcha": "pass"},
	})}
	if got := b.applyOriginBasedDecisionRemap(decisionscope.BannedValue, "CAPI"); got != decisionscope.CaptchaValue {
		t.Fatalf("CAPI ban applied %q", got)
	}
	if got := b.applyOriginBasedDecisionRemap(decisionscope.BannedValue, "lists:firehol_level1"); got != decisionscope.CaptchaValue {
		t.Fatalf("listed list ban applied %q", got)
	}
	if got := b.applyOriginBasedDecisionRemap(decisionscope.BannedValue, "lists:tor-exit"); got != decisionscope.BannedValue {
		t.Fatalf("other list ban applied %q", got)
	}
	if got := b.applyOriginBasedDecisionRemap(decisionscope.BannedValue, "cscli"); got != decisionscope.BannedValue {
		t.Fatalf("cscli ban applied %q", got)
	}
	if got := b.applyOriginBasedDecisionRemap(decisionscope.CaptchaValue, "CAPI"); got != decisionscope.CaptchaValue {
		t.Fatalf("CAPI captcha applied %q", got)
	}
	if got := b.applyOriginBasedDecisionRemap(decisionscope.CaptchaValue, "crowdsec"); got != decisionscope.NoBannedValue {
		t.Fatalf("crowdsec captcha pass applied %q", got)
	}
	if got := (&Bouncer{}).applyOriginBasedDecisionRemap(decisionscope.BannedValue, "CAPI"); got != decisionscope.BannedValue {
		t.Fatalf("empty table applied %q", got)
	}
}

func TestApplyBouncerDecisionRemap_OneHopDoesNotChain(t *testing.T) {
	b := &Bouncer{bouncerDecisionRemap: copyOriginBasedDecisionRemap(map[string]map[string]string{
		"CAPI": {"ban": "captcha", "captcha": "pass"},
	})}
	if got := b.applyOriginBasedDecisionRemap(decisionscope.BannedValue, "CAPI"); got != decisionscope.CaptchaValue {
		t.Fatalf("stored ban must apply captcha, not chain to pass, got %q", got)
	}
	if got := b.applyOriginBasedDecisionRemap(decisionscope.CaptchaValue, "CAPI"); got != decisionscope.NoBannedValue {
		t.Fatalf("stored captcha must apply pass, got %q", got)
	}
}

func testRemapStreamBouncer(t *testing.T, lapiClient *lapi.Client, remap map[string]map[string]string) (*Bouncer, *bool) {
	t.Helper()
	log := logger.New("ERROR", "")
	if lapiClient == nil {
		t.Fatal("lapiClient is required")
	}
	clientChecker, err := ip.NewChecker(log, nil)
	if err != nil {
		t.Fatal(err)
	}
	banTemplate, err := template.New("ban").Parse("banned")
	if err != nil {
		t.Fatal(err)
	}
	passed := false
	b := &Bouncer{
		enabled:                      true,
		lapiMode:                     configuration.StreamMode,
		lapiEnabled:                  true,
		lapiClient:                   lapiClient,
		clientPoolStrategy:           &ip.PoolStrategy{Checker: clientChecker},
		captchaClient:                &captcha.Client{},
		log:                          log,
		bouncerRemediationStatusCode: http.StatusForbidden,
		banTemplate:                  banTemplate,
		banTemplateContentType:       "text/html; charset=utf-8",
		bouncerDecisionRemap:         copyOriginBasedDecisionRemap(remap),
		next: http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
			passed = true
		}),
	}
	return b, &passed
}

func TestServeHTTP_BouncerDecisionRemapPassSkipsLAPIBan(t *testing.T) {
	log := logger.New("ERROR", "")
	lapiClient, store := lapi.NewTestClient(log)
	lapi.AttachTestMetricsReporter(lapiClient)
	lapiClient.SetStreamHealthyForTest(true)
	b, passed := testRemapStreamBouncer(t, lapiClient, map[string]map[string]string{
		"CAPI": {"ban": "pass"},
	})
	lapi.SeedLiveSnapshotForTest(store, "203.0.113.10", decisionscope.BannedValue, "CAPI", 60)
	req := httptest.NewRequest(http.MethodGet, "http://example.com/protected", nil)
	req.RemoteAddr = "203.0.113.10:1"
	b.ServeHTTP(httptest.NewRecorder(), req)
	if !*passed {
		t.Fatal("CAPI ban remapped to pass must reach next")
	}
}

func TestServeHTTP_BouncerDecisionRemapIsPerBouncer(t *testing.T) {
	log := logger.New("ERROR", "")
	lapiClient, store := lapi.NewTestClient(log)
	lapi.AttachTestMetricsReporter(lapiClient)
	lapiClient.SetStreamHealthyForTest(true)
	passBouncer, passed := testRemapStreamBouncer(t, lapiClient, map[string]map[string]string{
		"CAPI": {"ban": "pass"},
	})
	banBouncer, bannedPassed := testRemapStreamBouncer(t, lapiClient, nil)
	lapi.SeedLiveSnapshotForTest(store, "203.0.113.10", decisionscope.BannedValue, "CAPI", 60)

	req := httptest.NewRequest(http.MethodGet, "http://example.com/protected", nil)
	req.RemoteAddr = "203.0.113.10:1"
	passBouncer.ServeHTTP(httptest.NewRecorder(), req)
	if !*passed {
		t.Fatal("router with pass remap must reach next")
	}
	banBouncer.ServeHTTP(httptest.NewRecorder(), req)
	if *bannedPassed {
		t.Fatal("router without remap must still ban")
	}
}
