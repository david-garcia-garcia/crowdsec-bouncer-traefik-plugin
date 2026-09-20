package lapi

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pkg/configuration"
	"github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pkg/decisionscope"
	"github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pkg/decisionstore"
	"github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pkg/logger"
)

func TestMetricsOriginListsRewrite(t *testing.T) {
	if got := MetricsOrigin("lists", "firehol_level1"); got != "lists:firehol_level1" {
		t.Fatalf("got %q", got)
	}
	if got := MetricsOrigin("crowdsec", "ssh-bf"); got != "crowdsec" {
		t.Fatalf("crowdsec got %q", got)
	}
}

func TestReportMetricsPluginFailClosedOrigins(t *testing.T) {
	client, body := newUsageMetricsClient(t)
	origins := []string{
		OriginPluginTechGetRemoteFail,
		OriginPluginTechTrustIPFail,
		OriginPluginTechCacheFail,
		OriginPluginTechStreamFail,
		OriginPluginLapiFailure,
		OriginPluginAppsecFailure,
	}
	for _, origin := range origins {
		client.IncDropped(origin, "ipv4", "ban")
	}
	if err := client.reportMetrics(); err != nil {
		t.Fatal(err)
	}
	found := map[string]bool{}
	for _, raw := range usageMetricItems(t, body.bytes()) {
		item := asObject(t, raw)
		if item["name"] != "dropped" {
			continue
		}
		labels := asObject(t, item["labels"])
		origin, _ := labels["origin"].(string)
		found[origin] = true
	}
	for _, origin := range origins {
		if !found[origin] {
			t.Fatalf("missing dropped origin %q in %#v", origin, found)
		}
	}
}

func TestIncProcessedReportsWithoutWindowMap(t *testing.T) {
	client, body := newUsageMetricsClient(t)
	client.IncProcessed("ipv4")
	client.IncProcessed("ipv4")
	client.IncProcessed("ipv6")
	if err := client.reportMetrics(); err != nil {
		t.Fatal(err)
	}
	got := map[string]float64{}
	for _, raw := range usageMetricItems(t, body.bytes()) {
		item := asObject(t, raw)
		if item["name"] != "processed" {
			continue
		}
		labels := asObject(t, item["labels"])
		ipType, _ := labels["ip_type"].(string)
		value, _ := item["value"].(float64)
		got[ipType] = value
	}
	if got["ipv4"] != 2 || got["ipv6"] != 1 {
		t.Fatalf("processed %#v", got)
	}
}

func TestReportMetricsOfficialLabels(t *testing.T) {
	client, body := newUsageMetricsClient(t)
	store := AttachTestInternStore(client)
	client.IncDropped("lists:firehol_level1", "ipv4", "ban")
	client.IncProcessed("ipv4")
	store.Put(decisionstore.Decision{
		Scope: decisionscope.ScopeIP, Value: "1.2.3.4", Kind: decisionscope.BannedValue, Origin: "crowdsec", DurationSec: 60,
	})
	if err := client.reportMetrics(); err != nil {
		t.Fatal(err)
	}
	assertOfficialUsageItems(t, usageMetricItems(t, body.bytes()))
}

// TestReportMetricsPluginVersion checks usage-metrics JSON version and LAPI User-Agent carry the Client plugin version.
func TestReportMetricsPluginVersion(t *testing.T) {
	const wantVersion = "v9.9.9-test"
	gotUA := ""
	gotBody := new([]byte)
	lapi := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
		if req.URL.Path != "/v1/usage-metrics" {
			t.Errorf("path %s", req.URL.Path)
		}
		gotUA = req.Header.Get("User-Agent")
		raw, err := io.ReadAll(req.Body)
		if err != nil {
			t.Errorf("read body %v", err)
			return
		}
		*gotBody = raw
		rw.WriteHeader(http.StatusCreated)
	}))
	t.Cleanup(lapi.Close)
	lapiURL, err := url.Parse(lapi.URL)
	if err != nil {
		t.Fatal(err)
	}
	started := time.Unix(1_700_000_000, 0).UTC()
	client := &Client{
		crowdsecScheme: lapiURL.Scheme,
		crowdsecHost:   lapiURL.Host,
		crowdsecPath:   "/",
		crowdsecMode:   configuration.StreamMode,
		log:            logger.New("ERROR", ""),
		pluginVersion:  wantVersion,
	}
	attachTestTransport(client, lapi.Client(), "")
	attachTestMetricsReporter(client, started)
	if err := client.reportMetrics(); err != nil {
		t.Fatal(err)
	}
	if usageComponent(t, *gotBody)["version"] != wantVersion {
		t.Fatalf("version %#v", usageComponent(t, *gotBody)["version"])
	}
	wantUA := "Crowdsec-Bouncer-Traefik-Plugin/" + wantVersion
	if gotUA != wantUA {
		t.Fatalf("User-Agent %q want %q", gotUA, wantUA)
	}
}

func TestReportMetricsStartupTimestampStable(t *testing.T) {
	client, body := newUsageMetricsClient(t)
	started := float64(client.metricsReporter.startedAt.Unix())
	if err := client.reportMetrics(); err != nil {
		t.Fatal(err)
	}
	if usageStartupTimestamp(t, body.bytes()) != started {
		t.Fatalf("startup %v", usageStartupTimestamp(t, body.bytes()))
	}
	if err := client.reportMetrics(); err != nil {
		t.Fatal(err)
	}
	if usageStartupTimestamp(t, body.bytes()) != started {
		t.Fatal("startup moved")
	}
}

// testMetricsBody is a test-only capture of the usage-metrics POST body.
// Sleep drains asynchronously, so the mock handler and the test reader must not
// race on a bare *[]byte (that race is harness-only, not the production stream bug).
type testMetricsBody struct {
	mu  sync.Mutex
	raw []byte
}

func (b *testMetricsBody) store(raw []byte) {
	b.mu.Lock()
	b.raw = append([]byte(nil), raw...)
	b.mu.Unlock()
}

func (b *testMetricsBody) bytes() []byte {
	b.mu.Lock()
	defer b.mu.Unlock()
	out := make([]byte, len(b.raw))
	copy(out, b.raw)
	return out
}

func newUsageMetricsClient(t *testing.T) (*Client, *testMetricsBody) {
	t.Helper()
	gotBody := &testMetricsBody{}
	lapi := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
		if req.URL.Path != "/v1/usage-metrics" {
			t.Errorf("path %s", req.URL.Path)
		}
		raw, err := io.ReadAll(req.Body)
		if err != nil {
			t.Errorf("read body %v", err)
			return
		}
		gotBody.store(raw)
		rw.WriteHeader(http.StatusCreated)
	}))
	t.Cleanup(lapi.Close)
	lapiURL, err := url.Parse(lapi.URL)
	if err != nil {
		t.Fatal(err)
	}
	started := time.Unix(1_700_000_000, 0).UTC()
	client := &Client{
		crowdsecScheme: lapiURL.Scheme,
		crowdsecHost:   lapiURL.Host,
		crowdsecPath:   "/",
		crowdsecMode:   configuration.StreamMode,
		log:            logger.New("ERROR", ""),
		pluginVersion:  "test",
	}
	attachTestTransport(client, lapi.Client(), "")
	attachTestMetricsReporter(client, started)
	return client, gotBody
}

// attachTestMetricsReporter constructs the reporter beside a Client literal and binds crowdsecQuery.
func attachTestMetricsReporter(client *Client, startedAt time.Time) {
	client.metricsReporter = newMetricsReporter(client, startedAt)
	client.metricsReporter.lastMetricsPush = startedAt
}

func decodeUsageObject(t *testing.T, body []byte) map[string]interface{} {
	t.Helper()
	var payload map[string]interface{}
	if err := json.Unmarshal(body, &payload); err != nil {
		t.Fatal(err)
	}
	return payload
}

func asObject(t *testing.T, value interface{}) map[string]interface{} {
	t.Helper()
	obj, ok := value.(map[string]interface{})
	if !ok {
		t.Fatalf("want object got %T", value)
	}
	return obj
}

func asArray(t *testing.T, value interface{}) []interface{} {
	t.Helper()
	arr, ok := value.([]interface{})
	if !ok {
		t.Fatalf("want array got %T", value)
	}
	return arr
}

func usageComponent(t *testing.T, body []byte) map[string]interface{} {
	t.Helper()
	components := asArray(t, decodeUsageObject(t, body)["remediation_components"])
	if len(components) == 0 {
		t.Fatal("no remediation_components")
	}
	return asObject(t, components[0])
}

func usageStartupTimestamp(t *testing.T, body []byte) float64 {
	t.Helper()
	stamp, ok := usageComponent(t, body)["utc_startup_timestamp"].(float64)
	if !ok {
		t.Fatal("utc_startup_timestamp missing")
	}
	return stamp
}

func usageMetricItems(t *testing.T, body []byte) []interface{} {
	t.Helper()
	windows := asArray(t, usageComponent(t, body)["metrics"])
	if len(windows) == 0 {
		t.Fatal("no metrics windows")
	}
	return asArray(t, asObject(t, windows[0])["items"])
}

func assertOfficialUsageItems(t *testing.T, items []interface{}) {
	t.Helper()
	foundDropped, foundProcessed, foundActive := false, false, false
	for _, raw := range items {
		item := asObject(t, raw)
		labels := map[string]interface{}{}
		if rawLabels, ok := item["labels"]; ok && rawLabels != nil {
			labels = asObject(t, rawLabels)
		}
		if _, ok := labels["type"]; ok {
			t.Fatal("labels.type must not be sent")
		}
		switch item["name"] {
		case "dropped":
			foundDropped = true
			if labels["origin"] != "lists:firehol_level1" || labels["ip_type"] != "ipv4" || labels["remediation"] != "ban" {
				t.Fatalf("dropped labels %#v", labels)
			}
		case "processed":
			foundProcessed = true
			if _, ok := labels["origin"]; ok {
				t.Fatalf("processed should omit origin %#v", labels)
			}
		case "active_decisions":
			foundActive = true
			if labels["origin"] != "crowdsec" || labels["ip_type"] != "ipv4" {
				t.Fatalf("active labels %#v", labels)
			}
		}
	}
	if !foundDropped || !foundProcessed || !foundActive {
		t.Fatalf("missing items dropped=%v processed=%v active=%v", foundDropped, foundProcessed, foundActive)
	}
}

func TestReportMetricsOmitsRange(t *testing.T) {
	client, body := newUsageMetricsClient(t)
	store := AttachTestInternStore(client)
	if err := store.ApplyRangeBatch(map[string]string{"10.0.0.0/8": decisionstore.KindOriginString(decisionscope.BannedValue, "crowdsec")}, nil); err != nil {
		t.Fatal(err)
	}
	if err := client.reportMetrics(); err != nil {
		t.Fatal(err)
	}
	for _, raw := range usageMetricItems(t, body.bytes()) {
		item := asObject(t, raw)
		if item["name"] == "active_decisions" {
			t.Fatalf("Range CIDR must be omitted %#v", item)
		}
	}
}

func TestReportMetricsLiveModeOmitsActive(t *testing.T) {
	client, body := newUsageMetricsClient(t)
	client.metricsReporter.crowdsecMode = configuration.LiveMode
	store := AttachTestInternStore(client)
	store.Put(decisionstore.Decision{
		Scope: decisionscope.ScopeIP, Value: "1.2.3.4", Kind: decisionscope.BannedValue, Origin: "crowdsec", DurationSec: 60,
	})
	if err := client.reportMetrics(); err != nil {
		t.Fatal(err)
	}
	for _, raw := range usageMetricItems(t, body.bytes()) {
		item := asObject(t, raw)
		if item["name"] == "active_decisions" {
			t.Fatalf("live mode must omit active_decisions %#v", item)
		}
	}
}

func TestReportMetricsOverflowEmptyOrigin(t *testing.T) {
	client, body := newUsageMetricsClient(t)
	store := AttachTestInternStore(client)
	store.FillUntilMaxForTest()
	store.Put(decisionstore.Decision{
		Scope: decisionscope.ScopeIP, Value: "1.2.3.4", Kind: decisionscope.BannedValue, Origin: "overflow-origin", DurationSec: 60,
	})
	if err := client.reportMetrics(); err != nil {
		t.Fatal(err)
	}
	found := false
	for _, raw := range usageMetricItems(t, body.bytes()) {
		item := asObject(t, raw)
		if item["name"] != "active_decisions" {
			continue
		}
		found = true
		labels := map[string]interface{}{}
		if rawLabels, ok := item["labels"]; ok && rawLabels != nil {
			labels = asObject(t, rawLabels)
		}
		if _, ok := labels["origin"]; ok {
			t.Fatalf("overflow origin must be empty, labels %#v", labels)
		}
	}
	if !found {
		t.Fatal("overflow slot must still post active_decisions")
	}
}

func TestSleepDrainsMetrics(t *testing.T) {
	client, body := newUsageMetricsClient(t)
	client.metricsInterval = 1
	client.IncProcessed("ipv4")
	client.Sleep()
	waitMetricsBody(t, body)
	if processedValue(t, body.bytes(), "ipv4") != 1 {
		t.Fatalf("Sleep must POST remaining processed, body=%s", body.bytes())
	}
}

func TestCloseDrainsMetrics(t *testing.T) {
	client, body := newUsageMetricsClient(t)
	client.metricsInterval = 1
	client.IncProcessed("ipv6")
	client.Close()
	if processedValue(t, body.bytes(), "ipv6") != 1 {
		t.Fatalf("Close must POST remaining processed, body=%s", body.bytes())
	}
}

func TestReportMetricsRestoresOnFailure(t *testing.T) {
	fail := true
	gotBody := new([]byte)
	lapi := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
		if fail {
			rw.WriteHeader(http.StatusInternalServerError)
			return
		}
		raw, err := io.ReadAll(req.Body)
		if err != nil {
			t.Errorf("read body %v", err)
			return
		}
		*gotBody = raw
		rw.WriteHeader(http.StatusCreated)
	}))
	t.Cleanup(lapi.Close)
	lapiURL, err := url.Parse(lapi.URL)
	if err != nil {
		t.Fatal(err)
	}
	started := time.Unix(1_700_000_000, 0).UTC()
	client := &Client{
		crowdsecScheme:  lapiURL.Scheme,
		crowdsecHost:    lapiURL.Host,
		crowdsecPath:    "/",
		crowdsecMode:    configuration.StreamMode,
		log:             logger.New("ERROR", ""),
		pluginVersion:   "test",
		metricsInterval: 1,
	}
	attachTestTransport(client, lapi.Client(), "")
	attachTestMetricsReporter(client, started)
	client.IncProcessed("ipv4")
	if err := client.reportMetrics(); err == nil {
		t.Fatal("failed POST must error")
	}
	if atomic.LoadInt64(&client.metricsReporter.processedIPv4) != 1 {
		t.Fatalf("failed POST must restore processed, got %d", atomic.LoadInt64(&client.metricsReporter.processedIPv4))
	}
	fail = false
	if err := client.reportMetrics(); err != nil {
		t.Fatal(err)
	}
	if processedValue(t, *gotBody, "ipv4") != 1 {
		t.Fatalf("retry must send restored processed, body=%s", *gotBody)
	}
}

// TestReportMetricsWindowSurvivesAdoptTransport checks unsent counts POST through the replaced transport.
func TestReportMetricsWindowSurvivesAdoptTransport(t *testing.T) {
	gotKey := ""
	gotBody := new([]byte)
	lapi := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
		if req.URL.Path != "/v1/usage-metrics" {
			t.Errorf("path %s", req.URL.Path)
		}
		gotKey = req.Header.Get("X-Api-Key")
		raw, err := io.ReadAll(req.Body)
		if err != nil {
			t.Errorf("read body %v", err)
			return
		}
		*gotBody = raw
		rw.WriteHeader(http.StatusCreated)
	}))
	t.Cleanup(lapi.Close)
	lapiURL, err := url.Parse(lapi.URL)
	if err != nil {
		t.Fatal(err)
	}
	started := time.Unix(1_700_000_000, 0).UTC()
	client := &Client{
		crowdsecScheme: lapiURL.Scheme,
		crowdsecHost:   lapiURL.Host,
		crowdsecPath:   "/",
		crowdsecMode:   configuration.StreamMode,
		log:            logger.New("ERROR", ""),
		pluginVersion:  "test",
	}
	attachTestTransport(client, lapi.Client(), "first-key")
	attachTestMetricsReporter(client, started)
	client.IncProcessed("ipv4")
	client.IncDropped("crowdsec", "ipv4", "ban")
	adopted := testStreamConfig(lapiURL.Host, 0)
	adopted.CrowdsecLapiScheme = lapiURL.Scheme
	adopted.CrowdsecLapiKey = "second-key"
	adopted.HTTPTimeoutSeconds = 11
	if _, err := client.AdoptTransport(adopted); err != nil {
		t.Fatal(err)
	}
	if err := client.reportMetrics(); err != nil {
		t.Fatal(err)
	}
	if gotKey != "second-key" {
		t.Fatalf("POST must use adopted transport key, got %q", gotKey)
	}
	if processedValue(t, *gotBody, "ipv4") != 1 {
		t.Fatalf("unsent processed must survive AdoptTransport, body=%s", *gotBody)
	}
	foundDropped := false
	for _, raw := range usageMetricItems(t, *gotBody) {
		item := asObject(t, raw)
		if item["name"] == "dropped" {
			foundDropped = true
		}
	}
	if !foundDropped {
		t.Fatalf("unsent dropped must survive AdoptTransport, body=%s", *gotBody)
	}
}

func waitMetricsBody(t *testing.T, body *testMetricsBody) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if len(body.bytes()) > 0 {
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatal("usage-metrics body stayed empty")
}

func processedValue(t *testing.T, body []byte, ipType string) float64 {
	t.Helper()
	for _, raw := range usageMetricItems(t, body) {
		item := asObject(t, raw)
		if item["name"] != "processed" {
			continue
		}
		labels := asObject(t, item["labels"])
		if labels["ip_type"] != ipType {
			continue
		}
		value, _ := item["value"].(float64)
		return value
	}
	t.Fatalf("missing processed %s in %s", ipType, body)
	return 0
}
