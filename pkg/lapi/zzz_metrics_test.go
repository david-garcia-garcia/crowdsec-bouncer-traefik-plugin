package lapi

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sync/atomic"
	"testing"
	"time"

	"github.com/maxlerebourg/crowdsec-bouncer-traefik-plugin/pkg/configuration"
	"github.com/maxlerebourg/crowdsec-bouncer-traefik-plugin/pkg/logger"
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
	for _, raw := range usageMetricItems(t, *body) {
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
	for _, raw := range usageMetricItems(t, *body) {
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
	client.IncDropped("lists:firehol_level1", "ipv4", "ban")
	client.IncProcessed("ipv4")
	client.rememberActiveDecision("ip:1.2.3.4", "crowdsec", "1.2.3.4")
	if err := client.reportMetrics(); err != nil {
		t.Fatal(err)
	}
	assertOfficialUsageItems(t, usageMetricItems(t, *body))
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
		crowdsecScheme:  lapiURL.Scheme,
		crowdsecHost:    lapiURL.Host,
		crowdsecPath:    "/",
		crowdsecHeader:  crowdsecLapiHeader,
		crowdsecMode:    configuration.StreamMode,
		httpClient:      lapi.Client(),
		log:             logger.New("ERROR", ""),
		pluginVersion:   wantVersion,
		lastMetricsPush: started,
		startedAt:       started,
		windowCounters:  make(map[usageMetricKey]int64),
		activeDecisions: make(map[usageMetricKey]int64),
	}
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
	started := float64(client.startedAt.Unix())
	if err := client.reportMetrics(); err != nil {
		t.Fatal(err)
	}
	if usageStartupTimestamp(t, *body) != started {
		t.Fatalf("startup %v", usageStartupTimestamp(t, *body))
	}
	if err := client.reportMetrics(); err != nil {
		t.Fatal(err)
	}
	if usageStartupTimestamp(t, *body) != started {
		t.Fatal("startup moved")
	}
}

func newUsageMetricsClient(t *testing.T) (*Client, *[]byte) {
	t.Helper()
	gotBody := new([]byte)
	lapi := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
		if req.URL.Path != "/v1/usage-metrics" {
			t.Errorf("path %s", req.URL.Path)
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
		crowdsecHeader:  crowdsecLapiHeader,
		crowdsecMode:    configuration.StreamMode,
		httpClient:      lapi.Client(),
		log:             logger.New("ERROR", ""),
		pluginVersion:   "test",
		lastMetricsPush: started,
		startedAt:       started,
		windowCounters:  make(map[usageMetricKey]int64),
		activeDecisions: make(map[usageMetricKey]int64),
	}
	return client, gotBody
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

func TestSleepDrainsMetrics(t *testing.T) {
	client, body := newUsageMetricsClient(t)
	client.metricsInterval = 1
	client.IncProcessed("ipv4")
	client.Sleep()
	waitMetricsBody(t, body)
	if processedValue(t, *body, "ipv4") != 1 {
		t.Fatalf("Sleep must POST remaining processed, body=%s", *body)
	}
}

func TestCloseDrainsMetrics(t *testing.T) {
	client, body := newUsageMetricsClient(t)
	client.metricsInterval = 1
	client.IncProcessed("ipv6")
	client.Close()
	if processedValue(t, *body, "ipv6") != 1 {
		t.Fatalf("Close must POST remaining processed, body=%s", *body)
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
		crowdsecHeader:  crowdsecLapiHeader,
		crowdsecMode:    configuration.StreamMode,
		httpClient:      lapi.Client(),
		log:             logger.New("ERROR", ""),
		pluginVersion:   "test",
		lastMetricsPush: started,
		startedAt:       started,
		metricsInterval: 1,
		windowCounters:  make(map[usageMetricKey]int64),
		activeDecisions: make(map[usageMetricKey]int64),
	}
	client.IncProcessed("ipv4")
	if err := client.reportMetrics(); err == nil {
		t.Fatal("failed POST must error")
	}
	if atomic.LoadInt64(&client.processedIPv4) != 1 {
		t.Fatalf("failed POST must restore processed, got %d", atomic.LoadInt64(&client.processedIPv4))
	}
	fail = false
	if err := client.reportMetrics(); err != nil {
		t.Fatal(err)
	}
	if processedValue(t, *gotBody, "ipv4") != 1 {
		t.Fatalf("retry must send restored processed, body=%s", *gotBody)
	}
}

func waitMetricsBody(t *testing.T, body *[]byte) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if len(*body) > 0 {
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
