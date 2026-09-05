package crowdsecconnection

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
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

func TestReportMetricsOfficialLabels(t *testing.T) {
	conn, body := newUsageMetricsConn(t)
	conn.IncDropped("lists:firehol_level1", "ipv4", "ban")
	conn.IncProcessed("ipv4")
	conn.rememberActiveDecision("ip:1.2.3.4", "crowdsec", "1.2.3.4")
	if err := conn.reportMetrics(); err != nil {
		t.Fatal(err)
	}
	assertOfficialUsageItems(t, usageMetricItems(t, *body))
}

func TestReportMetricsStartupTimestampStable(t *testing.T) {
	conn, body := newUsageMetricsConn(t)
	started := float64(conn.startedAt.Unix())
	if err := conn.reportMetrics(); err != nil {
		t.Fatal(err)
	}
	if usageStartupTimestamp(t, *body) != started {
		t.Fatalf("startup %v", usageStartupTimestamp(t, *body))
	}
	if err := conn.reportMetrics(); err != nil {
		t.Fatal(err)
	}
	if usageStartupTimestamp(t, *body) != started {
		t.Fatal("startup moved")
	}
}

func newUsageMetricsConn(t *testing.T) (*CrowdsecConnection, *[]byte) {
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
	conn := &CrowdsecConnection{
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
	return conn, gotBody
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
