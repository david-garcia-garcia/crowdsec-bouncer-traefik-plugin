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
	var gotBody []byte
	lapi := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
		if req.URL.Path != "/v1/usage-metrics" {
			t.Errorf("path %s", req.URL.Path)
		}
		gotBody, _ = io.ReadAll(req.Body)
		rw.WriteHeader(http.StatusCreated)
	}))
	t.Cleanup(lapi.Close)
	lapiURL, _ := url.Parse(lapi.URL)
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
	conn.IncDropped("lists:firehol_level1", "ipv4", "ban")
	conn.IncProcessed("ipv4")
	conn.rememberActiveDecision("ip:1.2.3.4", "crowdsec", "1.2.3.4")
	if err := conn.reportMetrics(); err != nil {
		t.Fatal(err)
	}
	var payload map[string]interface{}
	if err := json.Unmarshal(gotBody, &payload); err != nil {
		t.Fatal(err)
	}
	rc := payload["remediation_components"].([]interface{})[0].(map[string]interface{})
	if rc["utc_startup_timestamp"].(float64) != float64(started.Unix()) {
		t.Fatalf("startup %v", rc["utc_startup_timestamp"])
	}
	items := rc["metrics"].([]interface{})[0].(map[string]interface{})["items"].([]interface{})
	foundDropped, foundProcessed, foundActive, foundTypeLabel := false, false, false, false
	for _, raw := range items {
		item := raw.(map[string]interface{})
		labels, _ := item["labels"].(map[string]interface{})
		if labels != nil {
			if _, ok := labels["type"]; ok {
				foundTypeLabel = true
			}
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
		t.Fatalf("missing items dropped=%v processed=%v active=%v body=%s", foundDropped, foundProcessed, foundActive, string(gotBody))
	}
	if foundTypeLabel {
		t.Fatal("labels.type must not be sent")
	}
	if err := conn.reportMetrics(); err != nil {
		t.Fatal(err)
	}
	if rc2, err := json.Marshal(gotBody); err == nil && string(rc2) == "" {
		t.Fatal("second push empty marshal")
	}
	var second map[string]interface{}
	if err := json.Unmarshal(gotBody, &second); err != nil {
		t.Fatal(err)
	}
	rcSecond := second["remediation_components"].([]interface{})[0].(map[string]interface{})
	if rcSecond["utc_startup_timestamp"].(float64) != float64(started.Unix()) {
		t.Fatal("startup moved")
	}
}
