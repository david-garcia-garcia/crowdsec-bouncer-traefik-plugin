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

type usageMetricsPayload struct {
	RemediationComponents []usageMetricsComponent `json:"remediation_components"`
}

type usageMetricsComponent struct {
	UTCStartupTimestamp int64    `json:"utc_startup_timestamp"`
	FeatureFlags        []string `json:"feature_flags"`
	Metrics             []struct {
		Items []usageMetricsItem `json:"items"`
	} `json:"metrics"`
}

type usageMetricsItem struct {
	Name   string            `json:"name"`
	Labels map[string]string `json:"labels"`
}

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
	component := decodeUsageMetricsComponent(t, *body)
	assertOfficialUsageItems(t, component.Metrics[0].Items)
}

func TestReportMetricsStartupTimestampStable(t *testing.T) {
	conn, body := newUsageMetricsConn(t)
	started := conn.startedAt.Unix()
	if err := conn.reportMetrics(); err != nil {
		t.Fatal(err)
	}
	first := decodeUsageMetricsComponent(t, *body)
	if first.UTCStartupTimestamp != started {
		t.Fatalf("startup %d", first.UTCStartupTimestamp)
	}
	if err := conn.reportMetrics(); err != nil {
		t.Fatal(err)
	}
	second := decodeUsageMetricsComponent(t, *body)
	if second.UTCStartupTimestamp != started {
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

func decodeUsageMetricsComponent(t *testing.T, body []byte) usageMetricsComponent {
	t.Helper()
	var payload usageMetricsPayload
	if err := json.Unmarshal(body, &payload); err != nil {
		t.Fatal(err)
	}
	if len(payload.RemediationComponents) == 0 {
		t.Fatal("no remediation_components")
	}
	component := payload.RemediationComponents[0]
	if len(component.Metrics) == 0 {
		t.Fatal("no metrics windows")
	}
	return component
}

func assertOfficialUsageItems(t *testing.T, items []usageMetricsItem) {
	t.Helper()
	foundDropped, foundProcessed, foundActive := false, false, false
	for _, item := range items {
		if _, ok := item.Labels["type"]; ok {
			t.Fatal("labels.type must not be sent")
		}
		switch item.Name {
		case "dropped":
			foundDropped = true
			if item.Labels["origin"] != "lists:firehol_level1" || item.Labels["ip_type"] != "ipv4" || item.Labels["remediation"] != "ban" {
				t.Fatalf("dropped labels %#v", item.Labels)
			}
		case "processed":
			foundProcessed = true
			if _, ok := item.Labels["origin"]; ok {
				t.Fatalf("processed should omit origin %#v", item.Labels)
			}
		case "active_decisions":
			foundActive = true
			if item.Labels["origin"] != "crowdsec" || item.Labels["ip_type"] != "ipv4" {
				t.Fatalf("active labels %#v", item.Labels)
			}
		}
	}
	if !foundDropped || !foundProcessed || !foundActive {
		t.Fatalf("missing items dropped=%v processed=%v active=%v", foundDropped, foundProcessed, foundActive)
	}
}
