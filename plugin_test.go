package crowdsec_bouncer_traefik_plugin //nolint:revive,stylecheck

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/maxlerebourg/crowdsec-bouncer-traefik-plugin/pkg/bouncer"
	"github.com/maxlerebourg/crowdsec-bouncer-traefik-plugin/pkg/configuration"
	"github.com/maxlerebourg/crowdsec-bouncer-traefik-plugin/pkg/decisionscope"
	"github.com/maxlerebourg/crowdsec-bouncer-traefik-plugin/pkg/lapi"
	"github.com/maxlerebourg/crowdsec-bouncer-traefik-plugin/pkg/reclaim"
)

func testNextOK() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("OK"))
	})
}

func testRoute(t *testing.T, h http.Handler) *bouncer.Bouncer {
	t.Helper()
	b, ok := h.(*bouncer.Bouncer)
	if !ok {
		t.Fatalf("handler type %T, want *bouncer.Bouncer", h)
	}
	return b
}

func liveLAPI(t *testing.T, banned map[string]bool, hits *int64) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.Path, "stream") {
			atomic.AddInt64(hits, 1)
			_ = json.NewEncoder(w).Encode(map[string][]lapi.Decision{
				"new":     {},
				"deleted": {},
			})
			return
		}
		if strings.Contains(r.URL.Path, "decisions") {
			atomic.AddInt64(hits, 1)
			ip := r.URL.Query().Get("ip")
			if banned[ip] {
				_ = json.NewEncoder(w).Encode([]lapi.Decision{{
					Value:    ip,
					Type:     "ban",
					Duration: "1h",
				}})
				return
			}
			_, _ = w.Write([]byte("null"))
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
}

func cfgLiveAt(host string) *configuration.Config {
	c := getTestConfig()
	c.Enabled = true
	c.CrowdsecMode = configuration.LiveMode
	c.CrowdsecLapiHost = host
	c.CrowdsecLapiPath = "/"
	c.CrowdsecLapiScheme = "http"
	c.MetricsUpdateIntervalSeconds = 0
	c.ForwardedHeadersTrustedIPs = []string{"127.0.0.1/32"}
	c.ForwardedHeadersCustomName = "X-Forwarded-For"
	c.DefaultDecisionSeconds = 2
	return c
}

func cfgStreamAt(host string, interval int64) *configuration.Config {
	c := cfgLiveAt(host)
	c.CrowdsecMode = configuration.StreamMode
	c.UpdateIntervalSeconds = interval
	c.StreamStartupBlock = true
	return c
}

func reqForIP(ip string) *http.Request {
	req := httptest.NewRequest(http.MethodGet, "http://example.com/foo", nil)
	req.RemoteAddr = "127.0.0.1:9"
	req.Header.Set("X-Forwarded-For", ip)
	return req
}

func TestServeHTTP(t *testing.T) {
	cfg := CreateConfig()
	cfg.CrowdsecLapiKey = "test"
	ctx := context.Background()
	handler, err := New(ctx, testNextOK(), cfg, "demo-plugin")
	if err != nil {
		t.Fatal(err)
	}
	recorder := httptest.NewRecorder()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://localhost", nil)
	if err != nil {
		t.Fatal(err)
	}
	handler.ServeHTTP(recorder, req)
}

// TestNew_LAPIUserAgentUsesVersionGo checks New sends LAPI User-Agent from version.go pluginVersion.
func TestNew_LAPIUserAgentUsesVersionGo(t *testing.T) {
	reclaim.ResetForTestWith(0)
	t.Cleanup(func() { reclaim.ResetForTestWith(reclaim.DefaultGrace) })

	gotUA := ""
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotUA = r.Header.Get("User-Agent")
		if strings.Contains(r.URL.Path, "decisions") {
			_, _ = w.Write([]byte("null"))
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(srv.Close)
	u, err := url.Parse(srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	h, err := New(ctx, testNextOK(), cfgLiveAt(u.Host), "version-ua")
	if err != nil {
		t.Fatal(err)
	}
	h.ServeHTTP(httptest.NewRecorder(), reqForIP("192.0.2.1"))
	if pluginVersion == "" {
		t.Fatal("pluginVersion must not be empty")
	}
	wantUA := "Crowdsec-Bouncer-Traefik-Plugin/" + pluginVersion
	if gotUA != wantUA {
		t.Fatalf("User-Agent %q want %q", gotUA, wantUA)
	}
}

func TestNew_SameLapiClientFields_ShareIncarnation(t *testing.T) {
	reclaim.ResetForTestWith(0)
	t.Cleanup(func() { reclaim.ResetForTestWith(reclaim.DefaultGrace) })

	var zero int64
	srv := liveLAPI(t, nil, &zero)
	t.Cleanup(func() { srv.Close() })
	u, _ := url.Parse(srv.URL)
	ctx := context.Background()
	a, err := New(ctx, testNextOK(), cfgLiveAt(u.Host), "alias-a")
	if err != nil {
		t.Fatal(err)
	}
	b, err := New(ctx, testNextOK(), cfgLiveAt(u.Host), "alias-b")
	if err != nil {
		t.Fatal(err)
	}
	if !testRoute(t, a).SameLapiClient(testRoute(t, b)) {
		t.Fatal("same LAPI fields and different names must share one lapi.Client")
	}
}

func TestNew_TwoLAPIs_IsolatedBan(t *testing.T) {
	reclaim.ResetForTestWith(0)
	t.Cleanup(func() { reclaim.ResetForTestWith(reclaim.DefaultGrace) })

	var hitsA, hitsB int64
	lapiA := liveLAPI(t, map[string]bool{"1.2.3.4": true}, &hitsA)
	lapiB := liveLAPI(t, map[string]bool{}, &hitsB)
	t.Cleanup(func() { lapiA.Close() })
	t.Cleanup(func() { lapiB.Close() })
	ua, _ := url.Parse(lapiA.URL)
	ub, _ := url.Parse(lapiB.URL)

	ctx := context.Background()
	ha, err := New(ctx, testNextOK(), cfgLiveAt(ua.Host), "bouncer-a")
	if err != nil {
		t.Fatal(err)
	}
	hb, err := New(ctx, testNextOK(), cfgLiveAt(ub.Host), "bouncer-b")
	if err != nil {
		t.Fatal(err)
	}
	if testRoute(t, ha).SameLapiClient(testRoute(t, hb)) {
		t.Fatal("different LAPI hosts must not share a lapi.Client")
	}

	ra := httptest.NewRecorder()
	ha.ServeHTTP(ra, reqForIP("1.2.3.4"))
	if ra.Code != http.StatusForbidden {
		t.Fatalf("bouncer A: got %d want 403", ra.Code)
	}
	rb := httptest.NewRecorder()
	hb.ServeHTTP(rb, reqForIP("1.2.3.4"))
	if rb.Code != http.StatusOK {
		t.Fatalf("bouncer B: got %d want 200", rb.Code)
	}

	got, err := testRoute(t, hb).LapiClient().Cache().Get("1.2.3.4")
	if err == nil && got == decisionscope.BannedValue {
		t.Fatal("B's cache must not contain A's ban")
	}
}

func TestNew_ReclaimWithinGrace(t *testing.T) {
	reclaim.ResetForTestWith(500 * time.Millisecond)
	t.Cleanup(func() { reclaim.ResetForTestWith(reclaim.DefaultGrace) })

	var zero int64
	srv := liveLAPI(t, nil, &zero)
	t.Cleanup(func() { srv.Close() })
	u, _ := url.Parse(srv.URL)
	ctx, cancel := context.WithCancel(context.Background())
	first, err := New(ctx, testNextOK(), cfgLiveAt(u.Host), "reclaim")
	if err != nil {
		t.Fatal(err)
	}
	firstLapiClient := testRoute(t, first).LapiClient()
	cancel()
	time.Sleep(50 * time.Millisecond)
	second, err := New(context.Background(), testNextOK(), cfgLiveAt(u.Host), "reclaim")
	if err != nil {
		t.Fatal(err)
	}
	if testRoute(t, second).LapiClient() != firstLapiClient {
		t.Fatal("Open within grace must reclaim the same lapi.Client")
	}
}

func TestNew_DisposeAfterGrace(t *testing.T) {
	reclaim.ResetForTestWith(20 * time.Millisecond)
	t.Cleanup(func() { reclaim.ResetForTestWith(reclaim.DefaultGrace) })

	var zero int64
	srv := liveLAPI(t, nil, &zero)
	t.Cleanup(func() { srv.Close() })
	u, _ := url.Parse(srv.URL)
	cfg := cfgLiveAt(u.Host)
	ctx, cancel := context.WithCancel(context.Background())
	first, err := New(ctx, testNextOK(), cfg, "dispose")
	if err != nil {
		t.Fatal(err)
	}
	firstLapiClient := testRoute(t, first).LapiClient()
	cancel()
	time.Sleep(150 * time.Millisecond)
	view := reclaim.Peek(lapi.Key(cfg))
	if !view.OK || view.Holders != 0 || !view.Sleeping {
		t.Fatalf("lapi.Client must still be in its 30s grace after table 20ms: found=%v holders=%d sleeping=%v", view.OK, view.Holders, view.Sleeping)
	}
	time.Sleep(lapi.ReclaimGraceDuration)
	second, err := New(context.Background(), testNextOK(), cfgLiveAt(u.Host), "dispose")
	if err != nil {
		t.Fatal(err)
	}
	if testRoute(t, second).LapiClient() == firstLapiClient {
		t.Fatal("after lapi.Client grace the previous incarnation must be disposed")
	}
}

func TestNew_StreamVsLive_SideBySide(t *testing.T) {
	reclaim.ResetForTestWith(0)
	t.Cleanup(func() { reclaim.ResetForTestWith(reclaim.DefaultGrace) })

	var streamHits, liveHits int64
	streamSrv := liveLAPI(t, map[string]bool{"9.9.9.9": true}, &streamHits)
	liveSrv := liveLAPI(t, map[string]bool{}, &liveHits)
	t.Cleanup(func() { streamSrv.Close() })
	t.Cleanup(func() { liveSrv.Close() })
	us, _ := url.Parse(streamSrv.URL)
	ul, _ := url.Parse(liveSrv.URL)

	ctx := context.Background()
	hs, err := New(ctx, testNextOK(), cfgStreamAt(us.Host, 60), "stream")
	if err != nil {
		t.Fatal(err)
	}
	hl, err := New(ctx, testNextOK(), cfgLiveAt(ul.Host), "live")
	if err != nil {
		t.Fatal(err)
	}
	if testRoute(t, hs).SameLapiClient(testRoute(t, hl)) {
		t.Fatal("stream and live configs must be two connections")
	}

	beforeLive := atomic.LoadInt64(&liveHits)
	rw := httptest.NewRecorder()
	hl.ServeHTTP(rw, reqForIP("5.6.7.8"))
	if rw.Code != http.StatusOK {
		t.Fatalf("live miss: got %d", rw.Code)
	}
	if atomic.LoadInt64(&liveHits) <= beforeLive {
		t.Fatal("live ServeHTTP must query only the live LAPI")
	}

	if testRoute(t, hs).LapiClient().StreamFetches() < 1 {
		t.Fatal("stream connection must poll its own stream endpoint")
	}
}

func TestBouncer_ServeHTTP_Matrix(t *testing.T) {
	reclaim.ResetForTestWith(0)
	t.Cleanup(func() { reclaim.ResetForTestWith(reclaim.DefaultGrace) })

	var hits int64
	srv := liveLAPI(t, map[string]bool{"8.8.8.8": true}, &hits)
	t.Cleanup(func() { srv.Close() })
	u, _ := url.Parse(srv.URL)
	ctx := context.Background()

	disabled := cfgLiveAt(u.Host)
	disabled.Enabled = false
	hOff, err := New(ctx, testNextOK(), disabled, "off")
	if err != nil {
		t.Fatal(err)
	}
	rw := httptest.NewRecorder()
	hOff.ServeHTTP(rw, reqForIP("8.8.8.8"))
	if rw.Code != http.StatusOK {
		t.Fatalf("disabled: got %d", rw.Code)
	}

	trusted := cfgLiveAt(u.Host)
	trusted.ClientTrustedIPs = []string{"9.9.9.9/32"}
	hTrust, err := New(ctx, testNextOK(), trusted, "trust")
	if err != nil {
		t.Fatal(err)
	}
	rw = httptest.NewRecorder()
	hTrust.ServeHTTP(rw, reqForIP("9.9.9.9"))
	if rw.Code != http.StatusOK {
		t.Fatalf("trusted IP: got %d", rw.Code)
	}

	h, err := New(ctx, testNextOK(), cfgLiveAt(u.Host), "live")
	if err != nil {
		t.Fatal(err)
	}
	rw = httptest.NewRecorder()
	h.ServeHTTP(rw, reqForIP("8.8.8.8"))
	if rw.Code != http.StatusForbidden {
		t.Fatalf("banned: got %d", rw.Code)
	}
	rw = httptest.NewRecorder()
	h.ServeHTTP(rw, reqForIP("1.1.1.1"))
	if rw.Code != http.StatusOK {
		t.Fatalf("allowed: got %d", rw.Code)
	}
}

func TestNew_TwoStreamConnections_BothPoll(t *testing.T) {
	reclaim.ResetForTestWith(0)
	t.Cleanup(func() { reclaim.ResetForTestWith(reclaim.DefaultGrace) })

	var hitsA, hitsB int64
	a := liveLAPI(t, nil, &hitsA)
	b := liveLAPI(t, nil, &hitsB)
	t.Cleanup(func() { a.Close() })
	t.Cleanup(func() { b.Close() })
	ua, _ := url.Parse(a.URL)
	ub, _ := url.Parse(b.URL)
	ctx := context.Background()
	ha, err := New(ctx, testNextOK(), cfgStreamAt(ua.Host, 60), "s-a")
	if err != nil {
		t.Fatal(err)
	}
	hb, err := New(ctx, testNextOK(), cfgStreamAt(ub.Host, 30), "s-b")
	if err != nil {
		t.Fatal(err)
	}
	if testRoute(t, ha).LapiClient().StreamFetches() < 1 || testRoute(t, hb).LapiClient().StreamFetches() < 1 {
		t.Fatal("each stream connection must fetch its own LAPI")
	}
	if atomic.LoadInt64(&hitsA) < 1 || atomic.LoadInt64(&hitsB) < 1 {
		t.Fatalf("LAPI hits A=%d B=%d", atomic.LoadInt64(&hitsA), atomic.LoadInt64(&hitsB))
	}
}

func TestNew_SameStreamKeyDifferentMetrics_SharesConnection(t *testing.T) {
	// CrowdSec stores both stream_cursor and usage-metrics on the bouncer row
	// (hashed X-Api-Key + the IP LAPI sees). Two metrics intervals on one key
	// must share one connection: a second ticker would steal stream deltas and
	// POST a second metrics window for the same bouncer. Interval is first-wins.
	reclaim.ResetForTestWith(0)
	t.Cleanup(func() { reclaim.ResetForTestWith(reclaim.DefaultGrace) })

	var hits int64
	srv := liveLAPI(t, nil, &hits)
	t.Cleanup(func() { srv.Close() })
	u, _ := url.Parse(srv.URL)

	fast := cfgStreamAt(u.Host, 60)
	fast.MetricsUpdateIntervalSeconds = 1
	slow := cfgStreamAt(u.Host, 60)
	slow.MetricsUpdateIntervalSeconds = 600

	ctx := context.Background()
	owner, err := New(ctx, testNextOK(), fast, "stream-fast")
	if err != nil {
		t.Fatal(err)
	}
	joiner, err := New(ctx, testNextOK(), slow, "stream-slow")
	if err != nil {
		t.Fatal(err)
	}
	if !testRoute(t, owner).SameLapiClient(testRoute(t, joiner)) {
		t.Fatal("same LAPI key and different metrics interval must share one stream connection")
	}
	if atomic.LoadInt64(&hits) != 1 {
		t.Fatalf("one ticker must poll once at startup, hits=%d", atomic.LoadInt64(&hits))
	}
}

func TestNew_StreamSnapshotChangeDuringGrace_ReplacesTicker(t *testing.T) {
	reclaim.ResetForTestWith(500 * time.Millisecond)
	t.Cleanup(func() { reclaim.ResetForTestWith(reclaim.DefaultGrace) })

	var hits int64
	srv := liveLAPI(t, nil, &hits)
	t.Cleanup(func() { srv.Close() })
	u, _ := url.Parse(srv.URL)

	ctx, cancel := context.WithCancel(context.Background())
	firstCfg := cfgStreamAt(u.Host, 60)
	firstCfg.MetricsUpdateIntervalSeconds = 1
	first, err := New(ctx, testNextOK(), firstCfg, "stream-old")
	if err != nil {
		t.Fatal(err)
	}
	oldLapiClient := testRoute(t, first).LapiClient()
	fetchesBeforeCancel := oldLapiClient.StreamFetches()
	cancel()
	waitPluginStreamInGrace(t, firstCfg)

	reloadCfg := cfgStreamAt(u.Host, 60)
	reloadCfg.MetricsUpdateIntervalSeconds = 600
	reloaded, err := New(context.Background(), testNextOK(), reloadCfg, "stream-new")
	if err != nil {
		t.Fatal(err)
	}
	newLapiClient := testRoute(t, reloaded).LapiClient()
	if newLapiClient == oldLapiClient {
		t.Fatal("changed snapshot during grace must not reclaim the old ticker")
	}
	if oldLapiClient.StreamFetches() != fetchesBeforeCancel {
		t.Fatal("old ticker must be stopped before the new poller starts")
	}
	if newLapiClient.StreamFetches() < 1 {
		t.Fatal("new snapshot must poll LAPI")
	}
}

func waitPluginStreamInGrace(t *testing.T, cfg *configuration.Config) {
	t.Helper()
	sessionKey := lapi.SessionKey(cfg)
	deadline := time.Now().Add(2 * time.Second)
	var view reclaim.View
	for time.Now().Before(deadline) {
		view = reclaim.Peek(sessionKey)
		if view.OK && view.Holders == 0 && view.Sleeping {
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatalf("stream session did not enter grace: found=%v holders=%d sleeping=%v", view.OK, view.Holders, view.Sleeping)
}
