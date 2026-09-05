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
	"github.com/maxlerebourg/crowdsec-bouncer-traefik-plugin/pkg/cache"
	"github.com/maxlerebourg/crowdsec-bouncer-traefik-plugin/pkg/configuration"
	"github.com/maxlerebourg/crowdsec-bouncer-traefik-plugin/pkg/crowdsecconnection"
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
			_ = json.NewEncoder(w).Encode(map[string][]crowdsecconnection.Decision{
				"new":     {},
				"deleted": {},
			})
			return
		}
		if strings.Contains(r.URL.Path, "decisions") {
			atomic.AddInt64(hits, 1)
			ip := r.URL.Query().Get("ip")
			if banned[ip] {
				_ = json.NewEncoder(w).Encode([]crowdsecconnection.Decision{{
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

func TestNew_SameConnectionFields_ShareIncarnation(t *testing.T) {
	reclaim.ResetWith(0)
	t.Cleanup(func() { reclaim.ResetWith(reclaim.DefaultGrace) })

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
	if !testRoute(t, a).SameConnection(testRoute(t, b)) {
		t.Fatal("same connection fields and different names must share one CrowdsecConnection")
	}
}

func TestNew_TwoLAPIs_IsolatedBan(t *testing.T) {
	reclaim.ResetWith(0)
	t.Cleanup(func() { reclaim.ResetWith(reclaim.DefaultGrace) })

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
	if testRoute(t, ha).SameConnection(testRoute(t, hb)) {
		t.Fatal("different LAPI hosts must not share a CrowdsecConnection")
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

	got, err := testRoute(t, hb).Connection().Cache().Get("1.2.3.4")
	if err == nil && got == cache.BannedValue {
		t.Fatal("B's cache must not contain A's ban")
	}
}

func TestNew_ReclaimWithinGrace(t *testing.T) {
	reclaim.ResetWith(500 * time.Millisecond)
	t.Cleanup(func() { reclaim.ResetWith(reclaim.DefaultGrace) })

	var zero int64
	srv := liveLAPI(t, nil, &zero)
	t.Cleanup(func() { srv.Close() })
	u, _ := url.Parse(srv.URL)
	ctx, cancel := context.WithCancel(context.Background())
	first, err := New(ctx, testNextOK(), cfgLiveAt(u.Host), "reclaim")
	if err != nil {
		t.Fatal(err)
	}
	conn1 := testRoute(t, first).Connection()
	cancel()
	time.Sleep(50 * time.Millisecond)
	second, err := New(context.Background(), testNextOK(), cfgLiveAt(u.Host), "reclaim")
	if err != nil {
		t.Fatal(err)
	}
	if testRoute(t, second).Connection() != conn1 {
		t.Fatal("Open within grace must reclaim the same CrowdsecConnection")
	}
}

func TestNew_DisposeAfterGrace(t *testing.T) {
	reclaim.ResetWith(20 * time.Millisecond)
	t.Cleanup(func() { reclaim.ResetWith(reclaim.DefaultGrace) })

	var zero int64
	srv := liveLAPI(t, nil, &zero)
	t.Cleanup(func() { srv.Close() })
	u, _ := url.Parse(srv.URL)
	ctx, cancel := context.WithCancel(context.Background())
	first, err := New(ctx, testNextOK(), cfgLiveAt(u.Host), "dispose")
	if err != nil {
		t.Fatal(err)
	}
	conn1 := testRoute(t, first).Connection()
	cancel()
	time.Sleep(150 * time.Millisecond)
	second, err := New(context.Background(), testNextOK(), cfgLiveAt(u.Host), "dispose")
	if err != nil {
		t.Fatal(err)
	}
	if testRoute(t, second).Connection() == conn1 {
		t.Fatal("after grace the previous CrowdsecConnection must be disposed")
	}
}

func TestNew_StreamVsLive_SideBySide(t *testing.T) {
	reclaim.ResetWith(0)
	t.Cleanup(func() { reclaim.ResetWith(reclaim.DefaultGrace) })

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
	if testRoute(t, hs).SameConnection(testRoute(t, hl)) {
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

	if testRoute(t, hs).Connection().StreamFetches() < 1 {
		t.Fatal("stream connection must poll its own stream endpoint")
	}
}

func TestBouncer_ServeHTTP_Matrix(t *testing.T) {
	reclaim.ResetWith(0)
	t.Cleanup(func() { reclaim.ResetWith(reclaim.DefaultGrace) })

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
	reclaim.ResetWith(0)
	t.Cleanup(func() { reclaim.ResetWith(reclaim.DefaultGrace) })

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
	if testRoute(t, ha).Connection().StreamFetches() < 1 || testRoute(t, hb).Connection().StreamFetches() < 1 {
		t.Fatal("each stream connection must fetch its own LAPI")
	}
	if atomic.LoadInt64(&hitsA) < 1 || atomic.LoadInt64(&hitsB) < 1 {
		t.Fatalf("LAPI hits A=%d B=%d", atomic.LoadInt64(&hitsA), atomic.LoadInt64(&hitsB))
	}
}
