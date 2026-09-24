package crowdsec_bouncer_traefik_plugin //nolint:revive,stylecheck

import (
	"context"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sync/atomic"
	"testing"

	"github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pkg/configuration"
	"github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pkg/lapi"
	"github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pkg/reclaim"
)

func TestServeHTTP_LiveFailureAction(t *testing.T) {
	reclaim.ResetForTestWith(0)
	t.Cleanup(func() { reclaim.ResetForTest() })

	var hits int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("ip") != "" {
			atomic.AddInt64(&hits, 1)
		}
		w.WriteHeader(http.StatusInternalServerError)
	}))
	t.Cleanup(srv.Close)
	parsed, err := url.Parse(srv.URL)
	if err != nil {
		t.Fatal(err)
	}

	banCfg := cfgLiveAt(parsed.Host)
	banCfg.LogLevel = "ERROR"
	banCfg.BouncerLapiFailureAction = configuration.FailureActionBan
	banHandler, err := New(context.Background(), testNextOK(), banCfg, "live-fail-ban")
	if err != nil {
		t.Fatal(err)
	}
	banRW := httptest.NewRecorder()
	banHandler.ServeHTTP(banRW, reqForIP("203.0.113.10"))
	if banRW.Code != http.StatusForbidden {
		t.Fatalf("live LAPI 500 ban status = %d", banRW.Code)
	}

	passCfg := cfgLiveAt(parsed.Host)
	passCfg.LogLevel = "ERROR"
	passCfg.LapiKey = "other-key"
	passCfg.BouncerLapiFailureAction = configuration.FailureActionPassthrough
	passHandler, err := New(context.Background(), testNextOK(), passCfg, "live-fail-pass")
	if err != nil {
		t.Fatal(err)
	}
	passRW := httptest.NewRecorder()
	passHandler.ServeHTTP(passRW, reqForIP("203.0.113.11"))
	if passRW.Code != http.StatusOK || passRW.Body.String() != "OK" {
		t.Fatalf("live LAPI 500 passthrough status=%d body=%q", passRW.Code, passRW.Body.String())
	}
	if atomic.LoadInt64(&hits) < 2 {
		t.Fatalf("both failure-action requests must query LAPI, hits=%d", hits)
	}
}

func TestServeHTTP_LiveBanOutranksScopeError(t *testing.T) {
	reclaim.ResetForTestWith(0)
	t.Cleanup(func() { reclaim.ResetForTest() })

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		query := r.URL.Query()
		if query.Get("scope") == "country" {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		_ = json.NewEncoder(w).Encode([]lapi.Decision{{
			Value: query.Get("ip"), Type: "ban", Duration: "1h", Origin: "CAPI", Scope: "ip",
		}})
	}))
	t.Cleanup(srv.Close)
	parsed, err := url.Parse(srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	cfg := cfgLiveAt(parsed.Host)
	cfg.LogLevel = "ERROR"
	cfg.BouncerLapiFailureAction = configuration.FailureActionPassthrough
	cfg.BouncerDecisionScopeHeaders = map[string]string{"country": "CF-IPCountry"}
	handler, err := New(context.Background(), testNextOK(), cfg, "live-ban-scope")
	if err != nil {
		t.Fatal(err)
	}
	req := reqForIP("203.0.113.20")
	req.Header.Set("Cf-Ipcountry", "FR")
	rw := httptest.NewRecorder()
	handler.ServeHTTP(rw, req)
	if rw.Code != http.StatusForbidden {
		t.Fatalf("active ban must not become passthrough, status=%d body=%q", rw.Code, rw.Body.String())
	}
}

func TestServeHTTP_NoneModeQueriesEveryRequest(t *testing.T) {
	reclaim.ResetForTestWith(0)
	t.Cleanup(func() { reclaim.ResetForTest() })

	var hits int64
	srv := liveLAPI(t, map[string]bool{}, &hits)
	t.Cleanup(srv.Close)
	parsed, err := url.Parse(srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	cfg := cfgLiveAt(parsed.Host)
	cfg.LogLevel = "ERROR"
	cfg.LapiMode = configuration.NoneMode
	handler, err := New(context.Background(), testNextOK(), cfg, "none-every")
	if err != nil {
		t.Fatal(err)
	}
	for range 2 {
		rw := httptest.NewRecorder()
		handler.ServeHTTP(rw, reqForIP("203.0.113.30"))
		if rw.Code != http.StatusOK {
			t.Fatalf("none-mode allow status = %d", rw.Code)
		}
	}
	if got := atomic.LoadInt64(&hits); got != 2 {
		t.Fatalf("none mode hits = %d, want 2 (no live memo)", got)
	}

	banSrv := liveLAPI(t, map[string]bool{"203.0.113.31": true}, &hits)
	t.Cleanup(banSrv.Close)
	banParsed, err := url.Parse(banSrv.URL)
	if err != nil {
		t.Fatal(err)
	}
	banCfg := cfgLiveAt(banParsed.Host)
	banCfg.LogLevel = "ERROR"
	banCfg.LapiMode = configuration.NoneMode
	banCfg.LapiKey = "none-ban-key"
	banHandler, err := New(context.Background(), testNextOK(), banCfg, "none-ban")
	if err != nil {
		t.Fatal(err)
	}
	banRW := httptest.NewRecorder()
	banHandler.ServeHTTP(banRW, reqForIP("203.0.113.31"))
	if banRW.Code != http.StatusForbidden {
		t.Fatalf("none-mode ban status = %d", banRW.Code)
	}
}

func TestServeHTTP_RedisUnreachableFailureAction(t *testing.T) {
	reclaim.ResetForTestWith(0)
	t.Cleanup(func() { reclaim.ResetForTest() })

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	redisAddr := listener.Addr().String()
	if closeErr := listener.Close(); closeErr != nil {
		t.Fatal(closeErr)
	}
	var hits int64
	srv := liveLAPI(t, map[string]bool{"203.0.113.40": true}, &hits)
	t.Cleanup(srv.Close)
	parsed, err := url.Parse(srv.URL)
	if err != nil {
		t.Fatal(err)
	}

	passCfg := cfgLiveAt(parsed.Host)
	passCfg.LogLevel = "ERROR"
	passCfg.LapiRedisEnabled = true
	passCfg.LapiRedisHost = redisAddr
	passCfg.BouncerRedisUnreachableBlock = false
	passHandler, err := New(context.Background(), testNextOK(), passCfg, "redis-pass")
	if err != nil {
		t.Fatal(err)
	}
	before := atomic.LoadInt64(&hits)
	passRW := httptest.NewRecorder()
	passHandler.ServeHTTP(passRW, reqForIP("203.0.113.40"))
	if passRW.Code != http.StatusOK {
		t.Fatalf("redis unreachable passthrough status = %d", passRW.Code)
	}
	if atomic.LoadInt64(&hits) != before {
		t.Fatal("redis unreachable must not fall through to LiveLookup")
	}

	blockCfg := cfgLiveAt(parsed.Host)
	blockCfg.LogLevel = "ERROR"
	blockCfg.LapiKey = "redis-block-key"
	blockCfg.LapiRedisEnabled = true
	blockCfg.LapiRedisHost = redisAddr
	blockCfg.BouncerRedisUnreachableBlock = true
	blockHandler, err := New(context.Background(), testNextOK(), blockCfg, "redis-block")
	if err != nil {
		t.Fatal(err)
	}
	blockRW := httptest.NewRecorder()
	blockHandler.ServeHTTP(blockRW, reqForIP("203.0.113.41"))
	if blockRW.Code != http.StatusForbidden {
		t.Fatalf("redis unreachable block status = %d", blockRW.Code)
	}
}
