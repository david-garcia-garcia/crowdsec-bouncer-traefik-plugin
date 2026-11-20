package crowdsec_bouncer_traefik_plugin //nolint:revive,stylecheck

import (
	"context"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"

	"github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pkg/configuration"
	"github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pkg/ratelimit"
	"github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pkg/reclaim"
)

// testRateLimitDeadRedis is an address where nothing listens; New must not dial it.
const testRateLimitDeadRedis = "127.0.0.1:1"

// cfgRateLimitDeadRedis is a bounce-only router (no LAPI, no AppSec) with the rate-limit leg on against a dead Redis.
func cfgRateLimitDeadRedis() *configuration.Config {
	c := getTestConfig()
	c.LapiEnabled = false
	c.LapiKey = ""
	c.BouncerRemediationHeadersCustomName = "X-Remediation"
	enableTestRateLimit(c, testRateLimitDeadRedis)
	return c
}

// enableTestRateLimit turns the rate-limit leg on in c with the CreateConfig defaults and one per-ip bucket.
func enableTestRateLimit(c *configuration.Config, redisHost string) {
	defaults := configuration.New()
	c.RateLimitEnabled = true
	c.RateLimitStore = defaults.RateLimitStore
	c.RateLimitRedisHost = redisHost
	c.RateLimitSyncRate = defaults.RateLimitSyncRate
	c.RateLimitStatusCode = defaults.RateLimitStatusCode
	c.RateLimitResponseHeaders = defaults.RateLimitResponseHeaders
	c.RateLimitFailureAction = defaults.RateLimitFailureAction
	c.RateLimitBuckets = []ratelimit.BucketRule{
		{Name: "per-ip", Requests: 5, Window: "1m", Key: []ratelimit.KeyPart{{From: ratelimit.KeyFromIP}}},
	}
}

// rateLimitTestOwnershipKey is the reclaim key New opens for cfg under middleware name.
func rateLimitTestOwnershipKey(t *testing.T, cfg *configuration.Config, name string) string {
	t.Helper()
	syncRate, err := configuration.RateLimitSyncRateDuration(cfg)
	if err != nil {
		t.Fatal(err)
	}
	return ratelimit.OwnershipKey(name, ratelimit.RedisSettings{
		Database: cfg.RateLimitRedisDatabase,
		Host:     cfg.RateLimitRedisHost,
		Password: cfg.RateLimitRedisPassword,
		SyncRate: syncRate,
	})
}

// TestNew_RateLimitDisabledOpensNothing proves a disabled leg opens no counter and ignores a missing password file.
func TestNew_RateLimitDisabledOpensNothing(t *testing.T) {
	reclaim.ResetForTestWith(0)
	t.Cleanup(func() { reclaim.ResetForTest() })

	cfg := cfgRateLimitDeadRedis()
	cfg.RateLimitEnabled = false
	cfg.RateLimitRedisPasswordFile = filepath.Join(t.TempDir(), "missing-redis-password")
	h, err := New(context.Background(), testNextOK(), cfg, "rl-off")
	if err != nil {
		t.Fatalf("a disabled leg must not fail New: %v", err)
	}
	if _, _, ok := reclaim.Peek(rateLimitTestOwnershipKey(t, cfgRateLimitDeadRedis(), "rl-off")); ok {
		t.Fatal("a disabled leg must not open a counter")
	}
	// Seven requests on a limit of five; a slice, not range-over-int, because yaegi runs this file.
	for request := range make([]struct{}, 7) {
		rw := httptest.NewRecorder()
		h.ServeHTTP(rw, reqForIP("203.0.113.40"))
		if rw.Code != http.StatusOK {
			t.Fatalf("request %d status %d: a disabled leg must not limit", request, rw.Code)
		}
	}
}

// TestNew_RateLimitSharesOneCounter proves two New calls with the same middleware name and settings
// share one counter, and that a changed sync rate opens another.
func TestNew_RateLimitSharesOneCounter(t *testing.T) {
	reclaim.ResetForTestWith(0)
	t.Cleanup(func() { reclaim.ResetForTest() })

	cfg := cfgRateLimitDeadRedis()
	if _, err := New(context.Background(), testNextOK(), cfg, "rl-shared"); err != nil {
		t.Fatal(err)
	}
	first, _, ok := reclaim.Peek(rateLimitTestOwnershipKey(t, cfg, "rl-shared"))
	if !ok {
		t.Fatal("an enabled leg must open a counter")
	}
	if _, err := New(context.Background(), testNextOK(), cfgRateLimitDeadRedis(), "rl-shared"); err != nil {
		t.Fatal(err)
	}
	if second, _, _ := reclaim.Peek(rateLimitTestOwnershipKey(t, cfg, "rl-shared")); second != first {
		t.Fatal("same middleware name and settings must share one counter")
	}
	exact := cfgRateLimitDeadRedis()
	exact.RateLimitSyncRate = "0"
	if _, err := New(context.Background(), testNextOK(), exact, "rl-shared"); err != nil {
		t.Fatal(err)
	}
	if other, _, ok := reclaim.Peek(rateLimitTestOwnershipKey(t, exact, "rl-shared")); !ok || other == first {
		t.Fatal("a changed sync rate must open a new counter")
	}
}

// TestNew_RateLimitReleasedWhenNewFailsAfterOpen proves a New that fails after opening the counter
// (here: a taken captcha instance name) releases that holder.
func TestNew_RateLimitReleasedWhenNewFailsAfterOpen(t *testing.T) {
	reclaim.ResetForTestWith(0)
	t.Cleanup(func() { reclaim.ResetForTest() })

	if _, err := New(context.Background(), testNextOK(), cfgCaptchaOwnerAt(t, "shared"), "rl-captcha-a"); err != nil {
		t.Fatal(err)
	}
	cfg := cfgCaptchaOwnerAt(t, "shared")
	enableTestRateLimit(cfg, testRateLimitDeadRedis)
	if _, err := New(context.Background(), testNextOK(), cfg, "rl-captcha-b"); err == nil {
		t.Fatal("a second captcha publisher on the same name must fail")
	}
	time.Sleep(100 * time.Millisecond)
	if _, _, ok := reclaim.Peek(rateLimitTestOwnershipKey(t, cfg, "rl-captcha-b")); ok {
		t.Fatal("a failed New must release the rate-limit counter it opened")
	}
}

// TestNew_RateLimitDeadRedisFailureAction proves an unreachable Redis does not fail New, and that the
// returned handler applies the failure action: passthrough reaches the backend, ban answers ban:ratelimit-failure.
func TestNew_RateLimitDeadRedisFailureAction(t *testing.T) {
	reclaim.ResetForTestWith(0)
	t.Cleanup(func() { reclaim.ResetForTest() })

	passthrough, err := New(context.Background(), testNextOK(), cfgRateLimitDeadRedis(), "rl-passthrough")
	if err != nil {
		t.Fatalf("an unreachable Redis must not fail New: %v", err)
	}
	rw := httptest.NewRecorder()
	passthrough.ServeHTTP(rw, reqForIP("203.0.113.41"))
	if rw.Code != http.StatusOK || rw.Header().Get("X-Remediation") != "" {
		t.Fatalf("passthrough: status %d header %q", rw.Code, rw.Header().Get("X-Remediation"))
	}

	banCfg := cfgRateLimitDeadRedis()
	banCfg.RateLimitFailureAction = configuration.FailureActionBan
	ban, err := New(context.Background(), testNextOK(), banCfg, "rl-ban")
	if err != nil {
		t.Fatal(err)
	}
	rw = httptest.NewRecorder()
	ban.ServeHTTP(rw, reqForIP("203.0.113.42"))
	if rw.Code != http.StatusForbidden || rw.Header().Get("X-Remediation") != "ban:ratelimit-failure" {
		t.Fatalf("ban: status %d header %q, want 403 ban:ratelimit-failure", rw.Code, rw.Header().Get("X-Remediation"))
	}
}
