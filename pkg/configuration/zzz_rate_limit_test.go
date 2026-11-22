package configuration

import (
	"net/http"
	"path/filepath"
	"strings"
	"testing"
	"time"

	logger "github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pkg/logger"
	"github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pkg/ratelimit"
)

// getRateLimitTestConfig is a minimal config with the rate-limit leg on and one catch-all bucket.
func getRateLimitTestConfig() *Config {
	cfg := getMinimalConfig()
	cfg.RateLimitEnabled = true
	cfg.RateLimitBuckets = []ratelimit.BucketRule{
		{Name: "per-ip", Requests: 300, Window: "1m", Key: []ratelimit.KeyPart{{From: ratelimit.KeyFromIP}}},
	}
	return cfg
}

// Test_New_rateLimitDefaults pins the CreateConfig defaults of every rate-limit setting.
func Test_New_rateLimitDefaults(t *testing.T) {
	cfg := New()
	if cfg.RateLimitEnabled || cfg.RateLimitBuckets == nil || len(cfg.RateLimitBuckets) != 0 {
		t.Fatalf("enabled=%v buckets=%v", cfg.RateLimitEnabled, cfg.RateLimitBuckets)
	}
	if cfg.RateLimitFailureAction != FailureActionPassthrough || cfg.RateLimitStore != RateLimitStoreRedis {
		t.Fatalf("failureAction=%q store=%q", cfg.RateLimitFailureAction, cfg.RateLimitStore)
	}
	if cfg.RateLimitRedisHost != "redis:6379" || cfg.RateLimitRedisDatabase != "" || cfg.RateLimitRedisPassword != "" || cfg.RateLimitRedisPasswordFile != "" {
		t.Fatalf("redis host=%q database=%q", cfg.RateLimitRedisHost, cfg.RateLimitRedisDatabase)
	}
	if !cfg.RateLimitResponseHeaders || cfg.RateLimitStatusCode != http.StatusTooManyRequests || cfg.RateLimitSyncRate != "200ms" {
		t.Fatalf("responseHeaders=%v status=%d syncRate=%q", cfg.RateLimitResponseHeaders, cfg.RateLimitStatusCode, cfg.RateLimitSyncRate)
	}
	if syncRate, err := RateLimitSyncRateDuration(cfg); err != nil || syncRate != 200*time.Millisecond {
		t.Fatalf("RateLimitSyncRateDuration=%s err=%v", syncRate, err)
	}
}

// Test_ValidateParams_rateLimit covers each top-level stem and the bucket wrapping of the config-validation delta.
func Test_ValidateParams_rateLimit(t *testing.T) {
	log := logger.New("INFO", "")
	missingFile := filepath.Join(t.TempDir(), "missing-redis-password")
	with := func(change func(*Config)) *Config {
		cfg := getRateLimitTestConfig()
		change(cfg)
		return cfg
	}
	tests := []struct {
		name    string
		config  *Config
		wantErr []string
	}{
		{name: "valid catch-all bucket", config: getRateLimitTestConfig()},
		{name: "sync rate 0 is exact mode", config: with(func(c *Config) { c.RateLimitSyncRate = "0" })},
		{name: "empty password with no file", config: with(func(c *Config) { c.RateLimitRedisPassword = "" })},
		{name: "memory store", config: with(func(c *Config) { c.RateLimitStore = "memory" }), wantErr: []string{"RateLimitStore", "memory"}},
		{name: "empty host", config: with(func(c *Config) { c.RateLimitRedisHost = " " }), wantErr: []string{"RateLimitRedisHost"}},
		{name: "missing password file", config: with(func(c *Config) { c.RateLimitRedisPasswordFile = missingFile }), wantErr: []string{"RateLimitRedisPassword"}},
		{name: "sync rate not a duration", config: with(func(c *Config) { c.RateLimitSyncRate = "fast" }), wantErr: []string{"RateLimitSyncRate"}},
		{name: "negative sync rate", config: with(func(c *Config) { c.RateLimitSyncRate = "-1s" }), wantErr: []string{"RateLimitSyncRate", "negative"}},
		{name: "unknown failure action", config: with(func(c *Config) { c.RateLimitFailureAction = "allow" }), wantErr: []string{"RateLimitFailureAction", "must be one of"}},
		{name: "captcha failure action on an owner without a captcha instance", config: with(func(c *Config) { c.RateLimitFailureAction = FailureActionCaptcha })},
		{name: "captcha failure action with a captcha instance", config: with(func(c *Config) {
			c.RateLimitFailureAction = FailureActionCaptcha
			c.BouncerEnabled = true
			c.CaptchaInstanceName = "shared-captcha"
		})},
		{name: "status 99", config: with(func(c *Config) { c.RateLimitStatusCode = 99 }), wantErr: []string{"RateLimitStatusCode"}},
		{name: "status 600", config: with(func(c *Config) { c.RateLimitStatusCode = 600 }), wantErr: []string{"RateLimitStatusCode"}},
		{name: "no bucket", config: with(func(c *Config) { c.RateLimitBuckets = nil }), wantErr: []string{"RateLimitBuckets"}},
		{name: "fractional window", config: with(func(c *Config) { c.RateLimitBuckets[0].Window = "1500ms" }), wantErr: []string{"RateLimitBuckets", "bucket 0"}},
		{name: "pattern without a capture group", config: with(func(c *Config) {
			c.RateLimitBuckets[0].Key = []ratelimit.KeyPart{{From: ratelimit.KeyFromPath, Pattern: "^/t/[^/]+/"}}
		}), wantErr: []string{"RateLimitBuckets", "capture group"}},
		{name: "bucket algorithm points at the limiter setting", config: with(func(c *Config) { c.RateLimitBuckets[0].Algorithm = "tokenBucket" }), wantErr: []string{"RateLimitBuckets", "bucket 0", "rateLimitAlgorithm"}},
		{name: "token bucket limiter", config: with(func(c *Config) { c.RateLimitAlgorithm = "tokenBucket" })},
		{name: "empty algorithm is the default", config: with(func(c *Config) { c.RateLimitAlgorithm = "" })},
		{name: "unknown algorithm", config: with(func(c *Config) { c.RateLimitAlgorithm = "leakyBucket" }), wantErr: []string{"RateLimitAlgorithm", `"slidingWindow"`, `"tokenBucket"`}},
		{name: "token bucket with burst", config: with(func(c *Config) {
			c.RateLimitAlgorithm = "tokenBucket"
			c.RateLimitBuckets[0].Burst = 20
		})},
		{name: "burst with the sliding window", config: with(func(c *Config) { c.RateLimitBuckets[0].Burst = 20 }), wantErr: []string{"RateLimitBuckets", "bucket 0", "burst", "rateLimitAlgorithm"}},
		{name: "captcha action", config: with(func(c *Config) { c.RateLimitBuckets[0].Action = "captcha" })},
		{name: "deny action", config: with(func(c *Config) { c.RateLimitBuckets[0].Action = "deny" }), wantErr: []string{"RateLimitBuckets", "bucket 0", `"ratelimit"`, `"captcha"`, `"log"`}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateParams(tt.config, log)
			if len(tt.wantErr) == 0 {
				if err != nil {
					t.Fatalf("ValidateParams() error = %v, want nil", err)
				}
				return
			}
			if err == nil {
				t.Fatalf("ValidateParams() = nil, want an error naming %v", tt.wantErr)
			}
			for _, want := range tt.wantErr {
				if !strings.Contains(err.Error(), want) {
					t.Fatalf("ValidateParams() error = %v, want it to name %q", err, want)
				}
			}
		})
	}
}

// Test_ValidateParams_disabledRateLimitIgnoresLeftovers proves a disabled leg reads no other rate-limit setting.
func Test_ValidateParams_disabledRateLimitIgnoresLeftovers(t *testing.T) {
	cfg := getMinimalConfig()
	cfg.RateLimitEnabled = false
	cfg.RateLimitBuckets = []ratelimit.BucketRule{{Name: "x", Requests: 1, Window: "500ms"}}
	cfg.RateLimitRedisPasswordFile = filepath.Join(t.TempDir(), "missing-redis-password")
	cfg.RateLimitSyncRate = "fast"
	cfg.RateLimitStatusCode = 0
	cfg.RateLimitStore = "memory"
	cfg.RateLimitFailureAction = "allow"
	cfg.RateLimitAlgorithm = "leakyBucket"
	if err := ValidateParams(cfg, logger.New("INFO", "")); err != nil {
		t.Fatalf("disabled leg must ignore leftovers: %v", err)
	}
}

// Test_ValidateParams_rateLimitOpenVsSubscribe covers the rate-limit row of the open-vs-subscribe matrix:
// a leftover rateLimitInstanceName with nothing enabled fails (E2), and a subscriber ignores leftover
// owner-read rateLimit* settings.
func Test_ValidateParams_rateLimitOpenVsSubscribe(t *testing.T) {
	log := logger.New("INFO", "")
	leftoverName := getMinimalConfig()
	leftoverName.RateLimitInstanceName = "shared"
	if err := ValidateParams(leftoverName, log); err == nil || !strings.Contains(err.Error(), "RateLimit") {
		t.Fatalf("leftover rateLimitInstanceName with nothing enabled: error = %v, want one naming RateLimit", err)
	}

	subscriber := getMinimalConfig()
	subscriber.BouncerEnabled = true
	subscriber.RateLimitInstanceName = "shared"
	subscriber.RateLimitBuckets = []ratelimit.BucketRule{{Name: "x", Requests: 1, Window: "500ms"}}
	subscriber.RateLimitStatusCode = 0
	if err := ValidateParams(subscriber, log); err != nil {
		t.Fatalf("a subscriber must ignore leftover owner-read rate-limit settings: %v", err)
	}

	owner := getRateLimitTestConfig()
	owner.RateLimitInstanceName = "shared"
	if err := ValidateParams(owner, log); err != nil {
		t.Fatalf("an owner with an instance name and bouncerEnabled false must pass: %v", err)
	}
}
