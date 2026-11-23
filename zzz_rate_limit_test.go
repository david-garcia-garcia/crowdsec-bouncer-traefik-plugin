package crowdsec_bouncer_traefik_plugin //nolint:revive,stylecheck

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"

	"github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pkg/bouncer"
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
	if _, err := configuration.RateLimitSyncRateDuration(cfg); err != nil {
		t.Fatal(err)
	}
	return ratelimit.OwnershipKey(name, rateLimitSettings(cfg))
}

// cfgRateLimitOwnerOnly owns the rate-limit leg against a dead Redis without bouncing: one per-ip
// bucket of requests per minute, the given status code, and an instance name (empty fills to the Traefik name).
func cfgRateLimitOwnerOnly(instanceName string, requests, statusCode int) *configuration.Config {
	c := cfgRateLimitDeadRedis()
	c.BouncerEnabled = false
	c.RateLimitInstanceName = instanceName
	c.RateLimitStatusCode = statusCode
	c.RateLimitBuckets[0].Requests = requests
	return c
}

// cfgRateLimitSubscriber bounces against rate-limit instance instanceName and sets no other rateLimit* key.
func cfgRateLimitSubscriber(instanceName string) *configuration.Config {
	c := getTestConfig()
	c.LapiEnabled = false
	c.LapiKey = ""
	c.BouncerRemediationHeadersCustomName = "X-Remediation"
	c.RateLimitInstanceName = instanceName
	return c
}

// serveTestRequests sends count requests from clientIP through handler and returns the last status.
func serveTestRequests(handler http.Handler, clientIP string, count int) int {
	status := 0
	// A slice, not range-over-int, because yaegi runs this file.
	for range make([]struct{}, count) {
		rw := httptest.NewRecorder()
		handler.ServeHTTP(rw, reqForIP(clientIP))
		status = rw.Code
	}
	return status
}

// publishedRateLimitIncarnation is the incarnation alias:ratelimit:<instanceName> publishes, or empty.
func publishedRateLimitIncarnation(instanceName string) string {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	incarnation := ""
	reclaim.Watch(ctx, instanceAlias(legRateLimit, instanceName), (*ratelimit.Client)(nil), func(published any) {
		notice, _ := published.(reclaim.Published)
		client, _ := notice.Value.(*ratelimit.Client)
		incarnation = client.Incarnation()
	})
	return incarnation
}

// TestNew_RateLimitOwnerFillsAndPublishes proves an owner with an omitted rateLimitInstanceName
// publishes its Client under its Traefik name, and that dropping rateLimitEnabled clears that alias.
func TestNew_RateLimitOwnerFillsAndPublishes(t *testing.T) {
	reclaim.ResetForTestWith(0)
	t.Cleanup(func() { reclaim.ResetForTest() })

	if _, err := New(context.Background(), testNextOK(), cfgRateLimitOwnerOnly("", 3, http.StatusTooManyRequests), "rl-owner"); err != nil {
		t.Fatal(err)
	}
	if publishedRateLimitIncarnation("rl-owner") == "" {
		t.Fatal("an owner without an instance name must publish alias:ratelimit:rl-owner")
	}
	dropped := cfgRateLimitOwnerOnly("", 3, http.StatusTooManyRequests)
	dropped.RateLimitEnabled = false
	if _, err := New(context.Background(), testNextOK(), dropped, "rl-owner"); err != nil {
		t.Fatal(err)
	}
	if published := publishedRateLimitIncarnation("rl-owner"); published != "" {
		t.Fatalf("dropping rateLimitEnabled must clear the alias, still publishes %s", published)
	}
}

// TestNew_RateLimitSubscribersShareTheOwnerPolicy proves two subscribers of one owner charge its bucket
// and answer its status code, each under its own counter, and that an owner policy edit opens a new
// Client the subscribers rebind to.
func TestNew_RateLimitSubscribersShareTheOwnerPolicy(t *testing.T) {
	reclaim.ResetForTestWith(0)
	t.Cleanup(func() { reclaim.ResetForTest() })

	owner := cfgRateLimitOwnerOnly("shared", 3, http.StatusServiceUnavailable)
	if _, err := New(context.Background(), testNextOK(), owner, "rl-owner"); err != nil {
		t.Fatal(err)
	}
	appA, err := New(context.Background(), testNextOK(), cfgRateLimitSubscriber("shared"), "app-a")
	if err != nil {
		t.Fatal(err)
	}
	appB, err := New(context.Background(), testNextOK(), cfgRateLimitSubscriber("shared"), "app-b")
	if err != nil {
		t.Fatal(err)
	}
	if status := serveTestRequests(appA, "203.0.113.50", 3); status != http.StatusOK {
		t.Fatalf("app-a third request: status %d, want 200", status)
	}
	if status := serveTestRequests(appA, "203.0.113.50", 1); status != http.StatusServiceUnavailable {
		t.Fatalf("app-a fourth request: status %d, want the owner's 503", status)
	}
	if status := serveTestRequests(appB, "203.0.113.50", 3); status != http.StatusOK {
		t.Fatalf("app-b third request: status %d, want 200 (separate counter)", status)
	}
	if status := serveTestRequests(appB, "203.0.113.50", 1); status != http.StatusServiceUnavailable {
		t.Fatalf("app-b fourth request: status %d, want the owner's 503", status)
	}

	// Owner policy edit: a new Client under the same alias; app-a answers with the new status.
	before := publishedRateLimitIncarnation("shared")
	if _, err := New(context.Background(), testNextOK(), cfgRateLimitOwnerOnly("shared", 3, http.StatusTeapot), "rl-owner"); err != nil {
		t.Fatal(err)
	}
	if after := publishedRateLimitIncarnation("shared"); after == "" || after == before {
		t.Fatalf("a policy edit must publish a new Client, before %s after %s", before, after)
	}
	if status := serveTestRequests(appA, "203.0.113.51", 4); status != http.StatusTeapot {
		t.Fatalf("app-a after the edit: status %d, want the new 418", status)
	}
}

// TestNew_RateLimitSubscriberWithoutNameDoesNotCharge proves bouncerEnabled without rateLimitEnabled or
// rateLimitInstanceName neither fills a name nor charges a published owner.
func TestNew_RateLimitSubscriberWithoutNameDoesNotCharge(t *testing.T) {
	reclaim.ResetForTestWith(0)
	t.Cleanup(func() { reclaim.ResetForTest() })

	// The owner publishes under app-c, the name the route below would fill to if it filled.
	if _, err := New(context.Background(), testNextOK(), cfgRateLimitOwnerOnly("app-c", 1, http.StatusTooManyRequests), "rl-owner-c"); err != nil {
		t.Fatal(err)
	}
	unnamed, err := New(context.Background(), testNextOK(), cfgRateLimitSubscriber(""), "app-c")
	if err != nil {
		t.Fatal(err)
	}
	if status := serveTestRequests(unnamed, "203.0.113.52", 3); status != http.StatusOK {
		t.Fatalf("a route without rateLimitInstanceName must not charge, got %d", status)
	}
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
// share one counter, and that a changed sync rate or algorithm opens another.
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
	tokenBucket := cfgRateLimitDeadRedis()
	tokenBucket.RateLimitAlgorithm = ratelimit.AlgorithmTokenBucket
	if _, err := New(context.Background(), testNextOK(), tokenBucket, "rl-shared"); err != nil {
		t.Fatal(err)
	}
	if other, _, ok := reclaim.Peek(rateLimitTestOwnershipKey(t, tokenBucket, "rl-shared")); !ok || other == first {
		t.Fatal("a changed algorithm must open a new counter")
	}
}

// TestNew_RateLimitTokenBucketDeadRedisAppliesFailureAction proves a tokenBucket owner has no buffered
// local count: with the default sync rate an unreachable Redis answers the first request with the failure
// action (ban:ratelimit-failure), where the sliding window would keep counting locally.
func TestNew_RateLimitTokenBucketDeadRedisAppliesFailureAction(t *testing.T) {
	reclaim.ResetForTestWith(0)
	t.Cleanup(func() { reclaim.ResetForTest() })

	cfg := cfgRateLimitDeadRedis()
	cfg.RateLimitAlgorithm = ratelimit.AlgorithmTokenBucket
	cfg.RateLimitFailureAction = configuration.FailureActionBan
	handler, err := New(context.Background(), testNextOK(), cfg, "rl-token-bucket")
	if err != nil {
		t.Fatalf("an unreachable Redis must not fail New: %v", err)
	}
	rw := httptest.NewRecorder()
	handler.ServeHTTP(rw, reqForIP("203.0.113.47"))
	if rw.Code != http.StatusForbidden || rw.Header().Get("X-Remediation") != "ban:ratelimit-failure" {
		t.Fatalf("status %d header %q, want 403 ban:ratelimit-failure", rw.Code, rw.Header().Get("X-Remediation"))
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

// TestNew_RateLimitDeadRedisFailureAction proves an unreachable Redis does not fail New, and that in exact
// mode (rateLimitSyncRate 0) the returned handler applies the failure action: passthrough reaches the
// backend, ban answers ban:ratelimit-failure.
func TestNew_RateLimitDeadRedisFailureAction(t *testing.T) {
	reclaim.ResetForTestWith(0)
	t.Cleanup(func() { reclaim.ResetForTest() })

	passthroughCfg := cfgRateLimitDeadRedis()
	passthroughCfg.RateLimitSyncRate = "0"
	passthrough, err := New(context.Background(), testNextOK(), passthroughCfg, "rl-passthrough")
	if err != nil {
		t.Fatalf("an unreachable Redis must not fail New: %v", err)
	}
	rw := httptest.NewRecorder()
	passthrough.ServeHTTP(rw, reqForIP("203.0.113.41"))
	if rw.Code != http.StatusOK || rw.Header().Get("X-Remediation") != "" {
		t.Fatalf("passthrough: status %d header %q", rw.Code, rw.Header().Get("X-Remediation"))
	}

	banCfg := cfgRateLimitDeadRedis()
	banCfg.RateLimitSyncRate = "0"
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

// TestNew_RateLimitDeadRedisBufferedKeepsTheLocalLimit proves that with the default buffered sync rate a
// Redis outage does not reach the failure action: the replica keeps counting locally and denies over the limit.
func TestNew_RateLimitDeadRedisBufferedKeepsTheLocalLimit(t *testing.T) {
	reclaim.ResetForTestWith(0)
	t.Cleanup(func() { reclaim.ResetForTest() })

	cfg := cfgRateLimitDeadRedis()
	cfg.RateLimitFailureAction = configuration.FailureActionBan
	handler, err := New(context.Background(), testNextOK(), cfg, "rl-buffered-outage")
	if err != nil {
		t.Fatal(err)
	}
	for hit := 1; hit <= 5; hit++ {
		rw := httptest.NewRecorder()
		handler.ServeHTTP(rw, reqForIP("203.0.113.43"))
		if rw.Code != http.StatusOK || rw.Header().Get("X-Remediation") != "" {
			t.Fatalf("hit %d: status %d header %q, want 200 within the local limit", hit, rw.Code, rw.Header().Get("X-Remediation"))
		}
	}
	rw := httptest.NewRecorder()
	handler.ServeHTTP(rw, reqForIP("203.0.113.43"))
	if rw.Code != http.StatusTooManyRequests || rw.Header().Get("X-Remediation") != "ban:ratelimit:per-ip" {
		t.Fatalf("hit 6: status %d header %q, want 429 ban:ratelimit:per-ip", rw.Code, rw.Header().Get("X-Remediation"))
	}
}

// countRateLimitOwnerLines is how many lines of logPath carry msg at level for subscriber app-a of
// rate-limit instance shared.
func countRateLimitOwnerLines(t *testing.T, logPath, msg, level string) int {
	t.Helper()
	total := 0
	for _, entry := range readLogEntries(t, logPath, msg) {
		// fmt.Sprint, not comma-ok assertions: yaegi runs this file.
		if fmt.Sprint(entry["level"]) == level && fmt.Sprint(entry["traefikName"]) == "app-a" && fmt.Sprint(entry["instanceName"]) == "shared" {
			total++
		}
	}
	return total
}

// TestNew_RateLimitOwnerUnavailableWarnsOnTransitions proves, through New and the real Watch, that a
// subscriber logs WARN "crowdsec bouncer rate limit owner unavailable" once when its owner is dropped and
// INFO "crowdsec bouncer rate limit owner available" once when it returns, never per request. A subscriber
// that starts before its owner warns once under Yaegi (Watch delivers the typed nil) and not in compiled
// Go (Watch skips it); either way the first bind logs one INFO per WARN before it. The WARN is pending per
// router name: a reload that rebuilds app-a while the owner is gone adds no WARN, and one INFO answers it.
func TestNew_RateLimitOwnerUnavailableWarnsOnTransitions(t *testing.T) {
	bouncer.ResetRateLimitOwnerWarningsForTest()
	t.Cleanup(bouncer.ResetRateLimitOwnerWarningsForTest)
	logPath := newTestLogFile(t)
	const warnMsg = "crowdsec bouncer rate limit owner unavailable"
	const infoMsg = "crowdsec bouncer rate limit owner available"
	// The owner logs to the same captured file, so it logs JSON too.
	jsonOwner := func() *configuration.Config {
		config := cfgRateLimitOwnerOnly("shared", 3, http.StatusTooManyRequests)
		config.LogFormat = "json"
		return config
	}

	// Subscribe before any owner publishes.
	subscriberConfig := cfgRateLimitSubscriber("shared")
	subscriberConfig.LogLevel = "INFO"
	subscriberConfig.LogFormat = "json"
	appA, err := New(context.Background(), testNextOK(), subscriberConfig, "app-a")
	if err != nil {
		t.Fatal(err)
	}
	warnedBeforeOwner := countRateLimitOwnerLines(t, logPath, warnMsg, "WARN")
	if warnedBeforeOwner > 1 {
		t.Fatalf("subscribe before publish logged %d WARN lines, want at most one", warnedBeforeOwner)
	}
	t.Logf("subscribe before publish: %d WARN (1 under Yaegi, 0 in compiled Go)", warnedBeforeOwner)

	// The owner publishes: one INFO per WARN before it.
	if _, err := New(context.Background(), testNextOK(), jsonOwner(), "rl-owner"); err != nil {
		t.Fatal(err)
	}
	if got := countRateLimitOwnerLines(t, logPath, infoMsg, "INFO"); got != warnedBeforeOwner {
		t.Fatalf("first bind: INFO lines=%d want %d", got, warnedBeforeOwner)
	}

	// The owner is dropped: one WARN, and requests pass without another.
	dropped := jsonOwner()
	dropped.RateLimitEnabled = false
	dropped.RateLimitInstanceName = ""
	if _, err := New(context.Background(), testNextOK(), dropped, "rl-owner"); err != nil {
		t.Fatal(err)
	}
	if status := serveTestRequests(appA, "203.0.113.70", 5); status != http.StatusOK {
		t.Fatalf("no owner: status %d, want 200", status)
	}
	if got := countRateLimitOwnerLines(t, logPath, warnMsg, "WARN"); got != warnedBeforeOwner+1 {
		t.Fatalf("owner dropped: WARN lines=%d want %d", got, warnedBeforeOwner+1)
	}

	// A reload rebuilds app-a while the owner is gone: under Yaegi its first delivery is the typed nil, which
	// is the same outage, so no second WARN.
	if _, err := New(context.Background(), testNextOK(), subscriberConfig, "app-a"); err != nil {
		t.Fatal(err)
	}
	if got := countRateLimitOwnerLines(t, logPath, warnMsg, "WARN"); got != warnedBeforeOwner+1 {
		t.Fatalf("app-a rebuilt without the owner: WARN lines=%d want %d", got, warnedBeforeOwner+1)
	}

	// The owner returns: one INFO although both app-a instances bind, and the limit answers again.
	if _, err := New(context.Background(), testNextOK(), jsonOwner(), "rl-owner"); err != nil {
		t.Fatal(err)
	}
	if got := countRateLimitOwnerLines(t, logPath, infoMsg, "INFO"); got != warnedBeforeOwner+1 {
		t.Fatalf("owner restored: INFO lines=%d want %d", got, warnedBeforeOwner+1)
	}
	if got := countRateLimitOwnerLines(t, logPath, warnMsg, "WARN"); got != warnedBeforeOwner+1 {
		t.Fatalf("owner restored: WARN lines=%d want %d", got, warnedBeforeOwner+1)
	}
}
