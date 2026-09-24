package lapi

import (
	"context"
	"log/slog"
	"net/url"
	"sync/atomic"
	"testing"
	"time"

	"github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pkg/reclaim"
)

func TestSessionHex_S1RedisOffIgnoresLeftoverFields(t *testing.T) {
	base := testStreamConfig("lapi.example:8080", 1)
	leftover := testStreamConfig("lapi.example:8080", 1)
	leftover.LapiRedisHost = "redis:6379"
	leftover.LapiRedisReadHosts = []string{"r1", "r2"}
	leftover.LapiRedisPassword = "secret"
	leftover.LapiRedisDatabase = "2"
	if SessionHex(base) != SessionHex(leftover) {
		t.Fatal("S1: redis off leftover fields must not change SessionHex")
	}

	reclaim.ResetForTestWith(500 * time.Millisecond)
	t.Cleanup(func() { reclaim.ResetForTest() })
	server, _ := testStreamLAPI(t)
	parsed, err := url.Parse(server.URL)
	if err != nil {
		t.Fatal(err)
	}
	firstCfg := testStreamConfig(parsed.Host, 1)
	ctx, cancel := context.WithCancel(context.Background())
	first, err := Open(ctx, firstCfg, slog.Default(), "s1", "test")
	if err != nil {
		t.Fatal(err)
	}
	cancel()
	waitClientSleeping(t, first)
	secondCfg := testStreamConfig(parsed.Host, 1)
	secondCfg.LapiRedisHost = "redis:6379"
	secondCfg.LapiRedisPassword = "secret"
	second, err := Open(context.Background(), secondCfg, slog.Default(), "s1", "test")
	if err != nil {
		t.Fatal(err)
	}
	if first.decisionStore != second.decisionStore {
		t.Fatal("S1: leftover redis fields must keep the store")
	}
}

func TestSessionHex_S2ReadHostOrderDoesNotFork(t *testing.T) {
	a := testStreamConfig("lapi.example:8080", 1)
	a.LapiRedisEnabled = true
	a.LapiRedisHost = "redis:6379"
	a.LapiRedisReadHosts = []string{"b", "a"}
	b := testStreamConfig("lapi.example:8080", 1)
	b.LapiRedisEnabled = true
	b.LapiRedisHost = "redis:6379"
	b.LapiRedisReadHosts = []string{"a", "b"}
	if SessionHex(a) != SessionHex(b) {
		t.Fatal("S2: read-host order must not fork SessionHex")
	}
}

func TestSessionHex_S3RedisFieldChangeForksStore(t *testing.T) {
	reclaim.ResetForTestWith(500 * time.Millisecond)
	t.Cleanup(func() { reclaim.ResetForTest() })
	server, _ := testStreamLAPI(t)
	parsed, err := url.Parse(server.URL)
	if err != nil {
		t.Fatal(err)
	}
	fields := []struct {
		name string
		mut  func(*configurationCopy)
	}{
		{name: "host", mut: func(c *configurationCopy) { c.host = "redis-b:6379" }},
		{name: "password", mut: func(c *configurationCopy) { c.password = "other" }},
		{name: "database", mut: func(c *configurationCopy) { c.database = "2" }},
		{name: "reads", mut: func(c *configurationCopy) { c.reads = []string{"extra"} }},
	}
	for _, field := range fields {
		t.Run(field.name, func(t *testing.T) {
			reclaim.ResetForTestWith(500 * time.Millisecond)
			firstCfg := testStreamConfig(parsed.Host, 1)
			firstCfg.LapiRedisEnabled = true
			firstCfg.LapiRedisHost = "redis-a:6379"
			firstCfg.LapiRedisPassword = "pw"
			firstCfg.LapiRedisDatabase = "1"
			firstCfg.LapiRedisReadHosts = []string{"r1"}
			ctx, cancel := context.WithCancel(context.Background())
			first, err := Open(ctx, firstCfg, slog.Default(), "s3-"+field.name, "test")
			if err != nil {
				t.Fatal(err)
			}
			cancel()
			waitClientSleeping(t, first)
			secondCfg := testStreamConfig(parsed.Host, 1)
			secondCfg.LapiRedisEnabled = true
			secondCfg.LapiRedisHost = "redis-a:6379"
			secondCfg.LapiRedisPassword = "pw"
			secondCfg.LapiRedisDatabase = "1"
			secondCfg.LapiRedisReadHosts = []string{"r1"}
			snapshot := configurationCopy{
				host: secondCfg.LapiRedisHost, password: secondCfg.LapiRedisPassword,
				database: secondCfg.LapiRedisDatabase, reads: secondCfg.LapiRedisReadHosts,
			}
			field.mut(&snapshot)
			secondCfg.LapiRedisHost = snapshot.host
			secondCfg.LapiRedisPassword = snapshot.password
			secondCfg.LapiRedisDatabase = snapshot.database
			secondCfg.LapiRedisReadHosts = snapshot.reads
			if SessionHex(firstCfg) == SessionHex(secondCfg) {
				t.Fatal("S3: redis field change must fork SessionHex")
			}
			second, err := Open(context.Background(), secondCfg, slog.Default(), "s3-"+field.name, "test")
			if err != nil {
				t.Fatal(err)
			}
			if first.decisionStore == second.decisionStore {
				t.Fatal("S3: redis field change must fork the store")
			}
			if atomic.LoadInt64(&second.isCrowdsecStreamStartup) == 0 {
				t.Fatal("S3: new store must send startup=true")
			}
		})
	}
}

type configurationCopy struct {
	host, password, database string
	reads                    []string
}

func TestSessionHex_S4RedisOnOffForksStore(t *testing.T) {
	off := testStreamConfig("lapi.example:8080", 1)
	on := testStreamConfig("lapi.example:8080", 1)
	on.LapiRedisEnabled = true
	on.LapiRedisHost = "redis:6379"
	if SessionHex(off) == SessionHex(on) {
		t.Fatal("S4: turning redis on must fork SessionHex")
	}
}

func TestSessionHex_S5SameRedisReclaims(t *testing.T) {
	reclaim.ResetForTestWith(500 * time.Millisecond)
	t.Cleanup(func() { reclaim.ResetForTest() })
	server, _ := testStreamLAPI(t)
	parsed, err := url.Parse(server.URL)
	if err != nil {
		t.Fatal(err)
	}
	cfg := testStreamConfig(parsed.Host, 1)
	cfg.LapiRedisEnabled = true
	cfg.LapiRedisHost = "redis:6379"
	cfg.LapiRedisReadHosts = []string{"r2", "r1"}
	cfg.LapiRedisPassword = "pw"
	cfg.LapiRedisDatabase = "1"
	ctx, cancel := context.WithCancel(context.Background())
	first, err := Open(ctx, cfg, slog.Default(), "s5", "test")
	if err != nil {
		t.Fatal(err)
	}
	cancel()
	waitClientSleeping(t, first)
	same := testStreamConfig(parsed.Host, 1)
	same.LapiRedisEnabled = true
	same.LapiRedisHost = "redis:6379"
	same.LapiRedisReadHosts = []string{"r1", "r2"}
	same.LapiRedisPassword = "pw"
	same.LapiRedisDatabase = "1"
	if SessionHex(cfg) != SessionHex(same) {
		t.Fatal("S5: same redis set must keep SessionHex")
	}
	second, err := Open(context.Background(), same, slog.Default(), "s5", "test")
	if err != nil {
		t.Fatal(err)
	}
	if first.decisionStore != second.decisionStore {
		t.Fatal("S5: same redis set must reclaim the store")
	}
}

func TestOwnership_I1IntervalMetricsFailureCAPIForkClient(t *testing.T) {
	reclaim.ResetForTestWith(0)
	t.Cleanup(func() { reclaim.ResetForTest() })
	server, _ := testStreamLAPI(t)
	parsed, err := url.Parse(server.URL)
	if err != nil {
		t.Fatal(err)
	}
	base := testStreamConfig(parsed.Host, 1)
	ctx := context.Background()
	first, err := Open(ctx, base, slog.Default(), "i1", "test")
	if err != nil {
		t.Fatal(err)
	}
	secondCfg := testStreamConfig(parsed.Host, 1)
	secondCfg.LapiUpdateIntervalSeconds = 120
	second, err := Open(ctx, secondCfg, slog.Default(), "i1", "test")
	if err != nil {
		t.Fatal(err)
	}
	if first == second {
		t.Fatal("I1: updateIntervalSeconds must fork the Client")
	}
	if SessionHex(base) != SessionHex(secondCfg) {
		t.Fatal("I1: updateIntervalSeconds must keep SessionHex")
	}
	metricsCfg := testStreamConfig(parsed.Host, 600)
	metrics, err := Open(ctx, metricsCfg, slog.Default(), "i1", "test")
	if err != nil {
		t.Fatal(err)
	}
	if metrics == first {
		t.Fatal("I1: metricsUpdateIntervalSeconds must fork the Client")
	}
	failCfg := testStreamConfig(parsed.Host, 1)
	failCfg.LapiUpdateMaxFailure = 3
	failClient, err := Open(ctx, failCfg, slog.Default(), "i1", "test")
	if err != nil {
		t.Fatal(err)
	}
	if failClient == first {
		t.Fatal("I1: updateMaxFailure must fork the Client")
	}
	capiCfg := testStreamConfig(parsed.Host, 1)
	capiCfg.LapiCapiScenarios = []string{"crowdsecurity/http-probing"}
	capi, err := Open(ctx, capiCfg, slog.Default(), "i1", "test")
	if err != nil {
		t.Fatal(err)
	}
	if capi == first {
		t.Fatal("I1: crowdsecCapiScenarios must fork the Client")
	}
}

func TestOwnership_I2DefaultDecisionSecondsForksStore(t *testing.T) {
	a := testStreamConfig("lapi.example:8080", 1)
	b := testStreamConfig("lapi.example:8080", 1)
	b.LapiDefaultDecisionSeconds = 5
	if SessionHex(a) == SessionHex(b) {
		t.Fatal("I2: defaultDecisionSeconds must fork SessionHex")
	}
	if OwnershipKey(a, "mw") == OwnershipKey(b, "mw") {
		t.Fatal("I2: defaultDecisionSeconds must fork the ownership key")
	}
}

func TestOwnership_I3StartupBlockIsNeitherKey(t *testing.T) {
	reclaim.ResetForTestWith(0)
	t.Cleanup(func() { reclaim.ResetForTest() })
	server, _ := testStreamLAPI(t)
	parsed, err := url.Parse(server.URL)
	if err != nil {
		t.Fatal(err)
	}
	firstCfg := testStreamConfig(parsed.Host, 1)
	firstCfg.BouncerStartupBlock = true
	started := time.Now()
	first, err := Open(context.Background(), firstCfg, slog.Default(), "i3", "test")
	if err != nil {
		t.Fatal(err)
	}
	if time.Since(started) > 2*time.Second {
		t.Fatal("I3: Open must not wait on the first poll")
	}
	secondCfg := testStreamConfig(parsed.Host, 1)
	secondCfg.BouncerStartupBlock = false
	if SessionHex(firstCfg) != SessionHex(secondCfg) {
		t.Fatal("I3: streamStartupBlock must not change SessionHex")
	}
	if OwnershipKey(firstCfg, "i3") != OwnershipKey(secondCfg, "i3") {
		t.Fatal("I3: streamStartupBlock must not change the ownership key")
	}
	second, err := Open(context.Background(), secondCfg, slog.Default(), "i3", "test")
	if err != nil {
		t.Fatal(err)
	}
	if first != second {
		t.Fatal("I3: streamStartupBlock-only change must Wake the same Client")
	}
}
