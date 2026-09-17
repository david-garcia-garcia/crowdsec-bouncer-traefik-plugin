package lapi

import (
	"log/slog"
	"testing"

	"github.com/maxlerebourg/crowdsec-bouncer-traefik-plugin/pkg/configuration"
)

func TestCachePrefix_RedisIncludesInstanceId(t *testing.T) {
	cfg := testStreamConfig("lapi.example:8080", 1)
	cfg.RedisCacheEnabled = true
	cfg.RedisCacheEffectiveInstanceID = "pod-a"
	prefix := CachePrefix(cfg)
	base := SessionHex(cfg)
	want := base + ":pod-a"
	if prefix != want {
		t.Fatalf("CachePrefix() = %q, want %q", prefix, want)
	}
	if prefix == base {
		t.Fatal("redis prefix must differ from session hex alone")
	}
}

func TestCachePrefix_MemoryOmitsInstanceId(t *testing.T) {
	cfg := testStreamConfig("lapi.example:8080", 1)
	if CachePrefix(cfg) != SessionHex(cfg) {
		t.Fatal("memory cache prefix must stay session hex only")
	}
}

func TestCachePrefix_LiveModeRedisUsesIdentityBase(t *testing.T) {
	cfg := testStreamConfig("lapi.example:8080", 1)
	cfg.CrowdsecMode = configuration.LiveMode
	cfg.RedisCacheEnabled = true
	cfg.RedisCacheEffectiveInstanceID = "pod-b"
	prefix := CachePrefix(cfg)
	want := IdentityHex(cfg) + ":pod-b"
	if prefix != want {
		t.Fatalf("live prefix = %q, want %q", prefix, want)
	}
}

func TestResolveCacheInstanceIdentity_Configured(t *testing.T) {
	cfg := testStreamConfig("lapi.example:8080", 1)
	cfg.RedisCacheEnabled = true
	cfg.RedisCacheInstanceID = "explicit-id"
	ResolveCacheInstanceIdentity(cfg, slog.Default())
	if cfg.RedisCacheEffectiveInstanceID != "explicit-id" {
		t.Fatalf("effective = %q", cfg.RedisCacheEffectiveInstanceID)
	}
}

func TestResolveCacheInstanceIdentity_Hostname(t *testing.T) {
	cfg := testStreamConfig("lapi.example:8080", 1)
	cfg.RedisCacheEnabled = true
	ResolveCacheInstanceIdentity(cfg, slog.Default())
	if cfg.RedisCacheEffectiveInstanceID == "" {
		t.Fatal("expected hostname or fallback")
	}
}

func TestCachePrefix_IsolatedStreamLeasePerInstance(t *testing.T) {
	base := testStreamConfig("lapi.example:8080", 1)
	cfgA := *base
	cfgA.RedisCacheEnabled = true
	cfgA.RedisCacheEffectiveInstanceID = "instance-a"
	cfgB := *base
	cfgB.RedisCacheEnabled = true
	cfgB.RedisCacheEffectiveInstanceID = "instance-b"
	leaseA := CachePrefix(&cfgA) + ":updated"
	leaseB := CachePrefix(&cfgB) + ":updated"
	if leaseA == leaseB {
		t.Fatalf("instances must not share redis lease key: %q", leaseA)
	}
	remediationA := CachePrefix(&cfgA) + ":1.2.3.4"
	remediationB := CachePrefix(&cfgB) + ":1.2.3.4"
	if remediationA == remediationB {
		t.Fatalf("instances must not share remediation namespace: %q", remediationA)
	}
}

func TestCachePrefix_SameSessionSameInstanceWarnAndWire(t *testing.T) {
	fast := testStreamConfig("lapi.example:8080", 1)
	fast.RedisCacheEnabled = true
	fast.RedisCacheEffectiveInstanceID = "same-pod"
	slow := testStreamConfig("lapi.example:8080", 600)
	slow.RedisCacheEnabled = true
	slow.RedisCacheEffectiveInstanceID = "same-pod"
	if CachePrefix(fast) != CachePrefix(slow) {
		t.Fatal("same LAPI session and instance must share one redis cache prefix for warn-and-wire")
	}
}
