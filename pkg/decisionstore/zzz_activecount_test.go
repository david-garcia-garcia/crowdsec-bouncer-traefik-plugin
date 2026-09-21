package decisionstore

import (
	"testing"

	"github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pkg/decisionscope"
	logger "github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pkg/logger"
)

const (
	activeCountBanIP     = "203.0.113.10"
	activeCountOrigin    = "crowdsec"
	activeCountNewOrigin = "lists:firehol_level1"
	activeCountFamily    = "ipv4"
)

func countedMemory(t *testing.T) *Store {
	t.Helper()
	return NewMemory(logger.New("ERROR", ""))
}

func originCount(store *Store, origin, family string) int64 {
	originID, _ := store.OriginID(origin)
	return store.ActiveCounts()[ActiveCountKey{OriginID: originID, Family: family}]
}

func publishDecisions(store *Store, items ...Decision) {
	store.BeginTick()
	store.PutMany(items)
	store.PublishTick(0)
}

func publishDelete(store *Store, scope, value string) {
	store.BeginTick()
	store.Delete(scope, value)
	store.PublishTick(0)
}

func TestActiveCountsStreamPutDelete(t *testing.T) {
	store := countedMemory(t)
	publishDecisions(store, Decision{Scope: decisionscope.ScopeIP, Value: activeCountBanIP, Kind: decisionscope.BannedValue, Origin: activeCountOrigin, DurationSec: 60})
	if got := originCount(store, activeCountOrigin, activeCountFamily); got != 1 {
		t.Fatalf("after PublishTick Put got %d", got)
	}
	publishDelete(store, decisionscope.ScopeIP, activeCountBanIP)
	if got := originCount(store, activeCountOrigin, activeCountFamily); got != 0 {
		t.Fatalf("after PublishTick Delete got %d", got)
	}
	if len(store.ActiveCounts()) != 0 {
		t.Fatalf("want empty snapshot, got %#v", store.ActiveCounts())
	}
}

func TestActiveCountsPutWithoutPublishTickIsEmpty(t *testing.T) {
	store := countedMemory(t)
	store.Put(Decision{Scope: decisionscope.ScopeIP, Value: activeCountBanIP, Kind: decisionscope.BannedValue, Origin: activeCountOrigin, DurationSec: 60})
	if got := store.ActiveCounts(); len(got) != 0 {
		t.Fatalf("Put without PublishTick must not count, got %#v", got)
	}
}

func TestActiveCountsLivePutDoesNotIncrement(t *testing.T) {
	store := NewMemory(logger.New("ERROR", ""))
	store.Put(Decision{Scope: decisionscope.ScopeIP, Value: activeCountBanIP, Kind: decisionscope.BannedValue, Origin: activeCountOrigin, DurationSec: 60})
	if got := store.ActiveCounts(); len(got) != 0 {
		t.Fatalf("live Put must not count, got %#v", got)
	}
}

func TestActiveCountsRedisAlwaysEmpty(t *testing.T) {
	server := startTestStoreRedis(t)
	store := NewRedis(logger.New("ERROR", ""), server.addr(), nil, "", "", "sess")
	t.Cleanup(store.Close)
	store.BeginTick()
	store.Put(Decision{Scope: decisionscope.ScopeIP, Value: activeCountBanIP, Kind: decisionscope.BannedValue, Origin: activeCountOrigin, DurationSec: 60})
	store.PublishTick(0)
	if got := store.ActiveCounts(); len(got) != 0 {
		t.Fatalf("Redis ActiveCounts must be empty, got %#v", got)
	}
	store.Delete(decisionscope.ScopeIP, activeCountBanIP)
	if got := store.ActiveCounts(); len(got) != 0 {
		t.Fatalf("Redis ActiveCounts must stay empty after Delete, got %#v", got)
	}
}

func TestActiveCountsRangeApplyDoesNotIncrement(t *testing.T) {
	store := countedMemory(t)
	if err := store.ApplyRangeBatch(map[string]string{"10.0.0.0/8": KindOriginString(decisionscope.BannedValue, activeCountOrigin)}, nil); err != nil {
		t.Fatal(err)
	}
	store.BeginTick()
	store.PublishTick(0)
	if got := store.ActiveCounts(); len(got) != 0 {
		t.Fatalf("Range must be omitted, got %#v", got)
	}
}

func TestActiveCountsOverwriteMovesGroup(t *testing.T) {
	store := countedMemory(t)
	publishDecisions(store, Decision{Scope: decisionscope.ScopeIP, Value: activeCountBanIP, Kind: decisionscope.BannedValue, Origin: activeCountOrigin, DurationSec: 60})
	publishDecisions(store, Decision{Scope: decisionscope.ScopeIP, Value: activeCountBanIP, Kind: decisionscope.BannedValue, Origin: activeCountNewOrigin, DurationSec: 60})
	if got := originCount(store, activeCountOrigin, activeCountFamily); got != 0 {
		t.Fatalf("previous origin still counted %d", got)
	}
	if got := originCount(store, activeCountNewOrigin, activeCountFamily); got != 1 {
		t.Fatalf("new origin got %d", got)
	}
}

func TestActiveCountsSameBatchOverwriteMovesGroup(t *testing.T) {
	store := countedMemory(t)
	publishDecisions(store,
		Decision{Scope: decisionscope.ScopeIP, Value: activeCountBanIP, Kind: decisionscope.BannedValue, Origin: activeCountOrigin, DurationSec: 60},
		Decision{Scope: decisionscope.ScopeIP, Value: activeCountBanIP, Kind: decisionscope.BannedValue, Origin: activeCountNewOrigin, DurationSec: 60},
	)
	if got := originCount(store, activeCountOrigin, activeCountFamily); got != 0 {
		t.Fatalf("same-batch previous origin still counted %d", got)
	}
	if got := originCount(store, activeCountNewOrigin, activeCountFamily); got != 1 {
		t.Fatalf("same-batch new origin got %d", got)
	}
}

func TestActiveCountsPriorSpellingDeleteIsOneEvent(t *testing.T) {
	store := countedMemory(t)
	publishDecisions(store,
		Decision{Scope: decisionscope.ScopeIP, Value: activeCountBanIP + "/32", Kind: decisionscope.BannedValue, Origin: activeCountOrigin, DurationSec: 60},
		Decision{Scope: decisionscope.ScopeIP, Value: "203.0.113.11", Kind: decisionscope.BannedValue, Origin: activeCountOrigin, DurationSec: 60},
	)
	publishDelete(store, decisionscope.ScopeIP, activeCountBanIP+"/32")
	if got := originCount(store, activeCountOrigin, activeCountFamily); got != 1 {
		t.Fatalf("prior-spelling DEL must not be a second gauge event, got %d", got)
	}
}

func TestActiveCountsHeaderFamilyEmpty(t *testing.T) {
	store := countedMemory(t)
	publishDecisions(store, Decision{Scope: decisionscope.ScopeCountry, Value: "US", Kind: decisionscope.BannedValue, Origin: activeCountOrigin, DurationSec: 60})
	if got := originCount(store, activeCountOrigin, ""); got != 1 {
		t.Fatalf("Country family want empty ip_type, got %#v", store.ActiveCounts())
	}
}

func TestActiveCountsIPv6Family(t *testing.T) {
	store := countedMemory(t)
	publishDecisions(store, Decision{Scope: decisionscope.ScopeIP, Value: "2001:db8::1", Kind: decisionscope.BannedValue, Origin: activeCountOrigin, DurationSec: 60})
	if got := originCount(store, activeCountOrigin, "ipv6"); got != 1 {
		t.Fatalf("ipv6 family want 1, got %#v", store.ActiveCounts())
	}
}

func TestActiveCountsOverflowOriginIDZero(t *testing.T) {
	store := countedMemory(t)
	store.FillUntilMaxForTest()
	publishDecisions(store, Decision{Scope: decisionscope.ScopeIP, Value: activeCountBanIP, Kind: decisionscope.BannedValue, Origin: "overflow-origin", DurationSec: 60})
	if got := store.ActiveCounts()[ActiveCountKey{OriginID: 0, Family: activeCountFamily}]; got != 1 {
		t.Fatalf("overflow want origin id 0, got %#v", store.ActiveCounts())
	}
}

func TestActiveCountsMemoryPublishTickExpiryDropsSlot(t *testing.T) {
	store := countedMemory(t)
	store.BeginTick()
	store.Put(Decision{Scope: decisionscope.ScopeIP, Value: activeCountBanIP, Kind: decisionscope.BannedValue, Origin: activeCountOrigin, DurationSec: 0})
	store.PublishTick(ElapsedNow())
	if got := originCount(store, activeCountOrigin, activeCountFamily); got != 0 {
		t.Fatalf("expiry must drop the slot from the gauge, got %d", got)
	}
}

func TestActiveCountsMemoryPublishTickZeroSkipsSweep(t *testing.T) {
	store := countedMemory(t)
	store.BeginTick()
	store.Put(Decision{Scope: decisionscope.ScopeIP, Value: activeCountBanIP, Kind: decisionscope.BannedValue, Origin: activeCountOrigin, DurationSec: 0})
	store.PublishTick(0)
	if got := originCount(store, activeCountOrigin, activeCountFamily); got != 1 {
		t.Fatalf("PublishTick(0) must keep the slot counted, got %d", got)
	}
}

func TestActiveCountsMissingDeleteIsNoOp(t *testing.T) {
	store := countedMemory(t)
	publishDelete(store, decisionscope.ScopeIP, activeCountBanIP)
	if got := store.ActiveCounts(); len(got) != 0 {
		t.Fatalf("missing delete must not invent a count, got %#v", got)
	}
}
