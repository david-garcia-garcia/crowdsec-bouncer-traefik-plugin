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
	return NewMemory(logger.New("ERROR", ""), true)
}

func countedRedis(t *testing.T) *Store {
	t.Helper()
	server := startTestStoreRedis(t)
	store := NewRedis(logger.New("ERROR", ""), server.addr(), nil, "", "", "sess", true)
	t.Cleanup(store.Close)
	return store
}

func originCount(store *Store, origin, family string) int64 {
	originID, _ := store.OriginID(origin)
	return store.ActiveCounts()[ActiveCountKey{OriginID: originID, Family: family}]
}

func TestActiveCountsStreamPutDelete(t *testing.T) {
	store := countedMemory(t)
	store.Put(Decision{Scope: decisionscope.ScopeIP, Value: activeCountBanIP, Kind: decisionscope.BannedValue, Origin: activeCountOrigin, DurationSec: 60})
	if got := originCount(store, activeCountOrigin, activeCountFamily); got != 1 {
		t.Fatalf("after Put got %d", got)
	}
	store.Delete(decisionscope.ScopeIP, activeCountBanIP)
	if got := originCount(store, activeCountOrigin, activeCountFamily); got != 0 {
		t.Fatalf("after Delete got %d", got)
	}
	if len(store.ActiveCounts()) != 0 {
		t.Fatalf("want empty snapshot, got %#v", store.ActiveCounts())
	}
}

func TestActiveCountsLivePutDoesNotIncrement(t *testing.T) {
	store := NewMemory(logger.New("ERROR", ""), false)
	store.Put(Decision{Scope: decisionscope.ScopeIP, Value: activeCountBanIP, Kind: decisionscope.BannedValue, Origin: activeCountOrigin, DurationSec: 60})
	if got := store.ActiveCounts(); len(got) != 0 {
		t.Fatalf("live Put must not count, got %#v", got)
	}
}

func TestActiveCountsLiveRedisPutDoesNotIncrement(t *testing.T) {
	server := startTestStoreRedis(t)
	store := NewRedis(logger.New("ERROR", ""), server.addr(), nil, "", "", "sess-live", false)
	t.Cleanup(store.Close)
	store.Put(Decision{Scope: decisionscope.ScopeIP, Value: activeCountBanIP, Kind: decisionscope.BannedValue, Origin: activeCountOrigin, DurationSec: 60})
	if got := store.ActiveCounts(); len(got) != 0 {
		t.Fatalf("live Redis Put must not count, got %#v", got)
	}
}

func TestActiveCountsRangeApplyDoesNotIncrement(t *testing.T) {
	store := countedMemory(t)
	if err := store.ApplyRangeBatch(map[string]string{"10.0.0.0/8": KindOriginString(decisionscope.BannedValue, activeCountOrigin)}, nil); err != nil {
		t.Fatal(err)
	}
	if got := store.ActiveCounts(); len(got) != 0 {
		t.Fatalf("Range must be omitted, got %#v", got)
	}
}

func TestActiveCountsOverwriteMovesGroup(t *testing.T) {
	store := countedMemory(t)
	store.Put(Decision{Scope: decisionscope.ScopeIP, Value: activeCountBanIP, Kind: decisionscope.BannedValue, Origin: activeCountOrigin, DurationSec: 60})
	store.Put(Decision{Scope: decisionscope.ScopeIP, Value: activeCountBanIP, Kind: decisionscope.BannedValue, Origin: activeCountNewOrigin, DurationSec: 60})
	if got := originCount(store, activeCountOrigin, activeCountFamily); got != 0 {
		t.Fatalf("previous origin still counted %d", got)
	}
	if got := originCount(store, activeCountNewOrigin, activeCountFamily); got != 1 {
		t.Fatalf("new origin got %d", got)
	}
}

func TestActiveCountsSameBatchOverwriteMovesGroup(t *testing.T) {
	store := countedMemory(t)
	store.PutMany([]Decision{
		{Scope: decisionscope.ScopeIP, Value: activeCountBanIP, Kind: decisionscope.BannedValue, Origin: activeCountOrigin, DurationSec: 60},
		{Scope: decisionscope.ScopeIP, Value: activeCountBanIP, Kind: decisionscope.BannedValue, Origin: activeCountNewOrigin, DurationSec: 60},
	})
	if got := originCount(store, activeCountOrigin, activeCountFamily); got != 0 {
		t.Fatalf("same-batch previous origin still counted %d", got)
	}
	if got := originCount(store, activeCountNewOrigin, activeCountFamily); got != 1 {
		t.Fatalf("same-batch new origin got %d", got)
	}
}

func TestActiveCountsPriorSpellingDeleteIsOneEvent(t *testing.T) {
	store := countedMemory(t)
	store.Put(Decision{Scope: decisionscope.ScopeIP, Value: activeCountBanIP + "/32", Kind: decisionscope.BannedValue, Origin: activeCountOrigin, DurationSec: 60})
	store.Put(Decision{Scope: decisionscope.ScopeIP, Value: "203.0.113.11", Kind: decisionscope.BannedValue, Origin: activeCountOrigin, DurationSec: 60})
	store.Delete(decisionscope.ScopeIP, activeCountBanIP+"/32")
	if got := originCount(store, activeCountOrigin, activeCountFamily); got != 1 {
		t.Fatalf("prior-spelling DEL must not be a second gauge event, got %d", got)
	}
}

func TestActiveCountsHeaderFamilyEmpty(t *testing.T) {
	store := countedMemory(t)
	store.Put(Decision{Scope: decisionscope.ScopeCountry, Value: "US", Kind: decisionscope.BannedValue, Origin: activeCountOrigin, DurationSec: 60})
	if got := originCount(store, activeCountOrigin, ""); got != 1 {
		t.Fatalf("Country family want empty ip_type, got %#v", store.ActiveCounts())
	}
}

func TestActiveCountsOverflowOriginIDZero(t *testing.T) {
	store := countedMemory(t)
	store.FillUntilMaxForTest()
	store.Put(Decision{Scope: decisionscope.ScopeIP, Value: activeCountBanIP, Kind: decisionscope.BannedValue, Origin: "overflow-origin", DurationSec: 60})
	if got := store.ActiveCounts()[ActiveCountKey{OriginID: 0, Family: activeCountFamily}]; got != 1 {
		t.Fatalf("overflow want origin id 0, got %#v", store.ActiveCounts())
	}
}

func TestActiveCountsMemoryPublishTickExpiryDoesNotDecrement(t *testing.T) {
	store := countedMemory(t)
	store.BeginTick()
	store.Put(Decision{Scope: decisionscope.ScopeIP, Value: activeCountBanIP, Kind: decisionscope.BannedValue, Origin: activeCountOrigin, DurationSec: 0})
	if got := originCount(store, activeCountOrigin, activeCountFamily); got != 1 {
		t.Fatalf("before expiry got %d", got)
	}
	store.PublishTick(ElapsedNow())
	if got := originCount(store, activeCountOrigin, activeCountFamily); got != 1 {
		t.Fatalf("expiry must not decrement the gauge, got %d", got)
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

func TestActiveCountsRedisOverwriteUsesPreviousOrigin(t *testing.T) {
	store := countedRedis(t)
	store.Put(Decision{Scope: decisionscope.ScopeIP, Value: activeCountBanIP, Kind: decisionscope.BannedValue, Origin: activeCountOrigin, DurationSec: 60})
	store.Put(Decision{Scope: decisionscope.ScopeIP, Value: activeCountBanIP, Kind: decisionscope.BannedValue, Origin: activeCountNewOrigin, DurationSec: 60})
	if got := originCount(store, activeCountOrigin, activeCountFamily); got != 0 {
		t.Fatalf("redis previous origin still counted %d", got)
	}
	if got := originCount(store, activeCountNewOrigin, activeCountFamily); got != 1 {
		t.Fatalf("redis new origin got %d", got)
	}
}

func TestActiveCountsRedisDelete(t *testing.T) {
	store := countedRedis(t)
	store.Put(Decision{Scope: decisionscope.ScopeIP, Value: activeCountBanIP, Kind: decisionscope.BannedValue, Origin: activeCountOrigin, DurationSec: 60})
	store.Delete(decisionscope.ScopeIP, activeCountBanIP)
	if got := store.ActiveCounts(); len(got) != 0 {
		t.Fatalf("redis Delete must decrement, got %#v", got)
	}
}

func TestActiveCountsMissingDeleteIsNoOp(t *testing.T) {
	store := countedMemory(t)
	store.Delete(decisionscope.ScopeIP, activeCountBanIP)
	if got := store.ActiveCounts(); len(got) != 0 {
		t.Fatalf("missing delete must not invent a count, got %#v", got)
	}
}
