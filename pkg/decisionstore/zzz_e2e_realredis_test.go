//go:build realredis

package decisionstore

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pkg/decisionscope"
	logger "github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pkg/logger"
)

const deadRedisAddr = "127.0.0.1:1"

// TestMain waits for Dragonfly (or Redis) at REALREDIS_ADDR before the suite.
func TestMain(m *testing.M) {
	if err := waitRealRedis(realRedisAddr(), 20*time.Second); err != nil {
		fmt.Fprintf(os.Stderr, "realredis: %v\n", err)
		os.Exit(1)
	}
	os.Exit(m.Run())
}

// realRedisAddr is host:port. CI publishes Dragonfly on 127.0.0.1:6379.
func realRedisAddr() string {
	addr := strings.TrimSpace(os.Getenv("REALREDIS_ADDR"))
	if addr == "" {
		return "127.0.0.1:6379"
	}
	return addr
}

// waitRealRedis retries Lookup until a miss (reachable) or budget expires.
func waitRealRedis(addr string, budget time.Duration) error {
	deadline := time.Now().Add(budget)
	var last error
	for {
		store := NewRedis(logger.New("ERROR", ""), addr, nil, "", "", "wait")
		_, _, _, last = store.LookupRemediation("203.0.113.254", nil, nil)
		store.Close()
		if errors.Is(last, ErrMiss) {
			return nil
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("no DecisionStore at %s: last error %v", addr, last)
		}
		time.Sleep(200 * time.Millisecond)
	}
}

// openRealRedis is one Store on a prefix unique to this test so keys do not collide.
func openRealRedis(t *testing.T) *Store {
	t.Helper()
	prefix := strings.ReplaceAll(t.Name(), "/", "-")
	store := NewRedis(logger.New("ERROR", ""), realRedisAddr(), nil, "", "", prefix)
	t.Cleanup(store.Close)
	return store
}

// waitMiss polls Lookup until the Ip slot is gone or budget expires.
func waitMiss(t *testing.T, store *Store, remoteIP string, budget time.Duration) {
	t.Helper()
	deadline := time.Now().Add(budget)
	for time.Now().Before(deadline) {
		kind, _, err := lookupRemediation(store, remoteIP, nil)
		if errors.Is(err, ErrMiss) {
			return
		}
		if err != nil {
			t.Fatalf("lookup while waiting for expiry: kind %q err %v", kind, err)
		}
		time.Sleep(100 * time.Millisecond)
	}
	t.Fatalf("%s still present after %s", remoteIP, budget)
}

// TestRealRedisBackendContract is the shared PutMany/Lookup/DeleteMany/Range matrix on Dragonfly.
func TestRealRedisBackendContract(t *testing.T) {
	for _, contract := range backendContracts() {
		t.Run(contract.name, func(t *testing.T) {
			contract.check(t, openRealRedis(t))
		})
	}
}

// TestRealRedisPutManySurvivesNewStore is a second client seeing MSetEX keys after the writer Close.
func TestRealRedisPutManySurvivesNewStore(t *testing.T) {
	addr := realRedisAddr()
	prefix := strings.ReplaceAll(t.Name(), "/", "-")
	writer := NewRedis(logger.New("ERROR", ""), addr, nil, "", "", prefix)
	writer.PutMany([]Decision{
		{Scope: decisionscope.ScopeIP, Value: backendBanIP, Kind: decisionscope.BannedValue, Origin: backendOrigin, DurationSec: backendLiveTTLSec},
	})
	mustKind(t, writer, backendBanIP, nil, decisionscope.BannedValue, backendOrigin)
	writer.Close()
	reader := NewRedis(logger.New("ERROR", ""), addr, nil, "", "", prefix)
	t.Cleanup(reader.Close)
	mustKind(t, reader, backendBanIP, nil, decisionscope.BannedValue, backendOrigin)
}

// TestRealRedisPrefixIsolation is a ban under one prefix that is a miss under another.
func TestRealRedisPrefixIsolation(t *testing.T) {
	addr := realRedisAddr()
	stem := strings.ReplaceAll(t.Name(), "/", "-")
	banned := NewRedis(logger.New("ERROR", ""), addr, nil, "", "", stem+"-a")
	other := NewRedis(logger.New("ERROR", ""), addr, nil, "", "", stem+"-b")
	t.Cleanup(banned.Close)
	t.Cleanup(other.Close)
	banned.Put(Decision{
		Scope: decisionscope.ScopeIP, Value: backendBanIP,
		Kind: decisionscope.BannedValue, Origin: backendOrigin, DurationSec: backendLiveTTLSec,
	})
	mustKind(t, banned, backendBanIP, nil, decisionscope.BannedValue, backendOrigin)
	mustMiss(t, other, backendBanIP, nil)
}

// TestRealRedisSlotExpires is Dragonfly EX dropping the Ip slot (the in-process RESP stand-in ignores TTL).
func TestRealRedisSlotExpires(t *testing.T) {
	store := openRealRedis(t)
	store.Put(Decision{
		Scope: decisionscope.ScopeIP, Value: backendBanIP,
		Kind: decisionscope.BannedValue, Origin: backendOrigin, DurationSec: 1,
	})
	mustKind(t, store, backendBanIP, nil, decisionscope.BannedValue, backendOrigin)
	waitMiss(t, store, backendBanIP, 5*time.Second)
}

// TestRealRedisCloseUnreachable is Lookup after Close, which must not dial again.
func TestRealRedisCloseUnreachable(t *testing.T) {
	store := NewRedis(logger.New("ERROR", ""), realRedisAddr(), nil, "", "", strings.ReplaceAll(t.Name(), "/", "-"))
	store.Close()
	kind, _, _, err := store.LookupRemediation(backendBanIP, nil, nil)
	if !errors.Is(err, ErrUnreachable) || err.Error() != "store:unreachable" {
		t.Fatalf("want store:unreachable, got kind %q err %v", kind, err)
	}
}

// TestRealRedisTickPutVisibleBeforePublish is Redis BeginTick as a no-op: the slot is already a hit.
func TestRealRedisTickPutVisibleBeforePublish(t *testing.T) {
	store := openRealRedis(t)
	store.BeginTick()
	store.Put(Decision{
		Scope: decisionscope.ScopeIP, Value: backendBanIP,
		Kind: decisionscope.BannedValue, Origin: backendOrigin, DurationSec: backendLiveTTLSec,
	})
	mustKind(t, store, backendBanIP, nil, decisionscope.BannedValue, backendOrigin)
}

// TestRealRedisEmptyBatchesDoNotWipe keeps a live ban across empty PutMany and DeleteMany.
func TestRealRedisEmptyBatchesDoNotWipe(t *testing.T) {
	store := openRealRedis(t)
	store.Put(Decision{
		Scope: decisionscope.ScopeIP, Value: backendBanIP,
		Kind: decisionscope.BannedValue, Origin: backendOrigin, DurationSec: backendLiveTTLSec,
	})
	store.PutMany(nil)
	store.PutMany([]Decision{})
	store.DeleteMany(nil)
	store.DeleteMany([]Decision{})
	mustKind(t, store, backendBanIP, nil, decisionscope.BannedValue, backendOrigin)
}

// TestRealRedisPutManySkipsRangeItems stores the Ip and ignores a Range row in the same batch.
func TestRealRedisPutManySkipsRangeItems(t *testing.T) {
	store := openRealRedis(t)
	store.PutMany([]Decision{
		{Scope: decisionscope.ScopeRange, Value: backendRangeCIDR, Kind: decisionscope.BannedValue, Origin: backendOrigin, DurationSec: backendLiveTTLSec},
		{Scope: decisionscope.ScopeIP, Value: backendBanIP, Kind: decisionscope.CaptchaValue, Origin: backendOrigin, DurationSec: backendLiveTTLSec},
	})
	mustKind(t, store, backendBanIP, nil, decisionscope.CaptchaValue, backendOrigin)
	mustMiss(t, store, backendRangeIP, nil)
}

// TestRealRedisLastPutWins replaces a ban with captcha on the same Ip key.
func TestRealRedisLastPutWins(t *testing.T) {
	store := openRealRedis(t)
	store.Put(Decision{
		Scope: decisionscope.ScopeIP, Value: backendBanIP,
		Kind: decisionscope.BannedValue, Origin: backendOrigin, DurationSec: backendLiveTTLSec,
	})
	store.Put(Decision{
		Scope: decisionscope.ScopeIP, Value: backendBanIP,
		Kind: decisionscope.CaptchaValue, Origin: "other", DurationSec: backendLiveTTLSec,
	})
	mustKind(t, store, backendBanIP, nil, decisionscope.CaptchaValue, "other")
}

// TestRealRedisShorterTTLReplacesExpiry is a second MSetEX on the same key that must not keep the first EX.
func TestRealRedisShorterTTLReplacesExpiry(t *testing.T) {
	store := openRealRedis(t)
	store.Put(Decision{
		Scope: decisionscope.ScopeIP, Value: backendBanIP,
		Kind: decisionscope.BannedValue, Origin: backendOrigin, DurationSec: backendLiveTTLSec,
	})
	store.Put(Decision{
		Scope: decisionscope.ScopeIP, Value: backendBanIP,
		Kind: decisionscope.BannedValue, Origin: backendOrigin, DurationSec: 1,
	})
	waitMiss(t, store, backendBanIP, 5*time.Second)
}

// TestRealRedisMixedTTLExpiresIndependently drops only the 1s slot while the 60s sibling stays.
func TestRealRedisMixedTTLExpiresIndependently(t *testing.T) {
	const heldIP = "203.0.113.11"
	store := openRealRedis(t)
	store.PutMany([]Decision{
		{Scope: decisionscope.ScopeIP, Value: backendBanIP, Kind: decisionscope.BannedValue, Origin: backendOrigin, DurationSec: 1},
		{Scope: decisionscope.ScopeIP, Value: heldIP, Kind: decisionscope.CaptchaValue, Origin: backendOrigin, DurationSec: backendLiveTTLSec},
	})
	waitMiss(t, store, backendBanIP, 5*time.Second)
	mustKind(t, store, heldIP, nil, decisionscope.CaptchaValue, backendOrigin)
}

// TestRealRedisDurationZeroIsNotLasting is MSetEX EX 0: Dragonfly must not keep a lasting Ip slot.
func TestRealRedisDurationZeroIsNotLasting(t *testing.T) {
	store := openRealRedis(t)
	store.Put(Decision{
		Scope: decisionscope.ScopeIP, Value: backendBanIP,
		Kind: decisionscope.BannedValue, Origin: backendOrigin, DurationSec: 0,
	})
	waitMiss(t, store, backendBanIP, 5*time.Second)
}

// TestRealRedisCloseTwiceThenUnreachable is a second Close that must not panic.
func TestRealRedisCloseTwiceThenUnreachable(t *testing.T) {
	store := NewRedis(logger.New("ERROR", ""), realRedisAddr(), nil, "", "", strings.ReplaceAll(t.Name(), "/", "-"))
	store.Close()
	store.Close()
	kind, _, _, err := store.LookupRemediation(backendBanIP, nil, nil)
	if !errors.Is(err, ErrUnreachable) {
		t.Fatalf("want store:unreachable after Close twice, got kind %q err %v", kind, err)
	}
}

// TestRealRedisPutAfterCloseIsDiscarded is a void MSetEX on a closed pool that a new client must not observe.
func TestRealRedisPutAfterCloseIsDiscarded(t *testing.T) {
	addr := realRedisAddr()
	prefix := strings.ReplaceAll(t.Name(), "/", "-")
	writer := NewRedis(logger.New("ERROR", ""), addr, nil, "", "", prefix)
	writer.Put(Decision{
		Scope: decisionscope.ScopeIP, Value: backendBanIP,
		Kind: decisionscope.BannedValue, Origin: backendOrigin, DurationSec: backendLiveTTLSec,
	})
	writer.Close()
	writer.Put(Decision{
		Scope: decisionscope.ScopeIP, Value: "203.0.113.11",
		Kind: decisionscope.BannedValue, Origin: backendOrigin, DurationSec: backendLiveTTLSec,
	})
	reader := NewRedis(logger.New("ERROR", ""), addr, nil, "", "", prefix)
	t.Cleanup(reader.Close)
	mustKind(t, reader, backendBanIP, nil, decisionscope.BannedValue, backendOrigin)
	mustMiss(t, reader, "203.0.113.11", nil)
}

// TestRealRedisDeadReaderDoesNotFallBackToWriter is nextReader-only: a ban on the writer is unreachable via a dead replica.
func TestRealRedisDeadReaderDoesNotFallBackToWriter(t *testing.T) {
	addr := realRedisAddr()
	prefix := strings.ReplaceAll(t.Name(), "/", "-")
	store := NewRedis(logger.New("ERROR", ""), addr, []string{deadRedisAddr}, "", "", prefix)
	t.Cleanup(store.Close)
	store.Put(Decision{
		Scope: decisionscope.ScopeIP, Value: backendBanIP,
		Kind: decisionscope.BannedValue, Origin: backendOrigin, DurationSec: backendLiveTTLSec,
	})
	kind, _, _, err := store.LookupRemediation(backendBanIP, net.ParseIP(backendBanIP), nil)
	if !errors.Is(err, ErrUnreachable) {
		t.Fatalf("dead reader must not retry writer, kind %q err %v", kind, err)
	}
	direct := NewRedis(logger.New("ERROR", ""), addr, nil, "", "", prefix)
	t.Cleanup(direct.Close)
	mustKind(t, direct, backendBanIP, nil, decisionscope.BannedValue, backendOrigin)
}

// TestRealRedisPutManyPastChunkBoundary is 1025 keys: one MSetEX of PutManyChunk plus a remainder.
func TestRealRedisPutManyPastChunkBoundary(t *testing.T) {
	store := openRealRedis(t)
	count := PutManyChunk + 1
	items := make([]Decision, count)
	for i := range items {
		items[i] = Decision{
			Scope: decisionscope.ScopeIP, Value: fmt.Sprintf("10.%d.%d.%d", i/65536, (i/256)%256, i%256),
			Kind: decisionscope.BannedValue, Origin: backendOrigin, DurationSec: backendLiveTTLSec,
		}
	}
	store.PutMany(items)
	mustKind(t, store, items[0].Value, nil, decisionscope.BannedValue, backendOrigin)
	mustKind(t, store, items[PutManyChunk-1].Value, nil, decisionscope.BannedValue, backendOrigin)
	mustKind(t, store, items[PutManyChunk].Value, nil, decisionscope.BannedValue, backendOrigin)
}

// TestRealRedisWhitespaceAndMappedIPShareSlot collapses CrowdSec spellings onto net.IP.String().
func TestRealRedisWhitespaceAndMappedIPShareSlot(t *testing.T) {
	store := openRealRedis(t)
	store.Put(Decision{
		Scope: decisionscope.ScopeIP, Value: "  " + backendBanIP + "  ",
		Kind: decisionscope.BannedValue, Origin: backendOrigin, DurationSec: backendLiveTTLSec,
	})
	mustKind(t, store, backendBanIP, nil, decisionscope.BannedValue, backendOrigin)
	store.Delete(decisionscope.ScopeIP, backendBanIP)
	store.Put(Decision{
		Scope: decisionscope.ScopeIP, Value: "::ffff:" + backendBanIP,
		Kind: decisionscope.CaptchaValue, Origin: backendOrigin, DurationSec: backendLiveTTLSec,
	})
	mustKind(t, store, backendBanIP, nil, decisionscope.CaptchaValue, backendOrigin)
}

// TestRealRedisHostPrefixCIDRIsAnIPSlot is a /32 CrowdSec value keyed as the bare address.
func TestRealRedisHostPrefixCIDRIsAnIPSlot(t *testing.T) {
	store := openRealRedis(t)
	store.Put(Decision{
		Scope: decisionscope.ScopeIP, Value: backendBanIP + "/32",
		Kind: decisionscope.BannedValue, Origin: backendOrigin, DurationSec: backendLiveTTLSec,
	})
	mustKind(t, store, backendBanIP, nil, decisionscope.BannedValue, backendOrigin)
}

// TestRealRedisExpandedRemoteIPMissesCanonicalSlot is Lookup keys as the remoteIP string, not IPCacheKey.
func TestRealRedisExpandedRemoteIPMissesCanonicalSlot(t *testing.T) {
	store := openRealRedis(t)
	store.Put(Decision{
		Scope: decisionscope.ScopeIP, Value: compressedV6,
		Kind: decisionscope.BannedValue, Origin: backendOrigin, DurationSec: backendLiveTTLSec,
	})
	kind, _, _, err := store.LookupRemediation(expandedV6, net.ParseIP(expandedV6), nil)
	if !errors.Is(err, ErrMiss) {
		t.Fatalf("expanded remoteIP must miss canonical slot, kind %q err %v", kind, err)
	}
	mustKind(t, store, compressedV6, nil, decisionscope.BannedValue, backendOrigin)
}

// TestRealRedisDeleteClearsPriorSpellingKey drops a leftover verbatim IPv6 key planted beside the canonical slot.
func TestRealRedisDeleteClearsPriorSpellingKey(t *testing.T) {
	store := openRealRedis(t)
	if store.red == nil || store.red.writer == nil {
		t.Fatal("redis writer is nil")
	}
	leftover := prefixed(store.red.prefix, expandedV6)
	if err := store.red.writer.Set(context.Background(), leftover, []byte(KindOriginString(decisionscope.BannedValue, backendOrigin)), backendLiveTTLSec); err != nil {
		t.Fatal(err)
	}
	store.Delete(decisionscope.ScopeIP, expandedV6)
	got, err := store.red.writer.Get(context.Background(), leftover)
	if err == nil && len(got) > 0 {
		t.Fatalf("prior spelling key still set: %q", got)
	}
}

// TestRealRedisVerbatimUnparseableValueIsASlot stores a CrowdSec value that is not an address.
func TestRealRedisVerbatimUnparseableValueIsASlot(t *testing.T) {
	const weird = "not-an-ip"
	store := openRealRedis(t)
	store.Put(Decision{
		Scope: decisionscope.ScopeIP, Value: weird,
		Kind: decisionscope.BannedValue, Origin: backendOrigin, DurationSec: backendLiveTTLSec,
	})
	mustKind(t, store, weird, nil, decisionscope.BannedValue, backendOrigin)
}

// TestRealRedisEmptyHeaderValueIsSkipped does not write a Country slot for an unusable identifier.
func TestRealRedisEmptyHeaderValueIsSkipped(t *testing.T) {
	store := openRealRedis(t)
	store.Put(Decision{
		Scope: decisionscope.ScopeCountry, Value: "XX",
		Kind: decisionscope.BannedValue, Origin: backendOrigin, DurationSec: backendLiveTTLSec,
	})
	mustMiss(t, store, backendBanIP, map[string]string{decisionscope.ScopeCountry: "XX"})
}

// TestRealRedisBareKindHasEmptyOrigin is a Redis slot with no newline origin suffix.
func TestRealRedisBareKindHasEmptyOrigin(t *testing.T) {
	store := openRealRedis(t)
	store.Put(Decision{
		Scope: decisionscope.ScopeIP, Value: backendBanIP,
		Kind: decisionscope.BannedValue, DurationSec: backendLiveTTLSec,
	})
	mustKind(t, store, backendBanIP, nil, decisionscope.BannedValue, "")
}

// TestRealRedisInternOverflowStillStoresOrigin is Redis KindOriginString, not a packed intern id.
func TestRealRedisInternOverflowStillStoresOrigin(t *testing.T) {
	store := openRealRedis(t)
	store.FillUntilMaxForTest()
	store.Put(Decision{
		Scope: decisionscope.ScopeIP, Value: backendBanIP,
		Kind: decisionscope.BannedValue, Origin: "overflow-origin", DurationSec: backendLiveTTLSec,
	})
	mustKind(t, store, backendBanIP, nil, decisionscope.BannedValue, "overflow-origin")
}

// TestRealRedisDeleteMissingIsStillMiss is DEL of an absent key, which stays void.
func TestRealRedisDeleteMissingIsStillMiss(t *testing.T) {
	store := openRealRedis(t)
	store.Delete(decisionscope.ScopeIP, backendBanIP)
	store.DeleteMany([]Decision{{Scope: decisionscope.ScopeRange, Value: backendRangeCIDR}})
	mustMiss(t, store, backendBanIP, nil)
}

// TestRealRedisSamePrefixTwoStoresShare is two clients on one SessionHex-style prefix.
func TestRealRedisSamePrefixTwoStoresShare(t *testing.T) {
	addr := realRedisAddr()
	prefix := strings.ReplaceAll(t.Name(), "/", "-")
	first := NewRedis(logger.New("ERROR", ""), addr, nil, "", "", prefix)
	second := NewRedis(logger.New("ERROR", ""), addr, nil, "", "", prefix)
	t.Cleanup(first.Close)
	t.Cleanup(second.Close)
	first.Put(Decision{
		Scope: decisionscope.ScopeIP, Value: backendBanIP,
		Kind: decisionscope.BannedValue, Origin: backendOrigin, DurationSec: backendLiveTTLSec,
	})
	mustKind(t, second, backendBanIP, nil, decisionscope.BannedValue, backendOrigin)
}

// TestRealRedisRangeNeedsHydrateOnNewStore is in-process membership empty until HydrateRange reads range-index.
func TestRealRedisRangeNeedsHydrateOnNewStore(t *testing.T) {
	addr := realRedisAddr()
	prefix := strings.ReplaceAll(t.Name(), "/", "-")
	writer := NewRedis(logger.New("ERROR", ""), addr, nil, "", "", prefix)
	if err := writer.ApplyRangeBatch(map[string]string{backendRangeCIDR: KindOriginString(decisionscope.BannedValue, backendOrigin)}, nil); err != nil {
		t.Fatal(err)
	}
	writer.Close()
	reader := NewRedis(logger.New("ERROR", ""), addr, nil, "", "", prefix)
	t.Cleanup(reader.Close)
	mustMiss(t, reader, backendRangeIP, nil)
	reader.HydrateRange()
	mustKind(t, reader, backendRangeIP, nil, decisionscope.BannedValue, backendOrigin)
}

// TestRealRedisEmptyRangeBatchPreservesIndex is ApplyRangeBatch with no CIDRs, which must not DEL range-index.
func TestRealRedisEmptyRangeBatchPreservesIndex(t *testing.T) {
	store := openRealRedis(t)
	if err := store.ApplyRangeBatch(map[string]string{backendRangeCIDR: decisionscope.BannedValue}, nil); err != nil {
		t.Fatal(err)
	}
	if err := store.ApplyRangeBatch(nil, nil); err != nil {
		t.Fatal(err)
	}
	mustKind(t, store, backendRangeIP, nil, decisionscope.BannedValue, "")
}

// TestRealRedisRangeSameCIDRReplacement stays banned when the blob removes then upserts one CIDR.
func TestRealRedisRangeSameCIDRReplacement(t *testing.T) {
	store := openRealRedis(t)
	if err := store.ApplyRangeBatch(
		map[string]string{backendRangeCIDR: KindOriginString(decisionscope.BannedValue, "next")},
		[]string{backendRangeCIDR},
	); err != nil {
		t.Fatal(err)
	}
	mustKind(t, store, backendRangeIP, nil, decisionscope.BannedValue, "next")
}

// TestRealRedisBareIPRangeIsHostPrefix remediates 10.1.2.3 when the blob stored that address as a /32.
func TestRealRedisBareIPRangeIsHostPrefix(t *testing.T) {
	store := openRealRedis(t)
	if err := store.ApplyRangeBatch(map[string]string{backendRangeIP: KindOriginString(decisionscope.CaptchaValue, backendOrigin)}, nil); err != nil {
		t.Fatal(err)
	}
	mustKind(t, store, backendRangeIP, nil, decisionscope.CaptchaValue, backendOrigin)
	mustMiss(t, store, "10.1.2.4", nil)
}

// TestRealRedisRangeIndexMissIsEmpty is GET miss of range-index, which is not store:miss.
func TestRealRedisRangeIndexMissIsEmpty(t *testing.T) {
	store := openRealRedis(t)
	index, err := store.RangeIndex()
	if err != nil || index != "" {
		t.Fatalf("empty index want \"\", got %q err %v", index, err)
	}
}

// TestRealRedisApplyRangeOnClosedIsUnreachable is a GET of range-index after Close.
func TestRealRedisApplyRangeOnClosedIsUnreachable(t *testing.T) {
	store := NewRedis(logger.New("ERROR", ""), realRedisAddr(), nil, "", "", strings.ReplaceAll(t.Name(), "/", "-"))
	store.Close()
	err := store.ApplyRangeBatch(map[string]string{backendRangeCIDR: decisionscope.BannedValue}, nil)
	if !errors.Is(err, ErrUnreachable) {
		t.Fatalf("want store:unreachable, got %v", err)
	}
}

// TestRealRedisEmptyRangeBatchOnClosedSucceeds does not touch Redis when both maps are empty.
func TestRealRedisEmptyRangeBatchOnClosedSucceeds(t *testing.T) {
	store := NewRedis(logger.New("ERROR", ""), realRedisAddr(), nil, "", "", strings.ReplaceAll(t.Name(), "/", "-"))
	store.Close()
	if err := store.ApplyRangeBatch(nil, nil); err != nil {
		t.Fatalf("empty batch on closed store: %v", err)
	}
}

// TestRealRedisPublishedMemoryMapIsNil is Redis, which has no COW map.
func TestRealRedisPublishedMemoryMapIsNil(t *testing.T) {
	store := openRealRedis(t)
	if got := store.PublishedMemoryMapForTest(); got != nil {
		t.Fatalf("redis published map %v, want nil", got)
	}
}

// TestRealRedisLookupEmptyScopeIdentifierSkipsHeader does not MGET a Country key for "".
func TestRealRedisLookupEmptyScopeIdentifierSkipsHeader(t *testing.T) {
	store := openRealRedis(t)
	store.Put(Decision{
		Scope: decisionscope.ScopeCountry, Value: "FR",
		Kind: decisionscope.BannedValue, Origin: backendOrigin, DurationSec: backendLiveTTLSec,
	})
	mustMiss(t, store, backendBanIP, map[string]string{decisionscope.ScopeCountry: ""})
	mustKind(t, store, backendBanIP, map[string]string{decisionscope.ScopeCountry: "FR"}, decisionscope.BannedValue, backendOrigin)
}
