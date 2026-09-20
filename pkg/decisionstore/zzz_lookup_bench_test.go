package decisionstore

import (
	"fmt"
	"net"
	"testing"

	"github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pkg/decisionscope"
	"github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pkg/intern"
	ttl_map "github.com/leprosus/golang-ttl-map"
)

const benchLiveEntries = 100_000

func benchLookupArgs() (string, net.IP, map[string]string) {
	remoteIP := "198.51.100.42"
	return remoteIP, net.ParseIP(remoteIP), map[string]string{decisionscope.ScopeCountry: "US"}
}

func BenchmarkLookupStreamMiss_100kSeq(b *testing.B) {
	snapshot := benchLiveSnapshot(b)
	remoteIP, ipAddr, scopes := benchLookupArgs()
	membership := MembershipFromIndex("10.0.0.0/8=" + decisionscope.BannedValue)
	get := benchSnapshotGet(snapshot)
	b.ResetTimer()
	for range b.N {
		kind, origin, originID := lookupHits(get, remoteIP, ipAddr, scopes, membership)
		_ = kind
		_ = origin
		_ = originID
	}
}

func BenchmarkLookupStreamMiss_100kParallel(b *testing.B) {
	snapshot := benchLiveSnapshot(b)
	remoteIP, ipAddr, scopes := benchLookupArgs()
	membership := MembershipFromIndex("10.0.0.0/8=" + decisionscope.BannedValue)
	get := benchSnapshotGet(snapshot)
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			kind, origin, originID := lookupHits(get, remoteIP, ipAddr, scopes, membership)
			_ = kind
			_ = origin
			_ = originID
		}
	})
}

func benchLiveSnapshot(b *testing.B) map[string]LiveSlot {
	b.Helper()
	word := benchPackedBan()
	snapshot := make(map[string]LiveSlot, benchLiveEntries+1)
	for n := range benchLiveEntries {
		key := fmt.Sprintf("10.%d.%d.%d", n>>16&0xff, n>>8&0xff, n&0xff)
		snapshot[key] = LiveSlot{Word: word, ExpiresAt: 9_999_999_999}
	}
	snapshot[HeaderScopeKey(decisionscope.ScopeCountry, "US")] = LiveSlot{Word: word, ExpiresAt: 9_999_999_999}
	return snapshot
}

func benchPackedBan() uint32 {
	table := intern.New()
	originID, _ := table.ID("o")
	return packWord(decisionscope.BannedValue, originID)
}

func benchSnapshotGet(snapshot map[string]LiveSlot) func(string) any {
	return func(key string) any {
		slot, ok := snapshot[key]
		if !ok {
			return nil
		}
		return slot.Word
	}
}

func BenchmarkHeapRetained_TTLMap100k(b *testing.B) {
	b.ReportAllocs()
	for range b.N {
		heap := ttl_map.New()
		for n := range benchLiveEntries {
			key := fmt.Sprintf("10.%d.%d.%d", n>>16&0xff, n>>8&0xff, n&0xff)
			heap.Set(key, uint32('t'), 3600)
		}
		b.SetBytes(benchLiveEntries * 100)
	}
}

func BenchmarkHeapRetained_LiveMap100k(b *testing.B) {
	b.ReportAllocs()
	for range b.N {
		snapshot := make(map[string]LiveSlot, benchLiveEntries)
		for n := range benchLiveEntries {
			key := fmt.Sprintf("10.%d.%d.%d", n>>16&0xff, n>>8&0xff, n&0xff)
			snapshot[key] = LiveSlot{Word: packWord(decisionscope.BannedValue, 1), ExpiresAt: 9_999_999_999}
		}
		b.SetBytes(int64(len(snapshot)) * 68)
	}
}
