package decisionscope

import (
	"fmt"
	"net"
	"testing"

	cache "github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pkg/cache"
	logger "github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pkg/logger"
	ttl_map "github.com/leprosus/golang-ttl-map"
)

const benchLiveEntries = 100_000

func benchLookupKeys() (remoteIP string, ipAddr net.IP, scopes map[string]string) {
	remoteIP = "198.51.100.42"
	ipAddr = net.ParseIP(remoteIP)
	scopes = map[string]string{ScopeCountry: "US"}
	return remoteIP, ipAddr, scopes
}

func BenchmarkLookupCachedMiss_100kSeq(b *testing.B) {
	client := newBenchTTLClient(b)
	remoteIP, ipAddr, scopes := benchLookupKeys()
	membership := MembershipFromIndex("10.0.0.0/8=" + BannedValue)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _, _, _ = LookupCachedRemediation(client, remoteIP, ipAddr, scopes, membership)
	}
}

func BenchmarkLookupLiveMiss_100kSeq(b *testing.B) {
	snapshot := benchLiveSnapshot(b)
	remoteIP, ipAddr, scopes := benchLookupKeys()
	membership := MembershipFromIndex("10.0.0.0/8=" + BannedValue)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _, _, _ = LookupLiveSnapshotRemediation(snapshot, remoteIP, ipAddr, scopes, membership)
	}
}

func BenchmarkLookupCachedMiss_100kParallel(b *testing.B) {
	client := newBenchTTLClient(b)
	remoteIP, ipAddr, scopes := benchLookupKeys()
	membership := MembershipFromIndex("10.0.0.0/8=" + BannedValue)
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			_, _, _, _ = LookupCachedRemediation(client, remoteIP, ipAddr, scopes, membership)
		}
	})
}

func BenchmarkLookupLiveMiss_100kParallel(b *testing.B) {
	snapshot := benchLiveSnapshot(b)
	remoteIP, ipAddr, scopes := benchLookupKeys()
	membership := MembershipFromIndex("10.0.0.0/8=" + BannedValue)
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			_, _, _, _ = LookupLiveSnapshotRemediation(snapshot, remoteIP, ipAddr, scopes, membership)
		}
	})
}

func BenchmarkHeapRetained_TTLMap100k(b *testing.B) {
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		heap := ttl_map.New()
		for n := 0; n < benchLiveEntries; n++ {
			key := fmt.Sprintf("10.%d.%d.%d", n>>16&0xff, n>>8&0xff, n&0xff)
			heap.Set(key, uint32('t'), 3600)
		}
		b.SetBytes(benchLiveEntries * 100)
	}
}

func BenchmarkHeapRetained_LiveMap100k(b *testing.B) {
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		snapshot := make(map[string]LiveSlot, benchLiveEntries)
		for n := 0; n < benchLiveEntries; n++ {
			key := fmt.Sprintf("10.%d.%d.%d", n>>16&0xff, n>>8&0xff, n&0xff)
			snapshot[key] = LiveSlot{Word: packWord(BannedValue, 1), ExpiresAt: 9_999_999_999}
		}
		b.SetBytes(int64(len(snapshot)) * 68)
	}
}

func newBenchTTLClient(b *testing.B) *cache.Client {
	b.Helper()
	client := &cache.Client{}
	client.New(logger.New("ERROR", ""), false, "", nil, "", "", "")
	for n := 0; n < benchLiveEntries; n++ {
		key := fmt.Sprintf("10.%d.%d.%d", n>>16&0xff, n>>8&0xff, n&0xff)
		client.Set(key, packWord(BannedValue, 1), 3600)
	}
	countryKey := HeaderScopeKey(ScopeCountry, "US")
	client.Set(countryKey, packWord(BannedValue, 1), 3600)
	return client
}

func benchLiveSnapshot(b *testing.B) map[string]LiveSlot {
	b.Helper()
	snapshot := make(map[string]LiveSlot, benchLiveEntries+1)
	for n := 0; n < benchLiveEntries; n++ {
		key := fmt.Sprintf("10.%d.%d.%d", n>>16&0xff, n>>8&0xff, n&0xff)
		snapshot[key] = LiveSlot{Word: packWord(BannedValue, 1), ExpiresAt: 9_999_999_999}
	}
	snapshot[HeaderScopeKey(ScopeCountry, "US")] = LiveSlot{Word: packWord(BannedValue, 1), ExpiresAt: 9_999_999_999}
	return snapshot
}
