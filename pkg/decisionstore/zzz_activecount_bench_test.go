package decisionstore

import (
	"fmt"
	"math"
	"testing"
)

func BenchmarkCountPublishedSlots_100k(b *testing.B) {
	benchmarkCountPublishedSlots(b, 100_000)
}

func BenchmarkCountPublishedSlots_1M(b *testing.B) {
	benchmarkCountPublishedSlots(b, 1_000_000)
}

func benchmarkCountPublishedSlots(b *testing.B, n int) {
	b.Helper()
	word := benchPackedBan()
	_, _, originID := unpackWord(word)
	want := ActiveCountKey{OriginID: originID, Family: packedFamily(word)}
	snapshot := make(map[string]LiveSlot, n)
	for i := range n {
		key := fmt.Sprintf("10.%d.%d.%d", i>>16&0xff, i>>8&0xff, i&0xff)
		snapshot[key] = LiveSlot{Word: word, ExpiresAt: math.MaxInt32}
	}
	b.ReportAllocs()
	b.ResetTimer()
	for range b.N {
		counts := countPublishedSlots(snapshot)
		if counts[want] != int64(n) {
			b.Fatalf("count %d want %d", counts[want], n)
		}
	}
}
