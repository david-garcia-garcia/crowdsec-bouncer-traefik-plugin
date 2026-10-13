package decisionstore

import (
	"testing"

	logger "github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pkg/logger"
	simpleredis "github.com/david-garcia-garcia/traefik-middleware-utilities/simpleredis"
)

func indexOfReader(backend *redis, reader *simpleredis.SimpleRedis) int {
	if reader == backend.writer {
		return -1
	}
	for i := range backend.readers {
		if reader == backend.readers[i] {
			return i
		}
	}
	return -2
}

func TestNextReader(t *testing.T) {
	tests := []struct {
		name    string
		readers int
		want    []int
	}{
		{name: "round-robin over three readers", readers: 3, want: []int{1, 2, 0, 1, 2, 0, 1}},
		{name: "single reader always selected", readers: 1, want: []int{0, 0, 0, 0, 0}},
		{name: "no readers fall back to writer", readers: 0, want: []int{-1, -1, -1}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			backend := &redis{log: logger.New("INFO", "")}
			backend.writer = &simpleredis.SimpleRedis{}
			backend.readers = make([]*simpleredis.SimpleRedis, tt.readers)
			for i := range backend.readers {
				backend.readers[i] = &simpleredis.SimpleRedis{}
			}
			for call, want := range tt.want {
				if got := indexOfReader(backend, backend.nextReader()); got != want {
					t.Errorf("call %d: nextReader() -> reader[%d], want reader[%d]", call, got, want)
				}
			}
		})
	}
}

func TestNewRedisKeepsReadersByPointer(t *testing.T) {
	store := NewRedis(logger.New("INFO", ""), "127.0.0.1:1", []string{"127.0.0.1:2", "127.0.0.1:3"}, "", "", "p")
	defer store.Close()
	backend := store.red
	if backend == nil {
		t.Fatal("redis engine is nil")
	}
	if backend.writer == nil {
		t.Fatal("writer is nil")
	}
	if len(backend.readers) != 2 {
		t.Fatalf("len(readers)=%d, want 2", len(backend.readers))
	}
	if backend.readers[0] == nil || backend.readers[1] == nil {
		t.Fatal("a reader pointer is nil")
	}
	if backend.readers[0] == backend.readers[1] {
		t.Fatal("both read hosts share one SimpleRedis pointer")
	}
	if backend.readers[0] == backend.writer || backend.readers[1] == backend.writer {
		t.Fatal("a reader aliases the writer")
	}
	want := []int{1, 0, 1, 0}
	for call, idx := range want {
		got := indexOfReader(backend, backend.nextReader())
		if got != idx {
			t.Errorf("call %d: nextReader() -> reader[%d], want reader[%d]", call, got, idx)
		}
	}
}

func TestPrefixed(t *testing.T) {
	if got := prefixed("", "ip"); got != "ip" {
		t.Fatalf("empty prefix: got %q", got)
	}
	if got := prefixed("ab", "ip"); got != "ab:ip" {
		t.Fatalf("prefix: got %q", got)
	}
}

func TestRedisReplicaMissDoesNotReadWriter(t *testing.T) {
	writer := startTestStoreRedis(t)
	replica := startTestStoreRedis(t)
	store := NewRedis(logger.New("ERROR", ""), writer.addr(), []string{replica.addr()}, "", "", "sess")
	defer store.Close()
	store.Put(Decision{Scope: "Ip", Value: "203.0.113.10", Kind: "t", Origin: "crowdsec", DurationSec: 60})
	kind, origin, originID, err := store.LookupRemediation("203.0.113.10", nil, nil)
	if err != nil || kind != "" {
		t.Fatalf("replica miss must not retry writer, kind %q origin %q id %d err %v", kind, origin, originID, err)
	}
}

func TestStoreCloseRedisTwice(_ *testing.T) {
	store := NewRedis(logger.New("INFO", ""), "127.0.0.1:1", []string{"127.0.0.1:1"}, "", "", "p")
	store.Close()
	store.Close()
}
