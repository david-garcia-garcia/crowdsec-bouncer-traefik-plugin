package cache

import (
	"context"
	"testing"

	logger "github.com/maxlerebourg/crowdsec-bouncer-traefik-plugin/pkg/logger"
)

// Test_SetNonPositiveTTLIsNoopInMemory locks the dangerous half of the old behavior: the vendored
// TTL map stored a negative TTL as timestamp -1, which its Get reads as "never expires", so a
// cached ban outlived the decision that justified it with no upper bound.
func Test_SetNonPositiveTTLIsNoopInMemory(t *testing.T) {
	for _, duration := range []int64{0, -1, -3600} {
		client := &Client{cache: &localCache{}, log: logger.New("INFO", "")}
		client.Set("1.2.3.4", "t", duration)
		got, err := client.Get("1.2.3.4")
		if err == nil || err.Error() != CacheMiss {
			t.Fatalf("Set(ttl=%d) then Get = %q err %v, want %s", duration, got, err, CacheMiss)
		}
	}
}

// Test_SetNonPositiveTTLLeavesExistingEntry documents the rest of the no-op: a rejected write does
// not clobber a live entry either.
func Test_SetNonPositiveTTLLeavesExistingEntry(t *testing.T) {
	client := &Client{cache: &localCache{}, log: logger.New("INFO", "")}
	client.Set("1.2.3.4", "t", 60)
	client.Set("1.2.3.4", "f", 0)
	got, err := client.Get("1.2.3.4")
	if err != nil || got != "t" {
		t.Fatalf("Get after a rejected write = %q err %v, want the live %q", got, err, "t")
	}
}

// Test_AcquireNonPositiveTTLDoesNotTakeTheLease covers the same danger on the lease verb: in memory
// a negative TTL took a lease that never expired, so that instance never polled the stream again,
// and a zero TTL stored nothing, so every caller won and the lease excluded nobody.
func Test_AcquireNonPositiveTTLDoesNotTakeTheLease(t *testing.T) {
	for _, duration := range []int64{0, -1} {
		client := &Client{cache: &localCache{}, log: logger.New("INFO", "")}
		won, err := client.Acquire(context.Background(), "updated", "f", duration)
		if won {
			t.Fatalf("Acquire(ttl=%d) won the lease", duration)
		}
		if err == nil || err.Error() != CacheBadTTL {
			t.Fatalf("Acquire(ttl=%d) err = %v, want %s", duration, err, CacheBadTTL)
		}
		// The rejected acquire must not have taken the key, so a well-formed lease still wins.
		won, err = client.Acquire(context.Background(), "updated", "f", 60)
		if !won || err != nil {
			t.Fatalf("Acquire(ttl=60) after a rejected one = %v err %v, want the win", won, err)
		}
	}
}

// Test_SetNonPositiveTTLSendsNothingToRedis locks the other backend. Redis answered every
// SET ... EX 0 with "ERR invalid expire time in 'set' command" (measured against redis:7-alpine),
// so the write was lost anyway and every call logged an error. A no-op does not reach the wire.
func Test_SetNonPositiveTTLSendsNothingToRedis(t *testing.T) {
	fake, addr := startFakeRedis(t, false)
	client := &Client{}
	client.New(logger.New("INFO", ""), true, addr, nil, "", "", "p")
	defer client.Close()

	client.Set("1.2.3.4", "t", 0)
	client.Set("1.2.3.4", "t", -1)
	if got := fake.countVerb("SET"); got != 0 {
		t.Fatalf("non-positive TTL sent %d SET commands, want 0 (verbs: %v)", got, fake.sentVerbs())
	}

	client.Set("1.2.3.4", "t", 60)
	if got := fake.countVerb("SET"); got != 1 {
		t.Fatalf("a valid TTL sent %d SET commands, want 1", got)
	}
	value, err := client.Get("1.2.3.4")
	if err != nil || value != "t" {
		t.Fatalf("Get after a valid Set = %q err %v, want %q", value, err, "t")
	}
}

// Test_AcquireNonPositiveTTLSendsNothingToRedis is the lease verb on the Redis backend: the Lua
// body runs the same SET ... EX and earned the same error.
func Test_AcquireNonPositiveTTLSendsNothingToRedis(t *testing.T) {
	fake, addr := startFakeRedis(t, false)
	client := &Client{}
	client.New(logger.New("INFO", ""), true, addr, nil, "", "", "p")
	defer client.Close()

	won, err := client.Acquire(context.Background(), "updated", "f", 0)
	if won || err == nil || err.Error() != CacheBadTTL {
		t.Fatalf("Acquire(ttl=0) = %v err %v, want false %s", won, err, CacheBadTTL)
	}
	if got := fake.countVerb("EVAL") + fake.countVerb("EVALSHA"); got != 0 {
		t.Fatalf("non-positive TTL sent %d Eval commands, want 0 (verbs: %v)", got, fake.sentVerbs())
	}
}
