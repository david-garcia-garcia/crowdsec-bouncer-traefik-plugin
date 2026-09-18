package cache

import (
	"strconv"
	"testing"
	"time"

	logger "github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pkg/logger"
)

// shrinkPinWindow shortens the writer pin so a test can watch it elapse.
func shrinkPinWindow(t *testing.T, client *Client, window time.Duration) *redisCache {
	t.Helper()
	rc, ok := client.cache.(*redisCache)
	if !ok {
		t.Fatalf("cache type %T, want *redisCache", client.cache)
	}
	rc.pinWindow = window
	return rc
}

// newLaggingReplicaClient wires a client whose single read host never caught up with the writer,
// which is the worst case of the lag RedisCacheReadHosts exposes.
func newLaggingReplicaClient(t *testing.T) (*Client, *fakeRedis) {
	t.Helper()
	_, writerAddr := startFakeRedis(t, false)
	replica, replicaAddr := startFakeRedis(t, true)
	client := &Client{}
	client.New(logger.New("INFO", ""), true, writerAddr, []string{replicaAddr}, "", "", "p")
	t.Cleanup(client.Close)
	return client, replica
}

// Test_ReadAfterWriteDoesNotReadALaggingReplica is the defect: every read went round-robin through
// nextReader, so an IP this process had just banned read back as a miss, and stream/alone mode reads
// a miss as "no decision affecting this IP" and serves the request it had already decided to block.
func Test_ReadAfterWriteDoesNotReadALaggingReplica(t *testing.T) {
	client, _ := newLaggingReplicaClient(t)

	client.Set("1.2.3.4", "t", 60)

	got, err := client.Get("1.2.3.4")
	if err != nil || got != "t" {
		t.Fatalf("Get right after Set = %q err %v, want the ban %q we just wrote", got, err, "t")
	}

	many, manyErr := client.GetMany([]string{"1.2.3.4"})
	if manyErr != nil {
		t.Fatalf("GetMany right after Set err %v", manyErr)
	}
	if many["1.2.3.4"] != "t" {
		t.Fatalf("GetMany right after Set = %+v, want the ban %q we just wrote", many, "t")
	}
}

// Test_ReadAfterDeleteDoesNotReadALaggingReplica is the same window in the other direction: a
// decision this process dropped must not read back as still active from a replica that still holds
// it, because that serves a ban CrowdSec already lifted.
func Test_ReadAfterDeleteDoesNotReadALaggingReplica(t *testing.T) {
	writer, writerAddr := startFakeRedis(t, false)
	replica, replicaAddr := startFakeRedis(t, false)
	writer.set("p:1.2.3.4", "t")
	replica.set("p:1.2.3.4", "t")
	client := &Client{}
	client.New(logger.New("INFO", ""), true, writerAddr, []string{replicaAddr}, "", "", "p")
	defer client.Close()

	client.Delete("1.2.3.4")

	got, err := client.Get("1.2.3.4")
	if err == nil || err.Error() != CacheMiss {
		t.Fatalf("Get right after Delete = %q err %v, want %s", got, err, CacheMiss)
	}
}

// Test_ReadsReturnToTheReplicasAfterThePinWindow is the other half of the contract, and the reason
// this is a pin and not writer-only reads: once the window elapses the read hosts carry the lookup
// again. Losing that would be a performance regression paid by every request in every deployment.
func Test_ReadsReturnToTheReplicasAfterThePinWindow(t *testing.T) {
	writer, writerAddr := startFakeRedis(t, false)
	replica, replicaAddr := startFakeRedis(t, true)
	client := &Client{}
	client.New(logger.New("INFO", ""), true, writerAddr, []string{replicaAddr}, "", "", "p")
	defer client.Close()
	shrinkPinWindow(t, client, 20*time.Millisecond)

	client.Set("1.2.3.4", "t", 60)
	if _, err := client.Get("1.2.3.4"); err != nil {
		t.Fatalf("Get inside the window err %v, want the value from the writer", err)
	}
	if got := replica.countVerb("GET"); got != 0 {
		t.Fatalf("replica served %d GET inside the window, want 0", got)
	}
	writerGets := writer.countVerb("GET")

	time.Sleep(40 * time.Millisecond)
	if _, err := client.Get("1.2.3.4"); err == nil {
		t.Fatal("Get past the window did not reach the replica")
	}
	if got := replica.countVerb("GET"); got != 1 {
		t.Fatalf("replica served %d GET past the window, want 1", got)
	}
	if got := writer.countVerb("GET"); got != writerGets {
		t.Fatalf("writer served %d GET past the window, want the %d it already had", got, writerGets)
	}
}

// Test_WritingOneKeyDoesNotPinAnother keeps the pin per key. A single deadline covering every read
// would have degenerated in live mode, where the cache is a per-request memo and writes never stop,
// so the window would never lapse and every read would land on the writer.
func Test_WritingOneKeyDoesNotPinAnother(t *testing.T) {
	client, replica := newLaggingReplicaClient(t)

	client.Set("1.2.3.4", "t", 60)
	if _, err := client.Get("5.6.7.8"); err == nil {
		t.Fatal("an untouched key did not reach the replica")
	}
	if got := replica.countVerb("GET"); got != 1 {
		t.Fatalf("replica served %d GET for an untouched key, want 1", got)
	}
}

// Test_GetConsistentAlwaysReadsTheWriter covers the read-modify-write entry point, which cannot
// rely on the window: ApplyRangeBatch reads the shared Range blob a whole update interval after it
// last wrote it.
func Test_GetConsistentAlwaysReadsTheWriter(t *testing.T) {
	writer, writerAddr := startFakeRedis(t, false)
	replica, replicaAddr := startFakeRedis(t, true)
	writer.set("p:range:index", "10.0.0.0/8=t")
	client := &Client{}
	client.New(logger.New("INFO", ""), true, writerAddr, []string{replicaAddr}, "", "", "p")
	defer client.Close()

	got, err := client.GetConsistent("range:index")
	if err != nil || got != "10.0.0.0/8=t" {
		t.Fatalf("GetConsistent = %q err %v, want the writer copy", got, err)
	}
	if served := replica.countVerb("GET"); served != 0 {
		t.Fatalf("replica served %d GET for a consistent read, want 0", served)
	}
}

// Test_PinOverflowFailsTowardTheWriter bounds the memory the pin can hold. A startup=true stream
// pull writes the whole decision list, far past the cap; the set must not grow with it, and the
// fallback must be the writer, never a silent return to a replica that has not caught up.
func Test_PinOverflowFailsTowardTheWriter(t *testing.T) {
	client, replica := newLaggingReplicaClient(t)
	rc := shrinkPinWindow(t, client, time.Minute)

	for i := range writerPinMaxKeys + 64 {
		client.Set("ip-"+strconv.Itoa(i), "t", 60)
	}

	rc.pinMu.Lock()
	held := len(rc.pinned)
	rc.pinMu.Unlock()
	if held > writerPinMaxKeys {
		t.Fatalf("pinned set holds %d keys, want at most %d", held, writerPinMaxKeys)
	}
	if _, err := client.Get("never-written"); err == nil || err.Error() != CacheMiss {
		t.Fatalf("Get after overflow err %v, want the writer miss %s", err, CacheMiss)
	}
	if served := replica.countVerb("GET"); served != 0 {
		t.Fatalf("replica served %d GET after overflow, want 0: overflow must fail toward the writer", served)
	}
}
