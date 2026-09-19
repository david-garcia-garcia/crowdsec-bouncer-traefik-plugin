package decisionstore

import (
	"errors"
	"net"
	"testing"
	"time"

	"github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pkg/decisionscope"
	logger "github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pkg/logger"
)

func TestMemoryTickPublishLookup(t *testing.T) {
	store := NewMemory(logger.New("ERROR", ""))
	store.BeginTick()
	store.Put(Decision{Scope: decisionscope.ScopeIP, Value: "203.0.113.10", Kind: decisionscope.BannedValue, DurationSec: 60})
	store.PublishTick(0)
	kind, _, _, err := store.LookupRemediation("203.0.113.10", net.ParseIP("203.0.113.10"), nil)
	if err != nil || kind != decisionscope.BannedValue {
		t.Fatalf("kind %q err %v", kind, err)
	}
	if _, ok := store.PublishedMemoryMapForTest()["203.0.113.10"]; !ok {
		t.Fatal("published map missing slot")
	}
}

func TestMemoryExpiryOnPublish(t *testing.T) {
	store := NewMemory(logger.New("ERROR", ""))
	store.BeginTick()
	store.Put(Decision{Scope: decisionscope.ScopeIP, Value: "203.0.113.10", Kind: decisionscope.BannedValue, DurationSec: -1})
	store.PublishTick(time.Now().Unix())
	_, _, originID, err := store.LookupRemediation("203.0.113.10", net.ParseIP("203.0.113.10"), nil)
	_ = originID
	if !errors.Is(err, ErrMiss) || err.Error() != "store:miss" {
		t.Fatalf("expired slot must miss, got %v", err)
	}
}

func TestHydrateRangeKeepsLastOnUnreachable(t *testing.T) {
	store := NewMemory(logger.New("ERROR", ""))
	if err := store.ApplyRangeBatch(map[string]string{"10.0.0.0/8": decisionscope.BannedValue}, nil); err != nil {
		t.Fatal(err)
	}
	if got := store.RangeMembership().Remediation(net.ParseIP("10.1.2.3")); got != decisionscope.BannedValue {
		t.Fatalf("seed got %q, want ban", got)
	}
	red := newRedis(logger.New("ERROR", ""), "127.0.0.1:1", nil, "", "", "p")
	store.engine = redisEngine(red)
	store.red = red
	store.mem = nil
	defer store.Close()
	store.HydrateRange()
	if got := store.RangeMembership().Remediation(net.ParseIP("10.1.2.3")); got != decisionscope.BannedValue {
		t.Fatalf("unreachable hydrate wiped membership, got %q", got)
	}
}
