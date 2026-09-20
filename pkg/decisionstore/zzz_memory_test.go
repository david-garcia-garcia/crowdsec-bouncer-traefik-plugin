package decisionstore

import (
	"bytes"
	"errors"
	"log/slog"
	"net"
	"strings"
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

func TestElapsedNowIgnoresWallStepBack(t *testing.T) {
	before := elapsedNow()
	savedOrigin := originUnix
	originUnix = time.Now().Unix() + 3600
	t.Cleanup(func() { originUnix = savedOrigin })
	after := elapsedNow()
	if after < before {
		t.Fatalf("elapsedNow decreased after wall step-back: before %d after %d", before, after)
	}
}

func TestMemoryDurationZeroMissesAfterPublish(t *testing.T) {
	store := NewMemory(logger.New("ERROR", ""))
	store.BeginTick()
	store.Put(Decision{Scope: decisionscope.ScopeIP, Value: "203.0.113.10", Kind: decisionscope.BannedValue, DurationSec: 0})
	store.PublishTick(ElapsedNow())
	_, _, _, err := store.LookupRemediation("203.0.113.10", net.ParseIP("203.0.113.10"), nil)
	if !errors.Is(err, ErrMiss) {
		t.Fatalf("duration 0 must miss after publish, got %v", err)
	}
}

func TestMemoryExpiryOnPublish(t *testing.T) {
	store := NewMemory(logger.New("ERROR", ""))
	store.BeginTick()
	store.Put(Decision{Scope: decisionscope.ScopeIP, Value: "203.0.113.10", Kind: decisionscope.BannedValue, DurationSec: -1})
	store.PublishTick(ElapsedNow())
	_, _, originID, err := store.LookupRemediation("203.0.113.10", net.ParseIP("203.0.113.10"), nil)
	_ = originID
	if !errors.Is(err, ErrMiss) || err.Error() != "store:miss" {
		t.Fatalf("expired slot must miss, got %v", err)
	}
}

func TestMemoryTickPutHiddenUntilPublish(t *testing.T) {
	store := NewMemory(logger.New("ERROR", ""))
	store.BeginTick()
	store.Put(Decision{Scope: decisionscope.ScopeIP, Value: "203.0.113.10", Kind: decisionscope.BannedValue, DurationSec: 60})
	kind, origin, originID, err := store.LookupRemediation("203.0.113.10", net.ParseIP("203.0.113.10"), nil)
	if !errors.Is(err, ErrMiss) {
		t.Fatalf("tick Put must stay unpublished, kind %q origin %q id %d err %v", kind, origin, originID, err)
	}
	store.PublishTick(0)
	kind, origin, originID, err = store.LookupRemediation("203.0.113.10", net.ParseIP("203.0.113.10"), nil)
	if err != nil || kind != decisionscope.BannedValue {
		t.Fatalf("kind %q origin %q id %d err %v", kind, origin, originID, err)
	}
}

func TestMemoryTickDeleteOnlyMissesAfterPublish(t *testing.T) {
	store := NewMemory(logger.New("ERROR", ""))
	store.BeginTick()
	store.Put(Decision{Scope: decisionscope.ScopeIP, Value: "203.0.113.10", Kind: decisionscope.BannedValue, DurationSec: 60})
	store.PublishTick(0)
	store.BeginTick()
	store.Delete(decisionscope.ScopeIP, "203.0.113.10")
	store.PublishTick(0)
	kind, origin, originID, err := store.LookupRemediation("203.0.113.10", net.ParseIP("203.0.113.10"), nil)
	if !errors.Is(err, ErrMiss) {
		t.Fatalf("tick Delete must miss after publish, kind %q origin %q id %d err %v", kind, origin, originID, err)
	}
}

func TestMemoryInternOverflowWarns(t *testing.T) {
	var logged bytes.Buffer
	log := slog.New(slog.NewJSONHandler(&logged, &slog.HandlerOptions{Level: slog.LevelWarn}))
	store := NewMemory(log)
	store.FillUntilMaxForTest()
	store.BeginTick()
	store.Put(Decision{Scope: decisionscope.ScopeIP, Value: "203.0.113.99", Kind: decisionscope.BannedValue, Origin: "overflow-origin", DurationSec: 60})
	store.PublishTick(0)
	if !strings.Contains(logged.String(), "decisionstore:intern overflow") {
		t.Fatalf("want overflow Warn, got %s", logged.String())
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
