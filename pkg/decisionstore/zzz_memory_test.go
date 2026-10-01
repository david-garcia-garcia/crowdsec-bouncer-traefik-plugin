package decisionstore

import (
	"bytes"
	"log/slog"
	"net"
	"strconv"
	"strings"
	"testing"

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

func TestElapsedNowStaysAboveSkipSentinel(t *testing.T) {
	if got := elapsedNow(); got < elapsedBias {
		t.Fatalf("elapsedNow %d, want at least bias %d", got, elapsedBias)
	}
}

func TestMemoryDurationZeroMissesAfterPublish(t *testing.T) {
	store := NewMemory(logger.New("ERROR", ""))
	store.BeginTick()
	store.Put(Decision{Scope: decisionscope.ScopeIP, Value: "203.0.113.10", Kind: decisionscope.BannedValue, DurationSec: 0})
	store.PublishTick(ElapsedNow())
	kind, _, originID, err := store.LookupRemediation("203.0.113.10", net.ParseIP("203.0.113.10"), nil)
	_ = originID
	if err != nil || kind != "" {
		t.Fatalf("duration 0 must miss after publish, got kind %q err %v", kind, err)
	}
}

func TestMemoryExpiryOnPublish(t *testing.T) {
	store := NewMemory(logger.New("ERROR", ""))
	store.BeginTick()
	store.Put(Decision{Scope: decisionscope.ScopeIP, Value: "203.0.113.10", Kind: decisionscope.BannedValue, DurationSec: -1})
	store.PublishTick(ElapsedNow())
	kind, _, originID, err := store.LookupRemediation("203.0.113.10", net.ParseIP("203.0.113.10"), nil)
	_ = originID
	if err != nil || kind != "" {
		t.Fatalf("expired slot must miss, got kind %q err %v", kind, err)
	}
}

func TestMemoryTickPutHiddenUntilPublish(t *testing.T) {
	store := NewMemory(logger.New("ERROR", ""))
	store.BeginTick()
	store.Put(Decision{Scope: decisionscope.ScopeIP, Value: "203.0.113.10", Kind: decisionscope.BannedValue, DurationSec: 60})
	kind, origin, originID, err := store.LookupRemediation("203.0.113.10", net.ParseIP("203.0.113.10"), nil)
	if err != nil || kind != "" {
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
	if err != nil || kind != "" {
		t.Fatalf("tick Delete must miss after publish, kind %q origin %q id %d err %v", kind, origin, originID, err)
	}
}

func TestMemoryInternOverflowPacksZero(t *testing.T) {
	var logged bytes.Buffer
	log := slog.New(slog.NewJSONHandler(&logged, &slog.HandlerOptions{Level: slog.LevelWarn}))
	store := NewMemory(log)
	store.FillUntilMaxForTest()
	store.BeginTick()
	store.Put(Decision{Scope: decisionscope.ScopeIP, Value: "203.0.113.99", Kind: decisionscope.BannedValue, Origin: "overflow-origin", DurationSec: 60})
	store.PublishTick(0)
	if strings.Contains(logged.String(), "intern overflow") {
		t.Fatalf("origin overflow must stay silent, got %s", logged.String())
	}
	kind, _, originID, err := store.LookupRemediation("203.0.113.99", net.ParseIP("203.0.113.99"), nil)
	if err != nil || kind != decisionscope.BannedValue || originID != 0 {
		t.Fatalf("kind %q id %d err %v", kind, originID, err)
	}
}

func TestMemoryOriginPackSaturatesAt12Bits(t *testing.T) {
	var logged bytes.Buffer
	log := slog.New(slog.NewJSONHandler(&logged, &slog.HandlerOptions{Level: slog.LevelWarn}))
	store := NewMemory(log)
	for n := 1; n <= packedOriginMask; n++ {
		if _, ok := store.OriginID(strconv.Itoa(n)); !ok {
			t.Fatalf("origin fill %d", n)
		}
	}
	store.BeginTick()
	store.Put(Decision{
		Scope: decisionscope.ScopeIP, Value: "203.0.113.10", Kind: decisionscope.BannedValue,
		Origin: "saturate-origin", Scenario: "ssh-bf", DurationSec: 60,
	})
	store.PublishTick(0)
	if strings.Contains(logged.String(), "intern overflow") {
		t.Fatalf("origin saturate must stay silent, got %s", logged.String())
	}
	kind, _, originID, err := store.LookupRemediation("203.0.113.10", net.ParseIP("203.0.113.10"), nil)
	if err != nil || kind != decisionscope.BannedValue || originID != 0 {
		t.Fatalf("kind %q id %d err %v", kind, originID, err)
	}
	slot, ok := store.PublishedMemoryMapForTest()["203.0.113.10"]
	if !ok {
		t.Fatal("missing slot")
	}
	if packedFamily(slot.Word) != "ipv4" || PackedScenarioIDForTest(slot.Word) == 0 {
		t.Fatalf("family %q scenario %d", packedFamily(slot.Word), PackedScenarioIDForTest(slot.Word))
	}
	if store.ScenarioNameForTest(PackedScenarioIDForTest(slot.Word)) != "ssh-bf" {
		t.Fatalf("scenario %q", store.ScenarioNameForTest(PackedScenarioIDForTest(slot.Word)))
	}
}

func TestMemoryListsInternTwice(t *testing.T) {
	store := NewMemory(logger.New("ERROR", ""))
	store.BeginTick()
	store.Put(Decision{
		Scope: decisionscope.ScopeIP, Value: "203.0.113.10", Kind: decisionscope.BannedValue,
		Origin: "lists:firehol_level1", Scenario: "firehol_level1", DurationSec: 60,
	})
	store.PublishTick(0)
	kind, _, originID, err := store.LookupRemediation("203.0.113.10", net.ParseIP("203.0.113.10"), nil)
	if err != nil || kind != decisionscope.BannedValue || store.OriginName(originID) != "lists:firehol_level1" {
		t.Fatalf("kind %q origin %q err %v", kind, store.OriginName(originID), err)
	}
	slot, ok := store.PublishedMemoryMapForTest()["203.0.113.10"]
	if !ok {
		t.Fatal("missing slot")
	}
	if store.ScenarioNameForTest(PackedScenarioIDForTest(slot.Word)) != "firehol_level1" {
		t.Fatalf("scenario %q", store.ScenarioNameForTest(PackedScenarioIDForTest(slot.Word)))
	}
}

func TestMemoryScenarioInternOverflowPacksZero(t *testing.T) {
	var logged bytes.Buffer
	log := slog.New(slog.NewJSONHandler(&logged, &slog.HandlerOptions{Level: slog.LevelWarn}))
	store := NewMemory(log)
	store.FillScenarioUntilMaxForTest()
	store.BeginTick()
	store.Put(Decision{
		Scope: decisionscope.ScopeIP, Value: "203.0.113.10", Kind: decisionscope.BannedValue,
		Origin: "crowdsec", Scenario: "overflow-scenario", DurationSec: 60,
	})
	store.PublishTick(0)
	if strings.Contains(logged.String(), "scenario intern overflow") {
		t.Fatalf("scenario overflow must stay silent, got %s", logged.String())
	}
	kind, _, originID, err := store.LookupRemediation("203.0.113.10", net.ParseIP("203.0.113.10"), nil)
	if err != nil || kind != decisionscope.BannedValue || store.OriginName(originID) != "crowdsec" {
		t.Fatalf("kind %q origin %q err %v", kind, store.OriginName(originID), err)
	}
	slot, ok := store.PublishedMemoryMapForTest()["203.0.113.10"]
	if !ok || PackedScenarioIDForTest(slot.Word) != 0 {
		t.Fatalf("scenario id %d", PackedScenarioIDForTest(slot.Word))
	}
}

func TestRedisPutHasNoInternId(t *testing.T) {
	server := startTestStoreRedis(t)
	store := NewRedis(logger.New("ERROR", ""), server.addr(), nil, "", "", "sess")
	t.Cleanup(store.Close)
	store.Put(Decision{
		Scope: decisionscope.ScopeIP, Value: "203.0.113.10", Kind: decisionscope.BannedValue,
		Origin: "crowdsec", Scenario: "ssh-bf", DurationSec: 60,
	})
	got, err := store.red.get("203.0.113.10")
	if err != nil {
		t.Fatal(err)
	}
	want := KindOriginString(decisionscope.BannedValue, "crowdsec")
	if got != want {
		t.Fatalf("redis payload %q, want %q", got, want)
	}
	kind, origin, originID, lookupErr := store.LookupRemediation("203.0.113.10", net.ParseIP("203.0.113.10"), nil)
	if lookupErr != nil || kind != decisionscope.BannedValue || origin != "crowdsec" || originID != 0 {
		t.Fatalf("kind %q origin %q id %d err %v", kind, origin, originID, lookupErr)
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
