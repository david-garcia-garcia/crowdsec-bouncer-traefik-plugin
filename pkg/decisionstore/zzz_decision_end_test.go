package decisionstore

import (
	"net"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pkg/decisionscope"
	logger "github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pkg/logger"
)

const decisionEndTestIP = "203.0.113.10"

// newDecisionEndTestRedisStore is a Redis store on the in-process RESP stand-in, for decision-end tests.
func newDecisionEndTestRedisStore(t *testing.T) *Store {
	t.Helper()
	server := startTestStoreRedis(t)
	store := NewRedis(logger.New("ERROR", ""), server.addr(), nil, "", "", "sess")
	t.Cleanup(store.Close)
	return store
}

// lookupDecisionEndTestIP looks up decisionEndTestIP with optional header scopes and fails the test on error.
func lookupDecisionEndTestIP(t *testing.T, store *Store, scopes map[string]string) (string, string, time.Duration) {
	t.Helper()
	kind, origin, _, decisionLeft, err := store.LookupRemediation(decisionEndTestIP, net.ParseIP(decisionEndTestIP), scopes)
	if err != nil {
		t.Fatal(err)
	}
	return kind, origin, decisionLeft
}

func TestMemoryStreamDecisionEndEqualsTTLEnd(t *testing.T) {
	store := NewMemory(logger.New("ERROR", ""))
	store.BeginTick()
	store.Put(Decision{Scope: decisionscope.ScopeIP, Value: decisionEndTestIP, Kind: decisionscope.BannedValue, DurationSec: 3600, DecisionDurationSec: 3600})
	store.PublishTick(ElapsedNow())
	slot := store.PublishedMemoryMapForTest()[decisionEndTestIP]
	if slot.DecisionEnd == 0 || slot.DecisionEnd != slot.ExpiresAt {
		t.Fatalf("DecisionEnd %d ExpiresAt %d, want equal and known", slot.DecisionEnd, slot.ExpiresAt)
	}
	kind, _, decisionLeft := lookupDecisionEndTestIP(t, store, nil)
	if kind != decisionscope.BannedValue || decisionLeft <= 0 || decisionLeft > 3600*time.Second {
		t.Fatalf("kind %q left %v, want ban with 0 < left <= 1h", kind, decisionLeft)
	}
}

func TestMemoryLiveMemoKeepsDecisionEndPastTTL(t *testing.T) {
	store := NewMemory(logger.New("ERROR", ""))
	store.Put(Decision{Scope: decisionscope.ScopeIP, Value: decisionEndTestIP, Kind: decisionscope.BannedValue, DurationSec: 60, DecisionDurationSec: 14400})
	kind, _, decisionLeft := lookupDecisionEndTestIP(t, store, nil)
	if kind != decisionscope.BannedValue || decisionLeft <= 60*time.Second {
		t.Fatalf("kind %q left %v, want ban with left > 60s", kind, decisionLeft)
	}
	slot := store.PublishedMemoryMapForTest()[decisionEndTestIP]
	if slot.ExpiresAt > ElapsedNow()+60 {
		t.Fatalf("ExpiresAt %d past the 60s cache TTL (now %d)", slot.ExpiresAt, ElapsedNow())
	}
}

func TestMemoryNoBanMemoHasNoDecisionEnd(t *testing.T) {
	store := NewMemory(logger.New("ERROR", ""))
	store.Put(Decision{Scope: decisionscope.ScopeIP, Value: decisionEndTestIP, Kind: decisionscope.NoBannedValue, DurationSec: 60})
	if slot := store.PublishedMemoryMapForTest()[decisionEndTestIP]; slot.DecisionEnd != 0 {
		t.Fatalf("f memo DecisionEnd %d, want 0", slot.DecisionEnd)
	}
}

func TestMemoryDecisionWithoutDurationHasNoTimeLeft(t *testing.T) {
	store := NewMemory(logger.New("ERROR", ""))
	store.Put(Decision{Scope: decisionscope.ScopeIP, Value: decisionEndTestIP, Kind: decisionscope.BannedValue, DurationSec: 60})
	if kind, _, decisionLeft := lookupDecisionEndTestIP(t, store, nil); kind != decisionscope.BannedValue || decisionLeft != 0 {
		t.Fatalf("kind %q left %v, want ban with no time left", kind, decisionLeft)
	}
}

func TestMemoryRangeWinnerHasNoTimeLeft(t *testing.T) {
	store := NewMemory(logger.New("ERROR", ""))
	store.Put(Decision{Scope: decisionscope.ScopeIP, Value: backendRangeIP, Kind: decisionscope.CaptchaValue, DurationSec: 600, DecisionDurationSec: 600})
	if err := store.ApplyRangeBatch(map[string]string{backendRangeCIDR: decisionscope.BannedValue}, nil); err != nil {
		t.Fatal(err)
	}
	kind, _, _, decisionLeft, err := store.LookupRemediation(backendRangeIP, net.ParseIP(backendRangeIP), nil)
	if err != nil || kind != decisionscope.BannedValue || decisionLeft != 0 {
		t.Fatalf("kind %q left %v err %v, want Range ban with no time left", kind, decisionLeft, err)
	}
}

func TestMemoryHeaderBanOverIPCaptchaReturnsHeaderEnd(t *testing.T) {
	store := NewMemory(logger.New("ERROR", ""))
	store.PutMany([]Decision{
		{Scope: decisionscope.ScopeIP, Value: decisionEndTestIP, Kind: decisionscope.CaptchaValue, DurationSec: 600, DecisionDurationSec: 600},
		{Scope: decisionscope.ScopeCountry, Value: "FR", Kind: decisionscope.BannedValue, DurationSec: 3600, DecisionDurationSec: 3600},
	})
	kind, _, decisionLeft := lookupDecisionEndTestIP(t, store, map[string]string{decisionscope.ScopeCountry: "FR"})
	if kind != decisionscope.BannedValue || decisionLeft <= 600*time.Second {
		t.Fatalf("kind %q left %v, want the Country ban's end (> 600s)", kind, decisionLeft)
	}
}

func TestRedisPutWritesDecisionEndAsFourthLine(t *testing.T) {
	store := newDecisionEndTestRedisStore(t)
	before := time.Now().Unix()
	store.Put(Decision{
		Scope: decisionscope.ScopeIP, Value: decisionEndTestIP, Kind: decisionscope.BannedValue,
		Origin: "crowdsec", Scenario: "crowdsecurity/http-probing", DurationSec: 3600, DecisionDurationSec: 3600,
	})
	stored, err := store.red.get(decisionEndTestIP)
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(stored, "\n")
	if len(lines) != 4 || lines[0] != decisionscope.BannedValue || lines[1] != "crowdsec" || lines[2] != "crowdsecurity/http-probing" {
		t.Fatalf("redis value %q, want kind, origin, scenario, end", stored)
	}
	endUnix, err := strconv.ParseInt(lines[3], 10, 64)
	if err != nil || endUnix < before+3600 || endUnix > time.Now().Unix()+3600 {
		t.Fatalf("end line %q, want now+3600", lines[3])
	}
	kind, origin, decisionLeft := lookupDecisionEndTestIP(t, store, nil)
	if kind != decisionscope.BannedValue || origin != "crowdsec" || decisionLeft <= 0 || decisionLeft > 3600*time.Second {
		t.Fatalf("kind %q origin %q left %v", kind, origin, decisionLeft)
	}
}

func TestRedisDecisionEndWithEmptyOriginAndScenario(t *testing.T) {
	store := newDecisionEndTestRedisStore(t)
	store.Put(Decision{Scope: decisionscope.ScopeIP, Value: decisionEndTestIP, Kind: decisionscope.BannedValue, DurationSec: 600, DecisionDurationSec: 600})
	stored, err := store.red.get(decisionEndTestIP)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(stored, decisionscope.BannedValue+"\n\n\n") || strings.Count(stored, "\n") != 3 {
		t.Fatalf("redis value %q, want kind, two empty lines, end", stored)
	}
	kind, origin, decisionLeft := lookupDecisionEndTestIP(t, store, nil)
	if kind != decisionscope.BannedValue || origin != "" || decisionLeft <= 0 {
		t.Fatalf("kind %q origin %q left %v", kind, origin, decisionLeft)
	}
}

func TestRedisPutWithoutDecisionDurationKeepsThreeLineValue(t *testing.T) {
	store := newDecisionEndTestRedisStore(t)
	store.Put(Decision{Scope: decisionscope.ScopeIP, Value: decisionEndTestIP, Kind: decisionscope.BannedValue, Origin: "crowdsec", Scenario: "ssh-bf", DurationSec: 60})
	stored, err := store.red.get(decisionEndTestIP)
	if err != nil || stored != "t\ncrowdsec\nssh-bf" {
		t.Fatalf("redis value %q err %v, want the three-line value", stored, err)
	}
}

func TestRedisValueWithoutUsableEndHasNoTimeLeft(t *testing.T) {
	pastEnd := strconv.FormatInt(time.Now().Add(-time.Minute).Unix(), 10)
	for name, stored := range map[string]string{
		"bare kind":     "t",
		"two lines":     "t\ncrowdsec",
		"three lines":   "t\ncrowdsec\nssh-bf",
		"word end":      "t\ncrowdsec\nssh-bf\nsoon",
		"zero end":      "t\ncrowdsec\nssh-bf\n0",
		"negative end":  "t\ncrowdsec\nssh-bf\n-5",
		"past end":      "t\ncrowdsec\nssh-bf\n" + pastEnd,
		"numeric scene": "t\ncrowdsec\n" + strconv.FormatInt(time.Now().Add(time.Hour).Unix(), 10),
	} {
		t.Run(name, func(t *testing.T) {
			store := newDecisionEndTestRedisStore(t)
			store.red.set(decisionEndTestIP, stored, 60)
			kind, origin, decisionLeft := lookupDecisionEndTestIP(t, store, nil)
			if kind != decisionscope.BannedValue || decisionLeft != 0 {
				t.Fatalf("kind %q left %v, want ban with no time left", kind, decisionLeft)
			}
			if stored != "t" && origin != "crowdsec" {
				t.Fatalf("origin %q, want crowdsec", origin)
			}
		})
	}
}

func TestUnpackNumericThreeLineScenarioIsNotAnEnd(t *testing.T) {
	hit, endUnix := unpackFromString("t\ncrowdsec\n4102444800")
	if endUnix != 0 || hit.scenario != "4102444800" || hit.origin != "crowdsec" {
		t.Fatalf("hit %+v end %d, want scenario kept and no end", hit, endUnix)
	}
}

func TestUnpackFourLineValueReadsEnd(t *testing.T) {
	stored := packToString(lookupHit{kind: decisionscope.BannedValue, origin: "crowdsec", scenario: "ssh-bf"}, 4102444800)
	hit, endUnix := unpackFromString(stored)
	if endUnix != 4102444800 || hit.kind != decisionscope.BannedValue || hit.origin != "crowdsec" || hit.scenario != "ssh-bf" {
		t.Fatalf("hit %+v end %d from %q", hit, endUnix, stored)
	}
}

// TestThreeWayReaderKeepsKindAndOriginOfFourLineValue reads a value with an end the way fork
// releases v1.9.4 to v1.9.7 do (cut kind, cut origin, the rest is the scenario).
func TestThreeWayReaderKeepsKindAndOriginOfFourLineValue(t *testing.T) {
	stored := packToString(lookupHit{kind: decisionscope.BannedValue, origin: "crowdsec", scenario: "ssh-bf"}, 4102444800)
	kind, rest, _ := strings.Cut(stored, "\n")
	origin, _, _ := strings.Cut(rest, "\n")
	if kind != decisionscope.BannedValue || origin != "crowdsec" {
		t.Fatalf("three-way reader kind %q origin %q from %q", kind, origin, stored)
	}
}
