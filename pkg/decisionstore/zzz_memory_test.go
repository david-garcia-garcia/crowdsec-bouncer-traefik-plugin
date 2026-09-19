package decisionstore

import (
	"net"
	"testing"
	"time"

	"github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pkg/decisionscope"
	logger "github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pkg/logger"
)

func TestMemoryTickPublishLookup(t *testing.T) {
	store := NewMemory(nil, logger.New("ERROR", ""))
	store.BeginTick()
	store.Put(Decision{Scope: decisionscope.ScopeIP, Value: "203.0.113.10", Kind: decisionscope.BannedValue, DurationSec: 60})
	store.PublishTick(0)
	kind, _, _, err := store.LookupRemediation("203.0.113.10", net.ParseIP("203.0.113.10"), nil, nil)
	if err != nil || kind != decisionscope.BannedValue {
		t.Fatalf("kind %q err %v", kind, err)
	}
	if _, ok := store.PublishedMemoryMapForTest()["203.0.113.10"]; !ok {
		t.Fatal("published map missing slot")
	}
}

func TestMemoryExpiryOnPublish(t *testing.T) {
	store := NewMemory(nil, logger.New("ERROR", ""))
	store.BeginTick()
	store.Put(Decision{Scope: decisionscope.ScopeIP, Value: "203.0.113.10", Kind: decisionscope.BannedValue, DurationSec: -1})
	store.PublishTick(time.Now().Unix())
	_, _, _, err := store.LookupRemediation("203.0.113.10", net.ParseIP("203.0.113.10"), nil, nil)
	if err == nil {
		t.Fatal("expired slot must miss")
	}
}
