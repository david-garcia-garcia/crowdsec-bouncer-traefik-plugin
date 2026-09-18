package lapi

import (
	"strconv"
	"strings"
	"testing"

	"github.com/maxlerebourg/crowdsec-bouncer-traefik-plugin/pkg/cache"
	"github.com/maxlerebourg/crowdsec-bouncer-traefik-plugin/pkg/configuration"
	"github.com/maxlerebourg/crowdsec-bouncer-traefik-plugin/pkg/decisionscope"
	logger "github.com/maxlerebourg/crowdsec-bouncer-traefik-plugin/pkg/logger"
)

func newTestMemoryDecisionStore() *DecisionStore {
	log := logger.New("ERROR", "")
	cacheClient := &cache.Client{}
	cacheClient.New(log, false, "", nil, "", "", "")
	return &DecisionStore{cache: cacheClient, log: log, origins: newOriginDictionary(log)}
}

func TestInternOriginReusesId(t *testing.T) {
	store := newTestMemoryDecisionStore()
	first, ok := store.InternOrigin("crowdsec")
	if !ok || first != 1 {
		t.Fatalf("first id %d ok %v", first, ok)
	}
	again, ok := store.InternOrigin("crowdsec")
	if !ok || again != first {
		t.Fatalf("reuse id %d want %d", again, first)
	}
}

func TestSharedStoreSharesOriginIds(t *testing.T) {
	store := newTestMemoryDecisionStore()
	first := &Client{decisionStore: store}
	second := &Client{decisionStore: store}
	id, ok := first.decisionStore.InternOrigin("lists:firehol_level1")
	if !ok {
		t.Fatal("intern")
	}
	if second.OriginName(id) != "lists:firehol_level1" {
		t.Fatalf("shared resolve %q", second.OriginName(id))
	}
	again, ok := second.decisionStore.InternOrigin("lists:firehol_level1")
	if !ok || again != id {
		t.Fatalf("shared intern %d want %d", again, id)
	}
}

func TestIsolatedStoresDoNotShareIds(t *testing.T) {
	first := newTestMemoryDecisionStore()
	second := newTestMemoryDecisionStore()
	if _, ok := first.InternOrigin("crowdsec"); !ok {
		t.Fatal("first intern")
	}
	if first == second {
		t.Fatal("stores must be distinct")
	}
	if second.OriginName(1) != "" {
		t.Fatal("isolated store must not see the other table")
	}
}

func TestOriginOverflowStaysOnStringPathAndLogsOnce(t *testing.T) {
	log, sink := newTestLogSink(0)
	store := &DecisionStore{log: log, origins: newOriginDictionary(log)}
	cacheClient := &cache.Client{}
	cacheClient.New(log, false, "", nil, "", "", "")
	store.cache = cacheClient
	for i := range maxInternedOrigins {
		if _, ok := store.InternOrigin("origin-" + strconv.Itoa(i)); !ok {
			t.Fatalf("fill intern %d", i)
		}
	}
	stored := store.RemediationStored(decisionscope.BannedValue, "overflow-origin")
	if _, packed := stored.PackedWord(); packed {
		t.Fatal("overflow must not pack")
	}
	if stored.IndexForm() != cache.RemediationWithOrigin(decisionscope.BannedValue, "overflow-origin") {
		t.Fatalf("overflow leftover %q", stored.IndexForm())
	}
	_ = store.RemediationStored(decisionscope.BannedValue, "overflow-origin-2")
	logged := sink.String()
	if strings.Count(logged, "origin dictionary full") != 1 {
		t.Fatalf("want one overflow log, got %s", logged)
	}
}

func TestRemediationStoredRedisStaysLeftover(t *testing.T) {
	log := logger.New("ERROR", "")
	cacheClient := &cache.Client{}
	cacheClient.New(log, true, "127.0.0.1:1", nil, "", "", "p")
	t.Cleanup(cacheClient.Close)
	store := &DecisionStore{cache: cacheClient, log: log, origins: newOriginDictionary(log)}
	client := &Client{decisionStore: store, cacheClient: cacheClient, crowdsecMode: configuration.StreamMode}
	stored := client.remediationStored(decisionscope.BannedValue, "crowdsec")
	if _, packed := stored.PackedWord(); packed {
		t.Fatal("redis must stay leftover")
	}
	if stored.IndexForm() != cache.RemediationWithOrigin(decisionscope.BannedValue, "crowdsec") {
		t.Fatalf("redis leftover %q", stored.IndexForm())
	}
}
