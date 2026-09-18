package lapi

import (
	"net"
	"testing"

	"github.com/maxlerebourg/crowdsec-bouncer-traefik-plugin/pkg/cache"
	"github.com/maxlerebourg/crowdsec-bouncer-traefik-plugin/pkg/configuration"
	"github.com/maxlerebourg/crowdsec-bouncer-traefik-plugin/pkg/decisionscope"
	logger "github.com/maxlerebourg/crowdsec-bouncer-traefik-plugin/pkg/logger"
)

func TestStoreStreamDecisionPacksMemoryBan(t *testing.T) {
	store := newTestMemoryDecisionStore()
	client := &Client{
		decisionStore: store,
		cacheClient:   store.Cache(),
		crowdsecMode:  configuration.StreamMode,
		log:           logger.New("ERROR", ""),
	}
	client.storeStreamDecision(Decision{Type: "ban", Scope: "ip", Value: "203.0.113.10", Origin: "crowdsec", Duration: "1h"}, 60)
	found, err := store.Cache().GetManyStored([]string{"203.0.113.10"})
	if err != nil {
		t.Fatal(err)
	}
	id, packed := found["203.0.113.10"].PackedOriginID()
	if !packed {
		t.Fatalf("memory ban must pack, got %#v", found["203.0.113.10"])
	}
	if store.OriginName(id) != "crowdsec" {
		t.Fatalf("resolve %q", store.OriginName(id))
	}
	kind, stored, lookupErr := decisionscope.LookupCachedRemediation(store.Cache(), "203.0.113.10", net.ParseIP("203.0.113.10"), nil, nil)
	if lookupErr != nil || kind != decisionscope.BannedValue {
		t.Fatalf("lookup kind %q err %v", kind, lookupErr)
	}
	if cache.RemediationOrigin(stored) != "" {
		t.Fatalf("allow/lookup must not format a leftover origin, stored %q", stored)
	}
	if store.OriginName(id) != "crowdsec" {
		t.Fatal("drop resolve still needs the table")
	}
}

func TestLookupPackedNoneDoesNotNeedOriginTable(t *testing.T) {
	client := &cache.Client{}
	client.New(logger.New("ERROR", ""), false, "", nil, "", "", "")
	client.SetRemediation("203.0.113.10", cache.Packed(decisionscope.NoBannedValue, 1), 60)
	kind, stored, err := decisionscope.LookupCachedRemediation(client, "203.0.113.10", net.ParseIP("203.0.113.10"), nil, nil)
	if err != nil || kind != decisionscope.NoBannedValue {
		t.Fatalf("kind %q err %v", kind, err)
	}
	if cache.RemediationOrigin(stored) != "" {
		t.Fatalf("none must not format origin, stored %q", stored)
	}
}

func TestRangeUpsertPacksBeforeApply(t *testing.T) {
	store := newTestMemoryDecisionStore()
	client := &Client{
		decisionStore: store,
		cacheClient:   store.Cache(),
		crowdsecMode:  configuration.StreamMode,
		log:           logger.New("ERROR", ""),
	}
	stored := client.remediationStored(decisionscope.BannedValue, "crowdsec")
	if _, packed := stored.PackedWord(); !packed {
		t.Fatal("memory range upsert must pack")
	}
	if err := decisionscope.ApplyRangeBatch(store.Cache(), map[string]string{"10.0.0.0/8": stored.IndexForm()}, nil); err != nil {
		t.Fatal(err)
	}
	index, _ := store.Cache().Get(decisionscope.RangeIndexKey)
	membership := decisionscope.MembershipFromIndex(index)
	got := membership.Remediation(net.ParseIP("10.1.2.3"))
	if cache.RemediationKind(got) != decisionscope.BannedValue {
		t.Fatalf("packed range got %q", got)
	}
	kind, lookupStored, err := decisionscope.LookupCachedRemediation(store.Cache(), "10.1.2.3", net.ParseIP("10.1.2.3"), nil, membership)
	if err != nil || kind != decisionscope.BannedValue {
		t.Fatalf("lookup kind %q err %v stored %q", kind, err, lookupStored)
	}
}

func TestPackedDropSendsOrigin(t *testing.T) {
	store := newTestMemoryDecisionStore()
	client, body := newUsageMetricsClient(t)
	client.decisionStore = store
	client.cacheClient = store.Cache()
	client.metricsReporter.origins = store
	client.storeStreamDecision(Decision{Type: "ban", Scope: "ip", Value: "1.2.3.4", Origin: "crowdsec"}, 60)
	kind, stored, err := decisionscope.LookupCachedRemediation(store.Cache(), "1.2.3.4", net.ParseIP("1.2.3.4"), nil, nil)
	if err != nil || kind != decisionscope.BannedValue {
		t.Fatalf("lookup kind %q err %v", kind, err)
	}
	id, packed := cache.ParsePackedOriginID(stored)
	if !packed {
		t.Fatalf("stored %q", stored)
	}
	client.IncDropped(store.OriginName(id), "ipv4", "ban")
	if err := client.reportMetrics(); err != nil {
		t.Fatal(err)
	}
	found := false
	for _, raw := range usageMetricItems(t, body.bytes()) {
		item := asObject(t, raw)
		if item["name"] != "dropped" {
			continue
		}
		labels := asObject(t, item["labels"])
		if labels["origin"] != "crowdsec" {
			t.Fatalf("dropped labels %#v", labels)
		}
		found = true
	}
	if !found {
		t.Fatal("drop must send origin")
	}
}

func TestLetterOnlyRangeStillRemediates(t *testing.T) {
	membership := decisionscope.MembershipFromIndex("10.0.0.0/8=" + decisionscope.BannedValue)
	cacheClient := &cache.Client{}
	cacheClient.New(logger.New("ERROR", ""), false, "", nil, "", "", "")
	kind, stored, err := decisionscope.LookupCachedRemediation(
		cacheClient,
		"10.1.2.3",
		net.ParseIP("10.1.2.3"),
		nil,
		membership,
	)
	if err != nil || kind != decisionscope.BannedValue || cache.RemediationOrigin(stored) != "" {
		t.Fatalf("letter-only kind %q stored %q err %v", kind, stored, err)
	}
}
