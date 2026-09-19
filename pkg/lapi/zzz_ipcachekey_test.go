package lapi

import (
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sync/atomic"
	"testing"

	cache "github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pkg/cache"
	"github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pkg/configuration"
	"github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pkg/decisionscope"
	logger "github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pkg/logger"
)

// Spellings of one address. CrowdSec was measured to store a decision value verbatim, so all of
// these reach the stream, and any of them can be what the forwarded header carries.
const (
	compressedV6 = "2001:db8::1"
	expandedV6   = "2001:0db8:0000:0000:0000:0000:0000:0001"
	upperV6      = "2001:DB8::1"
	hostPrefixV6 = "2001:db8::1/128"
	mappedV4     = "::ffff:192.0.2.4"
	bareV4       = "192.0.2.4"
)

// lookupAsRequest reads the decision cache the way ServeHTTP does after a successful parse:
// remoteIP is already ipAddr.String().
func lookupAsRequest(client *Client, remoteIP string) (string, error) {
	ipAddr := net.ParseIP(remoteIP)
	if ipAddr != nil {
		remoteIP = ipAddr.String()
	}
	if client.crowdsecMode == configuration.StreamMode || client.crowdsecMode == configuration.AloneMode {
		value, _, _, err := client.LookupStreamRemediation(remoteIP, ipAddr, nil)
		return value, err
	}
	value, _, _, err := decisionscope.LookupCachedRemediation(client.Cache(), remoteIP, ipAddr, nil, nil)
	return value, err
}

func applyStreamDecisionForTest(client *Client, decision Decision, duration int64) {
	client.decisionStore.beginStreamTick()
	client.storeStreamDecision(decision, duration)
	client.decisionStore.publishStreamTick()
}

func deleteStreamDecisionForTest(client *Client, decision Decision) {
	client.decisionStore.beginStreamTick()
	client.deleteStreamDecision(decision)
	client.decisionStore.publishStreamTick()
}

// TestStoreStreamDecision_SpellingsShareOneCacheSlot is the Ip-scope half of the defect: a ban the
// stream wrote under one spelling of an address has to be found by a request that spells it
// another way. Store side and request side must agree on the key, in both directions.
func TestStoreStreamDecision_SpellingsShareOneCacheSlot(t *testing.T) {
	tests := []struct {
		name          string
		decisionValue string
		remoteIP      string
	}{
		{"expanded stored, compressed requested", expandedV6, compressedV6},
		{"compressed stored, expanded requested", compressedV6, expandedV6},
		{"upper-case stored, lower-case requested", upperV6, compressedV6},
		{"host prefix stored, bare requested", hostPrefixV6, compressedV6},
		{"IPv4-mapped stored, dotted requested", mappedV4, bareV4},
		{"dotted stored, IPv4-mapped requested", bareV4, mappedV4},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			client, _ := newTestRangeClient(t)
			applyStreamDecisionForTest(client, Decision{
				Origin: "crowdsec", Type: "ban", Scope: "Ip", Value: tt.decisionValue, Duration: "1h",
			}, 3600)
			got, err := lookupAsRequest(client, tt.remoteIP)
			if err != nil || got != decisionscope.BannedValue {
				t.Fatalf("stored %q, requested %q: got %q err %v, want ban", tt.decisionValue, tt.remoteIP, got, err)
			}
		})
	}
}

// TestDeleteStreamDecision_ClearsTheSlotAnySpelling proves the delete side moved with the store
// side: a lifted ban must not survive under a key the store can no longer reach.
func TestDeleteStreamDecision_ClearsTheSlotAnySpelling(t *testing.T) {
	client, _ := newTestRangeClient(t)
	applyStreamDecisionForTest(client, Decision{
		Origin: "crowdsec", Type: "ban", Scope: "Ip", Value: expandedV6, Duration: "1h",
	}, 3600)
	deleteStreamDecisionForTest(client, Decision{Scope: "Ip", Value: upperV6})
	if got, err := lookupAsRequest(client, compressedV6); err == nil {
		t.Fatalf("lifted ban still enforced as %q", got)
	}
}

// TestStoreStreamDecision_HeaderScopesAreNotAddresses guards the other half of the contract: a
// Country or AS value must never be pushed through IP parsing.
func TestStoreStreamDecision_HeaderScopesAreNotAddresses(t *testing.T) {
	client, cacheClient := newTestRangeClient(t)
	client.decisionScopeHeaders = map[string]string{decisionscope.ScopeCountry: "CF-IPCountry"}
	applyStreamDecisionForTest(client, Decision{
		Origin: "crowdsec", Type: "ban", Scope: "Country", Value: "fr", Duration: "1h",
	}, 3600)
	key := decisionscope.HeaderScopeKey(decisionscope.ScopeCountry, "FR")
	if _, ok := client.decisionStore.streamMapForTest()[key]; !ok {
		t.Fatal("Country ban must live-map on normalized country code")
	}
	if _, err := cacheClient.Get(key); err == nil {
		t.Fatal("Country ban must not duplicate on TTL heap")
	}
}

// countingLiveLAPI answers every live query with body and counts the queries.
func countingLiveLAPI(t *testing.T, body string) (*httptest.Server, *int64) {
	t.Helper()
	var hits int64
	server := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, _ *http.Request) {
		atomic.AddInt64(&hits, 1)
		if _, err := rw.Write([]byte(body)); err != nil {
			t.Errorf("live LAPI stub write: %v", err)
		}
	}))
	t.Cleanup(server.Close)
	return server, &hits
}

// liveRequests replays the bouncer's live-mode sequence for each address in order: read the
// decision cache first, and only query LAPI when that read misses. The return is how many LAPI
// queries the run needed, which is the number the live-mode memo exists to keep at one.
func liveRequests(t *testing.T, addresses []string) int64 {
	t.Helper()
	server, hits := countingLiveLAPI(t, "null")
	client := newTestLiveClient(t, server)
	for _, address := range addresses {
		canonical := address
		if ipAddr := net.ParseIP(address); ipAddr != nil {
			canonical = ipAddr.String()
		}
		if _, err := lookupAsRequest(client, canonical); err == nil {
			continue
		}
		if _, err := client.LiveLookup(canonical, nil, 60); err != nil {
			t.Fatalf("live lookup %q: %v", address, err)
		}
	}
	return atomic.LoadInt64(hits)
}

// TestLiveLookup_MemoHitsOnRepeatedRequests is the regression guard the ticket asks for. A patch
// that canonicalizes the read side and leaves the write side writing the header text verbatim
// still passes for an address the header already spells canonically, so the spellings that do not
// round-trip are the ones under test: under that shape every one of these requests is a memo miss
// and a fresh LAPI query, which is worse than the defect being fixed.
func TestLiveLookup_MemoHitsOnRepeatedRequests(t *testing.T) {
	for _, spelling := range []string{compressedV6, upperV6, expandedV6, mappedV4, bareV4} {
		t.Run(spelling, func(t *testing.T) {
			repeated := []string{spelling, spelling, spelling, spelling, spelling}
			if got := liveRequests(t, repeated); got != 1 {
				t.Fatalf("5 requests spelled %q needed %d LAPI queries, want 1", spelling, got)
			}
		})
	}
}

// TestLiveLookup_MemoHitsAcrossSpellings is the defect itself on the live path: the memo is one
// address, so a second spelling of it must not pay for a second LAPI query.
func TestLiveLookup_MemoHitsAcrossSpellings(t *testing.T) {
	spellings := []string{compressedV6, expandedV6, upperV6, "2001:db8:0:0:0:0:0:1"}
	if got := liveRequests(t, spellings); got != 1 {
		t.Fatalf("4 spellings of one address needed %d LAPI queries, want 1", got)
	}
}

// splitCacheOnDeadReader builds the production shape that reaches the range-index defect with no
// timing window at all: writes and the stream lease go to a healthy writer, reads round-robin onto
// a read replica that is down. Returns the client and the writer's view of the stored keys.
func splitCacheOnDeadReader(t *testing.T) (*cache.Client, *testLeaseRedis) {
	t.Helper()
	writer := startTestLeaseRedis(t)
	client := &cache.Client{}
	client.New(logger.New("ERROR", ""), true, writer.addr(), []string{"127.0.0.1:1"}, "", "", "sess")
	t.Cleanup(client.Close)
	return client, writer
}

// TestApplyRangeBatch_UnreachableReadKeepsSharedIndex is the range half of the defect. The index is
// shared by every bouncer on this cache; rebuilding it from a read that never answered writes back
// only what this one poll carried and silently drops every other Range ban.
func TestApplyRangeBatch_UnreachableReadKeepsSharedIndex(t *testing.T) {
	client, writer := splitCacheOnDeadReader(t)
	client.Set(decisionscope.RangeIndexKey, "10.0.0.0/8="+decisionscope.BannedValue, 3600)

	err := decisionscope.ApplyRangeBatch(client, map[string]string{"192.168.0.0/16": decisionscope.BannedValue}, nil)
	if err == nil || !errors.Is(err, cache.ErrUnreachable) {
		t.Errorf("apply on an unreadable index returned %v, want ErrUnreachable", err)
	}
	stored, ok := writer.value("sess:" + decisionscope.RangeIndexKey)
	if !ok || stored != "10.0.0.0/8="+decisionscope.BannedValue {
		t.Fatalf("shared range index is now %q (present:%v); the other bouncers' Range bans were dropped", stored, ok)
	}
}

// TestApplyRangeBatch_UnreachableReadDoesNotDeleteIndex is the same defect on the removal path,
// where an empty rebuilt index deletes the shared key outright.
func TestApplyRangeBatch_UnreachableReadDoesNotDeleteIndex(t *testing.T) {
	client, writer := splitCacheOnDeadReader(t)
	client.Set(decisionscope.RangeIndexKey, "10.0.0.0/8="+decisionscope.BannedValue, 3600)

	if err := decisionscope.ApplyRangeBatch(client, nil, []string{"172.16.0.0/12"}); err == nil {
		t.Error("removal on an unreadable index must return an error")
	}
	if _, ok := writer.value("sess:" + decisionscope.RangeIndexKey); !ok {
		t.Fatal("the shared range index was deleted")
	}
}

// TestHandleStreamCache_RangeApplyFailureReleasesLease proves the poll is reported as failed, not
// as a clean tick that happened to skip the write. Releasing the lease is what lets the next tick
// retry, and the failed tick leaves isCrowdsecStreamStartup set so the retry asks for the full set.
func TestHandleStreamCache_RangeApplyFailureReleasesLease(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, _ *http.Request) {
		if _, err := rw.Write([]byte(`{"new":[{"id":1,"origin":"crowdsec","type":"ban","scope":"Range","value":"192.168.0.0/16","duration":"1h","scenario":"test"}],"deleted":[]}`)); err != nil {
			t.Errorf("stream stub write: %v", err)
		}
	}))
	t.Cleanup(server.Close)
	parsed, err := url.Parse(server.URL)
	if err != nil {
		t.Fatal(err)
	}
	client, writer := splitCacheOnDeadReader(t)
	client.Set(decisionscope.RangeIndexKey, "10.0.0.0/8="+decisionscope.BannedValue, 3600)
	poller := newSharedStreamPoller(t, client, parsed.Host)
	atomic.StoreInt64(&poller.isCrowdsecStreamStartup, 1)
	attachTestTransport(poller, server.Client(), "test-key")

	if pollErr := poller.handleStreamCache(); pollErr == nil {
		t.Fatal("a poll that could not apply its Range delta must report the failure")
	}
	if _, ok := writer.value("sess:" + cacheTimeoutKey); ok {
		t.Fatal("a failed poll must release the stream lease so the next tick retries")
	}
	if atomic.LoadInt64(&poller.isCrowdsecStreamStartup) == 0 {
		t.Fatal("a failed poll must stay in startup so the retry asks for the full decision set")
	}
}
