package lapi

import (
	"net"
	"testing"

	cache "github.com/maxlerebourg/crowdsec-bouncer-traefik-plugin/pkg/cache"
	"github.com/maxlerebourg/crowdsec-bouncer-traefik-plugin/pkg/decisionscope"
	logger "github.com/maxlerebourg/crowdsec-bouncer-traefik-plugin/pkg/logger"
)

func newTestRangeClient(t *testing.T) (*Client, *cache.Client) {
	t.Helper()
	cacheClient := &cache.Client{}
	cacheClient.New(logger.New("ERROR", ""), false, "", nil, "", "", "")
	return &Client{cacheClient: cacheClient, log: logger.New("ERROR", "")}, cacheClient
}

func TestHydrateRangeMembershipFromBlob(t *testing.T) {
	lapiClient, cacheClient := newTestRangeClient(t)
	decisionscope.AddRange(cacheClient, "10.0.0.0/8", decisionscope.BannedValue, 60)
	lapiClient.hydrateRangeMembership()
	if got := lapiClient.RangeMembership().Remediation(net.ParseIP("10.1.2.3")); got != decisionscope.BannedValue {
		t.Fatalf("hydrate got %q, want ban", got)
	}
}

func TestHydrateRangeMembershipEmptyBlob(t *testing.T) {
	lapiClient, cacheClient := newTestRangeClient(t)
	decisionscope.AddRange(cacheClient, "10.0.0.0/8", decisionscope.BannedValue, 60)
	lapiClient.hydrateRangeMembership()
	cacheClient.Delete(decisionscope.RangeIndexKey)
	lapiClient.hydrateRangeMembership()
	if got := lapiClient.RangeMembership().Remediation(net.ParseIP("10.1.2.3")); got != "" {
		t.Fatalf("empty blob should miss, got %q", got)
	}
}

func TestHydrateRangeMembershipKeepsLastOnUnreachable(t *testing.T) {
	lapiClient, cacheClient := newTestRangeClient(t)
	decisionscope.AddRange(cacheClient, "10.0.0.0/8", decisionscope.BannedValue, 60)
	lapiClient.hydrateRangeMembership()

	unreachable := &cache.Client{}
	unreachable.New(logger.New("ERROR", ""), true, "127.0.0.1:1", nil, "", "", "p")
	defer unreachable.Close()
	lapiClient.cacheClient = unreachable
	lapiClient.hydrateRangeMembership()
	if got := lapiClient.RangeMembership().Remediation(net.ParseIP("10.1.2.3")); got != decisionscope.BannedValue {
		t.Fatalf("unreachable hydrate wiped membership, got %q", got)
	}
}

func TestHandleStreamCacheLeaseHitHydrates(t *testing.T) {
	lapiClient, cacheClient := newTestRangeClient(t)
	cacheClient.Set(cacheTimeoutKey, decisionscope.NoBannedValue, 60)
	decisionscope.AddRange(cacheClient, "10.0.0.0/8", decisionscope.BannedValue, 60)
	if err := lapiClient.handleStreamCache(); err != nil {
		t.Fatalf("lease hit: %v", err)
	}
	if got := lapiClient.RangeMembership().Remediation(net.ParseIP("10.1.2.3")); got != decisionscope.BannedValue {
		t.Fatalf("lease hit hydrate got %q, want ban", got)
	}
}
