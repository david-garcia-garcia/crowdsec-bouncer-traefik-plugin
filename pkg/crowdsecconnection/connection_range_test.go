package crowdsecconnection

import (
	"testing"

	cache "github.com/maxlerebourg/crowdsec-bouncer-traefik-plugin/pkg/cache"
	"github.com/maxlerebourg/crowdsec-bouncer-traefik-plugin/pkg/decisionscope"
	logger "github.com/maxlerebourg/crowdsec-bouncer-traefik-plugin/pkg/logger"
)

func newTestRangeConn(t *testing.T) (*CrowdsecConnection, *cache.Client) {
	t.Helper()
	client := &cache.Client{}
	client.New(logger.New("ERROR", ""), false, "", nil, "", "", "")
	return &CrowdsecConnection{cacheClient: client, log: logger.New("ERROR", "")}, client
}

func TestHydrateRangeMembershipFromBlob(t *testing.T) {
	conn, client := newTestRangeConn(t)
	decisionscope.AddRange(client, "10.0.0.0/8", cache.BannedValue, 60)
	conn.hydrateRangeMembership()
	if got := conn.RangeMembership().Remediation("10.1.2.3"); got != cache.BannedValue {
		t.Fatalf("hydrate got %q, want ban", got)
	}
}

func TestHydrateRangeMembershipEmptyBlob(t *testing.T) {
	conn, client := newTestRangeConn(t)
	decisionscope.AddRange(client, "10.0.0.0/8", cache.BannedValue, 60)
	conn.hydrateRangeMembership()
	client.Delete(decisionscope.RangeIndexKey)
	conn.hydrateRangeMembership()
	if got := conn.RangeMembership().Remediation("10.1.2.3"); got != "" {
		t.Fatalf("empty blob should miss, got %q", got)
	}
}

func TestHydrateRangeMembershipKeepsLastOnUnreachable(t *testing.T) {
	conn, client := newTestRangeConn(t)
	decisionscope.AddRange(client, "10.0.0.0/8", cache.BannedValue, 60)
	conn.hydrateRangeMembership()

	unreachable := &cache.Client{}
	unreachable.New(logger.New("ERROR", ""), true, "127.0.0.1:1", nil, "", "", "p")
	defer unreachable.Close()
	conn.cacheClient = unreachable
	conn.hydrateRangeMembership()
	if got := conn.RangeMembership().Remediation("10.1.2.3"); got != cache.BannedValue {
		t.Fatalf("unreachable hydrate wiped membership, got %q", got)
	}
}

func TestHandleStreamCacheLeaseHitHydrates(t *testing.T) {
	conn, client := newTestRangeConn(t)
	client.Set(cacheTimeoutKey, cache.NoBannedValue, 60)
	decisionscope.AddRange(client, "10.0.0.0/8", cache.BannedValue, 60)
	if err := conn.handleStreamCache(); err != nil {
		t.Fatalf("lease hit: %v", err)
	}
	if got := conn.RangeMembership().Remediation("10.1.2.3"); got != cache.BannedValue {
		t.Fatalf("lease hit hydrate got %q, want ban", got)
	}
}
