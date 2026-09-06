package decisionscope

import (
	"net"
	"testing"

	cache "github.com/maxlerebourg/crowdsec-bouncer-traefik-plugin/pkg/cache"
	logger "github.com/maxlerebourg/crowdsec-bouncer-traefik-plugin/pkg/logger"
)

func newTestDecisionCache() *cache.Client {
	client := &cache.Client{}
	client.New(logger.New("ERROR", ""), false, "", nil, "", "", "")
	return client
}

func remediationFromRangeIndex(client *cache.Client, remoteIP string) string {
	index, _ := readRangeIndex(client)
	return MembershipFromIndex(index).Remediation(net.ParseIP(remoteIP))
}

func TestAddRangeBanWins(t *testing.T) {
	client := newTestDecisionCache()
	AddRange(client, "10.0.0.0/8", cache.CaptchaValue, 60)
	AddRange(client, "10.1.0.0/16", cache.BannedValue, 60)
	if got := remediationFromRangeIndex(client, "10.1.2.3"); got != cache.BannedValue {
		t.Fatalf("got %q, want ban", got)
	}
	if got := remediationFromRangeIndex(client, "11.0.0.1"); got != "" {
		t.Fatalf("outside range got %q", got)
	}
}

func TestRemoveRange(t *testing.T) {
	client := newTestDecisionCache()
	AddRange(client, "192.168.0.0/16", cache.BannedValue, 60)
	RemoveRange(client, "192.168.0.0/16")
	if got := remediationFromRangeIndex(client, "192.168.1.1"); got != "" {
		t.Fatalf("removed range still matched: %q", got)
	}
}

func TestAddRangeUpdatesRemediation(t *testing.T) {
	client := newTestDecisionCache()
	AddRange(client, "10.0.0.0/8", cache.CaptchaValue, 60)
	AddRange(client, "10.0.0.0/8", cache.BannedValue, 60)
	if got := remediationFromRangeIndex(client, "10.1.2.3"); got != cache.BannedValue {
		t.Fatalf("upsert got %q, want ban", got)
	}
}

func TestLookupCachedRemediationHeaderScope(t *testing.T) {
	client := newTestDecisionCache()
	client.Set(HeaderScopeKey(ScopeCountry, "FR"), cache.BannedValue, 60)
	got, _, err := LookupCachedRemediation(client, "203.0.113.10", net.ParseIP("203.0.113.10"), map[string]string{ScopeCountry: "FR"}, nil)
	if err != nil || got != cache.BannedValue {
		t.Fatalf("got %q %v, want ban", got, err)
	}
}

func TestLookupCachedRemediationMiss(t *testing.T) {
	client := newTestDecisionCache()
	_, _, err := LookupCachedRemediation(client, "203.0.113.10", net.ParseIP("203.0.113.10"), nil, nil)
	if err == nil || err.Error() != cache.CacheMiss {
		t.Fatalf("want cache miss, got %v", err)
	}
}

func TestLookupCachedRemediationBanWinsAcrossScopes(t *testing.T) {
	client := newTestDecisionCache()
	AddRange(client, "10.0.0.0/8", cache.CaptchaValue, 60)
	client.Set(HeaderScopeKey(ScopeCountry, "FR"), cache.BannedValue, 60)
	index, _ := readRangeIndex(client)
	got, _, err := LookupCachedRemediation(client, "10.1.2.3", net.ParseIP("10.1.2.3"), map[string]string{ScopeCountry: "FR"}, MembershipFromIndex(index))
	if err != nil || got != cache.BannedValue {
		t.Fatalf("range captcha + country ban got %q %v, want ban", got, err)
	}
}

func TestApplyRangeBatchOneWrite(t *testing.T) {
	client := newTestDecisionCache()
	if err := ApplyRangeBatch(client, map[string]string{
		"10.0.0.0/8":  cache.CaptchaValue,
		"10.1.0.0/16": cache.BannedValue,
	}, nil); err != nil {
		t.Fatalf("batch upsert: %v", err)
	}
	if got := remediationFromRangeIndex(client, "10.1.2.3"); got != cache.BannedValue {
		t.Fatalf("batch upsert got %q, want ban", got)
	}
	if err := ApplyRangeBatch(client, nil, []string{"10.1.0.0/16"}); err != nil {
		t.Fatalf("batch removal: %v", err)
	}
	if got := remediationFromRangeIndex(client, "10.1.2.3"); got != cache.CaptchaValue {
		t.Fatalf("after removal got %q, want captcha from remaining /8", got)
	}
}

func TestLookupCachedRemediationNilMembershipDoesNotReadBlob(t *testing.T) {
	client := newTestDecisionCache()
	AddRange(client, "10.0.0.0/8", cache.BannedValue, 60)
	got, _, err := LookupCachedRemediation(client, "10.1.2.3", net.ParseIP("10.1.2.3"), nil, nil)
	if err == nil || err.Error() != cache.CacheMiss {
		t.Fatalf("nil membership must not read blob, got %q %v", got, err)
	}
}

func TestLookupCachedRemediationStreamUsesMembershipNotBlob(t *testing.T) {
	client := newTestDecisionCache()
	AddRange(client, "10.0.0.0/8", cache.CaptchaValue, 60)
	banOnly := MembershipFromIndex("10.0.0.0/8=" + cache.BannedValue)
	got, _, err := LookupCachedRemediation(client, "10.1.2.3", net.ParseIP("10.1.2.3"), nil, banOnly)
	if err != nil || got != cache.BannedValue {
		t.Fatalf("membership must win over unread blob, got %q %v", got, err)
	}
	_, _, missErr := LookupCachedRemediation(client, "10.1.2.3", net.ParseIP("10.1.2.3"), nil, MembershipFromIndex(""))
	if missErr == nil || missErr.Error() != cache.CacheMiss {
		t.Fatalf("empty membership must not read blob, got %v", missErr)
	}
}

func TestLookupCachedRemediationOriginSuffix(t *testing.T) {
	client := newTestDecisionCache()
	client.Set("203.0.113.10", cache.RemediationWithOrigin(cache.BannedValue, "crowdsec"), 60)
	got, origin, err := LookupCachedRemediation(client, "203.0.113.10", net.ParseIP("203.0.113.10"), nil, nil)
	if err != nil || got != cache.BannedValue || origin != "crowdsec" {
		t.Fatalf("got %q origin %q err %v", got, origin, err)
	}
}

func TestApplyRangeBatchRoundTripOriginSuffix(t *testing.T) {
	client := newTestDecisionCache()
	stored := cache.RemediationWithOrigin(cache.BannedValue, "crowdsec")
	if err := ApplyRangeBatch(client, map[string]string{"10.0.0.0/8": stored}, nil); err != nil {
		t.Fatalf("round-trip apply: %v", err)
	}
	index, _ := readRangeIndex(client)
	if index != "10.0.0.0/8="+stored {
		t.Fatalf("blob %q", index)
	}
	if got := MembershipFromIndex(index).Remediation(net.ParseIP("10.1.2.3")); got != stored {
		t.Fatalf("round-trip got %q", got)
	}
}

func TestLookupCachedRemediationRangeOnlyOrigin(t *testing.T) {
	client := newTestDecisionCache()
	stored := cache.RemediationWithOrigin(cache.BannedValue, "crowdsec")
	membership := MembershipFromIndex("10.0.0.0/8=" + stored)
	got, origin, err := LookupCachedRemediation(client, "10.1.2.3", net.ParseIP("10.1.2.3"), nil, membership)
	if err != nil || got != cache.BannedValue || origin != "crowdsec" {
		t.Fatalf("got %q origin %q err %v", got, origin, err)
	}
}

func TestLookupCachedRemediationExpandedIPv6(t *testing.T) {
	client := newTestDecisionCache()
	storeKey := IPCacheKey("2001:db8::1/128")
	client.Set(storeKey, cache.BannedValue, 60)
	expanded := "2001:db8:0:0:0:0:0:1"
	ipAddr := net.ParseIP(expanded)
	got, _, err := LookupCachedRemediation(client, expanded, ipAddr, nil, nil)
	if err != nil || got != cache.BannedValue {
		t.Fatalf("expanded IPv6 got %q err %v, want ban", got, err)
	}
}

func TestLookupCachedRemediationIPv4Mapped(t *testing.T) {
	client := newTestDecisionCache()
	storeKey := IPCacheKey("203.0.113.10/32")
	client.Set(storeKey, cache.BannedValue, 60)
	mapped := "::ffff:203.0.113.10"
	ipAddr := net.ParseIP(mapped)
	got, _, err := LookupCachedRemediation(client, mapped, ipAddr, nil, nil)
	if err != nil || got != cache.BannedValue {
		t.Fatalf("IPv4-mapped got %q err %v, want ban", got, err)
	}
}

func TestApplyRangeBatchAbortOnUnreachableRead(t *testing.T) {
	client := newTestDecisionCache()
	AddRange(client, "10.0.0.0/8", cache.BannedValue, 60)

	unreachable := &cache.Client{}
	unreachable.New(logger.New("ERROR", ""), true, "127.0.0.1:1", nil, "", "", "p")
	defer unreachable.Close()

	err := ApplyRangeBatch(unreachable, map[string]string{"192.168.0.0/16": cache.BannedValue}, nil)
	if err == nil || err.Error() != cache.CacheUnreachable {
		t.Fatalf("want %s, got %v", cache.CacheUnreachable, err)
	}
	if got := remediationFromRangeIndex(client, "10.1.2.3"); got != cache.BannedValue {
		t.Fatalf("healthy index should be unchanged, got %q", got)
	}
}

func TestApplyRangeBatchCacheMissStillApplies(t *testing.T) {
	client := newTestDecisionCache()
	if err := ApplyRangeBatch(client, map[string]string{"10.0.0.0/8": cache.BannedValue}, nil); err != nil {
		t.Fatalf("miss apply: %v", err)
	}
	if got := remediationFromRangeIndex(client, "10.1.2.3"); got != cache.BannedValue {
		t.Fatalf("got %q, want ban", got)
	}
}
func TestLookupCachedRemediationRangeLetterOnlyStillBans(t *testing.T) {
	client := newTestDecisionCache()
	membership := MembershipFromIndex("10.0.0.0/8=" + cache.BannedValue)
	got, origin, err := LookupCachedRemediation(client, "10.1.2.3", net.ParseIP("10.1.2.3"), nil, membership)
	if err != nil || got != cache.BannedValue || origin != "" {
		t.Fatalf("letter-only got %q origin %q err %v", got, origin, err)
	}
}
