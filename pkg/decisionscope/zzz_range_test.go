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
	AddRange(client, "10.0.0.0/8", CaptchaValue, 60)
	AddRange(client, "10.1.0.0/16", BannedValue, 60)
	if got := remediationFromRangeIndex(client, "10.1.2.3"); got != BannedValue {
		t.Fatalf("got %q, want ban", got)
	}
	if got := remediationFromRangeIndex(client, "11.0.0.1"); got != "" {
		t.Fatalf("outside range got %q", got)
	}
}

func TestRemoveRange(t *testing.T) {
	client := newTestDecisionCache()
	AddRange(client, "192.168.0.0/16", BannedValue, 60)
	RemoveRange(client, "192.168.0.0/16")
	if got := remediationFromRangeIndex(client, "192.168.1.1"); got != "" {
		t.Fatalf("removed range still matched: %q", got)
	}
}

func TestAddRangeUpdatesRemediation(t *testing.T) {
	client := newTestDecisionCache()
	AddRange(client, "10.0.0.0/8", CaptchaValue, 60)
	AddRange(client, "10.0.0.0/8", BannedValue, 60)
	if got := remediationFromRangeIndex(client, "10.1.2.3"); got != BannedValue {
		t.Fatalf("upsert got %q, want ban", got)
	}
}

func TestLookupCachedRemediationHeaderScope(t *testing.T) {
	client := newTestDecisionCache()
	client.Set(HeaderScopeKey(ScopeCountry, "FR"), BannedValue, 60)
	got, _, err := LookupCachedRemediation(client, "203.0.113.10", net.ParseIP("203.0.113.10"), map[string]string{ScopeCountry: "FR"}, nil)
	if err != nil || got != BannedValue {
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
	AddRange(client, "10.0.0.0/8", CaptchaValue, 60)
	client.Set(HeaderScopeKey(ScopeCountry, "FR"), BannedValue, 60)
	index, _ := readRangeIndex(client)
	got, _, err := LookupCachedRemediation(client, "10.1.2.3", net.ParseIP("10.1.2.3"), map[string]string{ScopeCountry: "FR"}, MembershipFromIndex(index))
	if err != nil || got != BannedValue {
		t.Fatalf("range captcha + country ban got %q %v, want ban", got, err)
	}
}

func TestApplyRangeBatchOneWrite(t *testing.T) {
	client := newTestDecisionCache()
	if err := ApplyRangeBatch(client, map[string]string{
		"10.0.0.0/8":  CaptchaValue,
		"10.1.0.0/16": BannedValue,
	}, nil); err != nil {
		t.Fatalf("batch upsert: %v", err)
	}
	if got := remediationFromRangeIndex(client, "10.1.2.3"); got != BannedValue {
		t.Fatalf("batch upsert got %q, want ban", got)
	}
	if err := ApplyRangeBatch(client, nil, []string{"10.1.0.0/16"}); err != nil {
		t.Fatalf("batch removal: %v", err)
	}
	if got := remediationFromRangeIndex(client, "10.1.2.3"); got != CaptchaValue {
		t.Fatalf("after removal got %q, want captcha from remaining /8", got)
	}
}

// TestReadRangeIndexMissIsNotAnError keeps the miss path applying normally: an index that was
// never written is an empty index, not a read that failed.
func TestReadRangeIndexMissIsNotAnError(t *testing.T) {
	index, err := readRangeIndex(newTestDecisionCache())
	if err != nil || index != "" {
		t.Fatalf("missing index got %q err %v, want empty and no error", index, err)
	}
}

func TestLookupCachedRemediationNilMembershipDoesNotReadBlob(t *testing.T) {
	client := newTestDecisionCache()
	AddRange(client, "10.0.0.0/8", BannedValue, 60)
	got, _, err := LookupCachedRemediation(client, "10.1.2.3", net.ParseIP("10.1.2.3"), nil, nil)
	if err == nil || err.Error() != cache.CacheMiss {
		t.Fatalf("nil membership must not read blob, got %q %v", got, err)
	}
}

func TestLookupCachedRemediationStreamUsesMembershipNotBlob(t *testing.T) {
	client := newTestDecisionCache()
	AddRange(client, "10.0.0.0/8", CaptchaValue, 60)
	banOnly := MembershipFromIndex("10.0.0.0/8=" + BannedValue)
	got, _, err := LookupCachedRemediation(client, "10.1.2.3", net.ParseIP("10.1.2.3"), nil, banOnly)
	if err != nil || got != BannedValue {
		t.Fatalf("membership must win over unread blob, got %q %v", got, err)
	}
	_, _, missErr := LookupCachedRemediation(client, "10.1.2.3", net.ParseIP("10.1.2.3"), nil, MembershipFromIndex(""))
	if missErr == nil || missErr.Error() != cache.CacheMiss {
		t.Fatalf("empty membership must not read blob, got %v", missErr)
	}
}

func TestLookupCachedRemediationOriginSuffix(t *testing.T) {
	client := newTestDecisionCache()
	client.Set("203.0.113.10", cache.RemediationWithOrigin(BannedValue, "crowdsec"), 60)
	got, origin, err := LookupCachedRemediation(client, "203.0.113.10", net.ParseIP("203.0.113.10"), nil, nil)
	if err != nil || got != BannedValue || origin != "crowdsec" {
		t.Fatalf("got %q origin %q err %v", got, origin, err)
	}
}

func TestApplyRangeBatchRoundTripOriginSuffix(t *testing.T) {
	client := newTestDecisionCache()
	stored := cache.RemediationWithOrigin(BannedValue, "crowdsec")
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
	stored := cache.RemediationWithOrigin(BannedValue, "crowdsec")
	membership := MembershipFromIndex("10.0.0.0/8=" + stored)
	got, origin, err := LookupCachedRemediation(client, "10.1.2.3", net.ParseIP("10.1.2.3"), nil, membership)
	if err != nil || got != BannedValue || origin != "crowdsec" {
		t.Fatalf("got %q origin %q err %v", got, origin, err)
	}
}

func TestAddRangeBareIPIsHostPrefix(t *testing.T) {
	client := newTestDecisionCache()
	AddRange(client, "192.0.2.1", BannedValue, 60)
	index, err := readRangeIndex(client)
	if err != nil {
		t.Fatalf("read index: %v", err)
	}
	if index != "192.0.2.1/32="+BannedValue {
		t.Fatalf("blob %q", index)
	}
	if got := MembershipFromIndex(index).Remediation(net.ParseIP("192.0.2.1")); got != BannedValue {
		t.Fatalf("bare host got %q", got)
	}
	if got := MembershipFromIndex(index).Remediation(net.ParseIP("192.0.2.2")); got != "" {
		t.Fatalf("neighbor got %q", got)
	}
	RemoveRange(client, "192.0.2.1")
	if got := remediationFromRangeIndex(client, "192.0.2.1"); got != "" {
		t.Fatalf("removed bare host still matched: %q", got)
	}
	AddRange(client, "2001:db8::1", BannedValue, 60)
	ipv6, err := readRangeIndex(client)
	if err != nil {
		t.Fatalf("read ipv6 index: %v", err)
	}
	if ipv6 != "2001:db8::1/128="+BannedValue {
		t.Fatalf("ipv6 blob %q", ipv6)
	}
	if got := MembershipFromIndex(ipv6).Remediation(net.ParseIP("2001:db8::1")); got != BannedValue {
		t.Fatalf("ipv6 bare host got %q", got)
	}
}

func TestMembershipFromIndexLeftoverBareIPDoesNotRemediate(t *testing.T) {
	index := "192.0.2.1=" + BannedValue
	if got := MembershipFromIndex(index).Remediation(net.ParseIP("192.0.2.1")); got != "" {
		t.Fatalf("leftover bare line remediates: %q", got)
	}
}

func TestLookupCachedRemediationRangeLetterOnlyStillBans(t *testing.T) {
	client := newTestDecisionCache()
	membership := MembershipFromIndex("10.0.0.0/8=" + BannedValue)
	got, origin, err := LookupCachedRemediation(client, "10.1.2.3", net.ParseIP("10.1.2.3"), nil, membership)
	if err != nil || got != BannedValue || origin != "" {
		t.Fatalf("letter-only got %q origin %q err %v", got, origin, err)
	}
}
