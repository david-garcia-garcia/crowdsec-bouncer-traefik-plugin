package decisionscope

import (
	"errors"
	"net"
	"testing"

	cache "github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pkg/cache"
	logger "github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pkg/logger"
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

// TestRemoveRangeSameNetworkDifferentSpelling drops AddRange(10.1.2.0/8) when RemoveRange uses 10.0.0.0/8.
func TestRemoveRangeSameNetworkDifferentSpelling(t *testing.T) {
	client := newTestDecisionCache()
	AddRange(client, "10.1.2.0/8", BannedValue, 60)
	RemoveRange(client, "10.0.0.0/8")
	if got := remediationFromRangeIndex(client, "10.1.2.3"); got != "" {
		t.Fatalf("same-network remove still matched: %q", got)
	}
}

// TestRemoveRangeUnparseableIdenticalText drops a garbage CIDR line when remove uses that same text.
func TestRemoveRangeUnparseableIdenticalText(t *testing.T) {
	client := newTestDecisionCache()
	if err := ApplyRangeBatch(client, map[string]string{"not-a-cidr": BannedValue}, nil); err != nil {
		t.Fatalf("seed unparseable: %v", err)
	}
	RemoveRange(client, "not-a-cidr")
	index, err := readRangeIndex(client)
	if err != nil || index != "" {
		t.Fatalf("identical unparseable remove left %q err %v", index, err)
	}
}

// TestRemoveRangeParseableVsUnparseableKeepsLine leaves 10.0.0.0/8 when remove uses different garbage text.
func TestRemoveRangeParseableVsUnparseableKeepsLine(t *testing.T) {
	client := newTestDecisionCache()
	AddRange(client, "10.0.0.0/8", BannedValue, 60)
	RemoveRange(client, "not-a-cidr")
	if got := remediationFromRangeIndex(client, "10.1.2.3"); got != BannedValue {
		t.Fatalf("unparseable remove dropped parseable line: %q", got)
	}
}

// TestAddRangeSameNetworkPersistsIncomingSpelling replaces 10.1.2.0/8 with the incoming 10.0.0.0/8 text.
func TestAddRangeSameNetworkPersistsIncomingSpelling(t *testing.T) {
	client := newTestDecisionCache()
	AddRange(client, "10.1.2.0/8", CaptchaValue, 60)
	AddRange(client, "10.0.0.0/8", BannedValue, 60)
	index, err := readRangeIndex(client)
	want := "10.0.0.0/8=" + BannedValue
	if err != nil || index != want {
		t.Fatalf("same-network upsert persisted %q err %v, want %q", index, err, want)
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
	got, _, _, err := LookupCachedRemediation(client, "203.0.113.10", net.ParseIP("203.0.113.10"), map[string]string{ScopeCountry: "FR"}, nil)
	if err != nil || got != BannedValue {
		t.Fatalf("got %q %v, want ban", got, err)
	}
}

func TestLookupCachedRemediationMiss(t *testing.T) {
	client := newTestDecisionCache()
	_, origin, originID, err := LookupCachedRemediation(client, "203.0.113.10", net.ParseIP("203.0.113.10"), nil, nil)
	if origin != "" || originID != 0 {
		t.Fatalf("miss origin %q id %d", origin, originID)
	}
	if err == nil || !errors.Is(err, cache.ErrMiss) {
		t.Fatalf("want cache miss, got %v", err)
	}
}

func TestLookupCachedRemediationBanWinsAcrossScopes(t *testing.T) {
	client := newTestDecisionCache()
	AddRange(client, "10.0.0.0/8", CaptchaValue, 60)
	client.Set(HeaderScopeKey(ScopeCountry, "FR"), BannedValue, 60)
	index, _ := readRangeIndex(client)
	got, _, _, err := LookupCachedRemediation(client, "10.1.2.3", net.ParseIP("10.1.2.3"), map[string]string{ScopeCountry: "FR"}, MembershipFromIndex(index))
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
	got, _, _, err := LookupCachedRemediation(client, "10.1.2.3", net.ParseIP("10.1.2.3"), nil, nil)
	if err == nil || !errors.Is(err, cache.ErrMiss) {
		t.Fatalf("nil membership must not read blob, got %q %v", got, err)
	}
}

func TestLookupCachedRemediationStreamUsesMembershipNotBlob(t *testing.T) {
	client := newTestDecisionCache()
	AddRange(client, "10.0.0.0/8", CaptchaValue, 60)
	banOnly := MembershipFromIndex("10.0.0.0/8=" + BannedValue)
	got, _, _, err := LookupCachedRemediation(client, "10.1.2.3", net.ParseIP("10.1.2.3"), nil, banOnly)
	if err != nil || got != BannedValue {
		t.Fatalf("membership must win over unread blob, got %q %v", got, err)
	}
	_, origin, originID, missErr := LookupCachedRemediation(client, "10.1.2.3", net.ParseIP("10.1.2.3"), nil, MembershipFromIndex(""))
	if missErr == nil || !errors.Is(missErr, cache.ErrMiss) || origin != "" || originID != 0 {
		t.Fatalf("empty membership must not read blob, got %v origin %q id %d", missErr, origin, originID)
	}
}

func TestLookupCachedRemediationPackedWord(t *testing.T) {
	client := newTestDecisionCache()
	client.Set("203.0.113.10", packWord(BannedValue, 3), 60)
	got, origin, originID, err := LookupCachedRemediation(client, "203.0.113.10", net.ParseIP("203.0.113.10"), nil, nil)
	if err != nil || got != BannedValue || origin != "" || originID != 3 {
		t.Fatalf("got %q origin %q id %d err %v", got, origin, originID, err)
	}
}

func TestLookupCachedRemediationOriginSuffix(t *testing.T) {
	client := newTestDecisionCache()
	client.Set("203.0.113.10", RemediationWithOrigin(BannedValue, "crowdsec"), 60)
	got, origin, _, err := LookupCachedRemediation(client, "203.0.113.10", net.ParseIP("203.0.113.10"), nil, nil)
	if err != nil || got != BannedValue || origin != "crowdsec" {
		t.Fatalf("got %q origin %q err %v", got, origin, err)
	}
}

func TestApplyRangeBatchRoundTripOriginSuffix(t *testing.T) {
	client := newTestDecisionCache()
	stored := RemediationWithOrigin(BannedValue, "crowdsec")
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
	stored := RemediationWithOrigin(BannedValue, "crowdsec")
	membership := MembershipFromIndex("10.0.0.0/8=" + stored)
	got, origin, _, err := LookupCachedRemediation(client, "10.1.2.3", net.ParseIP("10.1.2.3"), nil, membership)
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
	got, origin, _, err := LookupCachedRemediation(client, "10.1.2.3", net.ParseIP("10.1.2.3"), nil, membership)
	if err != nil || got != BannedValue || origin != "" {
		t.Fatalf("letter-only got %q origin %q err %v", got, origin, err)
	}
}
