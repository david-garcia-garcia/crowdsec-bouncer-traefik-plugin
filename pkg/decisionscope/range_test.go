package decisionscope

import (
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
	return MembershipFromIndex(readRangeIndex(client)).Remediation(remoteIP)
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
	got, err := LookupCachedRemediation(client, "stream", "203.0.113.10", map[string]string{ScopeCountry: "FR"}, nil)
	if err != nil || got != BannedValue {
		t.Fatalf("got %q %v, want ban", got, err)
	}
}

func TestLookupCachedRemediationMiss(t *testing.T) {
	client := newTestDecisionCache()
	_, err := LookupCachedRemediation(client, "stream", "203.0.113.10", nil, nil)
	if err == nil || err.Error() != cache.CacheMiss {
		t.Fatalf("want cache miss, got %v", err)
	}
}

func TestLookupCachedRemediationBanWinsAcrossScopes(t *testing.T) {
	client := newTestDecisionCache()
	AddRange(client, "10.0.0.0/8", CaptchaValue, 60)
	client.Set(HeaderScopeKey(ScopeCountry, "FR"), BannedValue, 60)
	got, err := LookupCachedRemediation(client, "stream", "10.1.2.3", map[string]string{ScopeCountry: "FR"}, MembershipFromIndex(readRangeIndex(client)))
	if err != nil || got != BannedValue {
		t.Fatalf("range captcha + country ban got %q %v, want ban", got, err)
	}
}

func TestApplyRangeBatchOneWrite(t *testing.T) {
	client := newTestDecisionCache()
	ApplyRangeBatch(client, map[string]string{
		"10.0.0.0/8":  CaptchaValue,
		"10.1.0.0/16": BannedValue,
	}, nil)
	if got := remediationFromRangeIndex(client, "10.1.2.3"); got != BannedValue {
		t.Fatalf("batch upsert got %q, want ban", got)
	}
	ApplyRangeBatch(client, nil, []string{"10.1.0.0/16"})
	if got := remediationFromRangeIndex(client, "10.1.2.3"); got != CaptchaValue {
		t.Fatalf("after removal got %q, want captcha from remaining /8", got)
	}
}

func TestLookupCachedRemediationNoneSkipsRangeIndex(t *testing.T) {
	client := newTestDecisionCache()
	AddRange(client, "10.0.0.0/8", BannedValue, 60)
	got, err := LookupCachedRemediation(client, "none", "10.1.2.3", nil, MembershipFromIndex(readRangeIndex(client)))
	if err == nil || err.Error() != cache.CacheMiss {
		t.Fatalf("none mode should miss range-index, got %q %v", got, err)
	}
}

func TestLookupCachedRemediationStreamUsesMembershipNotBlob(t *testing.T) {
	client := newTestDecisionCache()
	AddRange(client, "10.0.0.0/8", CaptchaValue, 60)
	banOnly := MembershipFromIndex("10.0.0.0/8=" + BannedValue)
	got, err := LookupCachedRemediation(client, "stream", "10.1.2.3", nil, banOnly)
	if err != nil || got != BannedValue {
		t.Fatalf("membership must win over unread blob, got %q %v", got, err)
	}
	_, missErr := LookupCachedRemediation(client, "stream", "10.1.2.3", nil, MembershipFromIndex(""))
	if missErr == nil || missErr.Error() != cache.CacheMiss {
		t.Fatalf("empty membership must not read blob, got %v", missErr)
	}
}
