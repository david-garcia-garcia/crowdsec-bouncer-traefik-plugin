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

func TestMatchRangeBanWins(t *testing.T) {
	client := newTestDecisionCache()
	AddRange(client, "10.0.0.0/8", cache.CaptchaValue, 60)
	AddRange(client, "10.1.0.0/16", cache.BannedValue, 60)
	if got := MatchRange(client, "10.1.2.3"); got != cache.BannedValue {
		t.Fatalf("got %q, want ban", got)
	}
	if got := MatchRange(client, "11.0.0.1"); got != "" {
		t.Fatalf("outside range got %q", got)
	}
}

func TestRemoveRange(t *testing.T) {
	client := newTestDecisionCache()
	AddRange(client, "192.168.0.0/16", cache.BannedValue, 60)
	RemoveRange(client, "192.168.0.0/16")
	if got := MatchRange(client, "192.168.1.1"); got != "" {
		t.Fatalf("removed range still matched: %q", got)
	}
}

func TestAddRangeUpdatesRemediation(t *testing.T) {
	client := newTestDecisionCache()
	AddRange(client, "10.0.0.0/8", cache.CaptchaValue, 60)
	AddRange(client, "10.0.0.0/8", cache.BannedValue, 60)
	if got := MatchRange(client, "10.1.2.3"); got != cache.BannedValue {
		t.Fatalf("upsert got %q, want ban", got)
	}
}

func TestMatchRangeFromIndexInline(t *testing.T) {
	if got := MatchRangeFromIndex("10.0.0.0/8="+cache.CaptchaValue+"\n10.1.0.0/16="+cache.BannedValue, "10.1.2.3"); got != cache.BannedValue {
		t.Fatalf("inline index got %q", got)
	}
}

func TestLookupCachedRemediationHeaderScope(t *testing.T) {
	client := newTestDecisionCache()
	client.Set(HeaderScopeKey(ScopeCountry, "FR"), cache.BannedValue, 60)
	got, err := LookupCachedRemediation(client, "stream", "203.0.113.10", map[string]string{ScopeCountry: "FR"})
	if err != nil || got != cache.BannedValue {
		t.Fatalf("got %q %v, want ban", got, err)
	}
}

func TestLookupCachedRemediationMiss(t *testing.T) {
	client := newTestDecisionCache()
	_, err := LookupCachedRemediation(client, "stream", "203.0.113.10", nil)
	if err == nil || err.Error() != cache.CacheMiss {
		t.Fatalf("want cache miss, got %v", err)
	}
}

func TestLookupCachedRemediationNoneSkipsRangeIndex(t *testing.T) {
	client := newTestDecisionCache()
	AddRange(client, "10.0.0.0/8", cache.BannedValue, 60)
	got, err := LookupCachedRemediation(client, "none", "10.1.2.3", nil)
	if err == nil || err.Error() != cache.CacheMiss {
		t.Fatalf("none mode should miss range-index, got %q %v", got, err)
	}
}
