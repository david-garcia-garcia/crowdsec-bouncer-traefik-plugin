package decisionscope

import (
	"net"
	"testing"

	"github.com/maxlerebourg/crowdsec-bouncer-traefik-plugin/pkg/cache"
)

func TestLookupPackedMemoryBanDoesNotReturnOriginName(t *testing.T) {
	client := newTestDecisionCache()
	client.SetRemediation("203.0.113.10", cache.Packed(BannedValue, 4), 60)
	kind, stored, err := LookupCachedRemediation(client, "203.0.113.10", net.ParseIP("203.0.113.10"), nil, nil)
	if err != nil || kind != BannedValue {
		t.Fatalf("kind %q err %v", kind, err)
	}
	if cache.RemediationOrigin(stored) != "" {
		t.Fatalf("lookup must not resolve leftover origin, stored %q", stored)
	}
	id, packed := cache.ParsePackedOriginID(stored)
	if !packed || id != 4 {
		t.Fatalf("stored packed id %d packed %v form %q", id, packed, stored)
	}
}

func TestLookupPackedRangeMembershipRemediates(t *testing.T) {
	client := newTestDecisionCache()
	packed := cache.Packed(BannedValue, 2)
	if err := ApplyRangeBatch(client, map[string]string{"10.0.0.0/8": packed.IndexForm()}, nil); err != nil {
		t.Fatal(err)
	}
	index, _ := readRangeIndex(client)
	membership := MembershipFromIndex(index)
	if cache.RemediationKind(membership.Remediation(net.ParseIP("10.1.2.3"))) != BannedValue {
		t.Fatalf("membership %q", membership.Remediation(net.ParseIP("10.1.2.3")))
	}
	kind, stored, err := LookupCachedRemediation(client, "10.1.2.3", net.ParseIP("10.1.2.3"), nil, membership)
	if err != nil || kind != BannedValue {
		t.Fatalf("kind %q err %v", kind, err)
	}
	id, ok := cache.ParsePackedOriginID(stored)
	if !ok || id != 2 {
		t.Fatalf("range stored %q id %d ok %v", stored, id, ok)
	}
}
