package lapi

import (
	"fmt"
	"net"
	"net/url"
	"testing"

	"github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pkg/decisionscope"
	"github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pkg/decisionstore"
)

func testChunkIP(octetBase, index int) string {
	return fmt.Sprintf("10.%d.%d.%d", octetBase, (index>>8)&0xff, index&0xff)
}

func TestHandleStreamCache_SkipsUndecodableDuration(t *testing.T) {
	const kept = "203.0.113.8"
	const skipped = "203.0.113.9"
	server := testReplacementStreamLAPI(t, []Decision{
		{Type: "ban", Scope: "ip", Value: skipped, Duration: "not-a-duration", Origin: "crowdsec"},
		{Type: "ban", Scope: "ip", Value: kept, Duration: "1h", Origin: "crowdsec"},
	}, nil)
	client := newTestStreamPoller(t, server)
	if err := client.handleStreamCache(); err != nil {
		t.Fatal(err)
	}
	if kind, _, _, err := client.LookupRemediation(skipped, net.ParseIP(skipped), nil); err != nil || kind != "" {
		t.Fatalf("bad duration must be skipped, got %q err %v", kind, err)
	}
	if kind, _, _, err := client.LookupRemediation(kept, net.ParseIP(kept), nil); err != nil || kind != decisionscope.BannedValue {
		t.Fatalf("sibling decision = %q err %v", kind, err)
	}
}

func TestHandleStreamCache_FlushesAtPutManyChunk(t *testing.T) {
	count := decisionstore.PutManyChunk + 1
	deleted := make([]Decision, count)
	added := make([]Decision, count)
	for index := range count {
		deleted[index] = Decision{Type: "ban", Scope: "ip", Value: testChunkIP(1, index)}
		added[index] = Decision{
			Type: "ban", Scope: "ip", Value: testChunkIP(2, index), Duration: "1h", Origin: "crowdsec",
		}
	}
	server := testReplacementStreamLAPI(t, added, deleted)
	parsed, err := url.Parse(server.URL)
	if err != nil {
		t.Fatal(err)
	}
	client, store := newTestRangeClient(t)
	for index := range count {
		store.Put(decisionstore.Decision{
			Scope: decisionscope.ScopeIP, Value: testChunkIP(1, index), Kind: decisionscope.BannedValue, DurationSec: 60,
		})
	}
	client.crowdsecScheme = "http"
	client.crowdsecHost = parsed.Host
	client.crowdsecPath = "/"
	client.crowdsecStreamRoute = crowdsecLapiStreamRoute
	attachTestTransport(client, server.Client(), "test-key")

	if err := client.handleStreamCache(); err != nil {
		t.Fatal(err)
	}
	for _, index := range []int{0, decisionstore.PutManyChunk - 1, decisionstore.PutManyChunk} {
		oldIP := testChunkIP(1, index)
		if kind, _, _, lookupErr := client.LookupRemediation(oldIP, net.ParseIP(oldIP), nil); lookupErr != nil || kind != "" {
			t.Fatalf("deleted %s = %q err %v", oldIP, kind, lookupErr)
		}
		newIP := testChunkIP(2, index)
		if kind, _, _, lookupErr := client.LookupRemediation(newIP, net.ParseIP(newIP), nil); lookupErr != nil || kind != decisionscope.BannedValue {
			t.Fatalf("added %s = %q err %v", newIP, kind, lookupErr)
		}
	}
}
