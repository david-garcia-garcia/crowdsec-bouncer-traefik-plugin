package ratelimit

import (
	"net"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strings"
	"testing"
)

// testKeyOf returns the counter key the first bucket of rules gives the request, or false when a part is missing.
func testKeyOf(t *testing.T, middlewareName string, rules []BucketRule, httpReq *http.Request, clientIP string) (string, bool) {
	t.Helper()
	set := mustNewTestBucketSet(t, rules)
	return set.buckets[0].counterKey(middlewareName, &keySource{httpReq: httpReq, clientIP: net.ParseIP(clientIP)})
}

// TestCounterKey_eachSource proves every source reads its own request value and a missing value skips.
func TestCounterKey_eachSource(t *testing.T) {
	httpReq := httptest.NewRequest(http.MethodPost, "http://shop.example:8443/t/acme/orders?tenant=acme", nil)
	httpReq.Header.Set("Authorization", "Bearer secret-token")
	httpReq.AddCookie(&http.Cookie{Name: "session", Value: "s1"})
	tests := []struct {
		name  string
		part  KeyPart
		value string
	}{
		{name: "ip", part: KeyPart{From: KeyFromIP}, value: "198.51.100.7"},
		{name: "header is case-insensitive", part: KeyPart{From: KeyFromHeader, Name: "authorization"}, value: "Bearer secret-token"},
		{name: "cookie", part: KeyPart{From: KeyFromCookie, Name: "session"}, value: "s1"},
		{name: "query", part: KeyPart{From: KeyFromQuery, Name: "tenant"}, value: "acme"},
		{name: "host drops the port", part: KeyPart{From: KeyFromHost}, value: "shop.example"},
		{name: "path", part: KeyPart{From: KeyFromPath}, value: "/t/acme/orders"},
		{name: "method", part: KeyPart{From: KeyFromMethod}, value: http.MethodPost},
		{name: "pattern group", part: KeyPart{From: KeyFromPath, Pattern: "^/t/([^/]+)/"}, value: "acme"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			bucket := validTestBucket("b")
			bucket.Key = []KeyPart{tt.part}
			key, found := testKeyOf(t, "edge", []BucketRule{bucket}, httpReq, "198.51.100.7")
			if !found {
				t.Fatal("value missing")
			}
			if want := redisCounterKey("edge", "b", []string{tt.value}); key != want {
				t.Fatalf("key=%s want %s (value %q)", key, want, tt.value)
			}
		})
	}
	missing := []KeyPart{
		{From: KeyFromHeader, Name: "X-Absent"},
		{From: KeyFromCookie, Name: "Session"},
		{From: KeyFromQuery, Name: "Tenant"},
		{From: KeyFromPath, Pattern: "^/u/([^/]+)/"},
	}
	for _, part := range missing {
		bucket := validTestBucket("b")
		bucket.Key = []KeyPart{{From: KeyFromIP}, part}
		if _, found := testKeyOf(t, "edge", []BucketRule{bucket}, httpReq, "198.51.100.7"); found {
			t.Errorf("part %+v must be missing", part)
		}
	}
	// The pattern matches but its group is empty: the value is missing, not "".
	emptyGroup := validTestBucket("b")
	emptyGroup.Key = []KeyPart{{From: KeyFromPath, Pattern: "^/t/([^/]*)/"}}
	emptyGroupReq := httptest.NewRequest(http.MethodGet, "http://x/t//orders", nil)
	if _, found := testKeyOf(t, "edge", []BucketRule{emptyGroup}, emptyGroupReq, "198.51.100.7"); found {
		t.Error("an empty capture group must be a missing value")
	}
}

// TestCounterKey_groupsAndSeparates proves tenant capture, IPv6 /64 grouping, the fixed key of an empty
// key list, the hashed Redis key, and separate middleware names.
func TestCounterKey_groupsAndSeparates(t *testing.T) {
	tenant := validTestBucket("tenant")
	tenant.Key = []KeyPart{{From: KeyFromPath, Pattern: "^/t/([^/]+)/"}}
	acmeOrders, _ := testKeyOf(t, "edge", []BucketRule{tenant}, httptest.NewRequest(http.MethodGet, "http://x/t/acme/orders", nil), "198.51.100.1")
	acmeUsers, _ := testKeyOf(t, "edge", []BucketRule{tenant}, httptest.NewRequest(http.MethodGet, "http://x/t/acme/users", nil), "198.51.100.2")
	other, _ := testKeyOf(t, "edge", []BucketRule{tenant}, httptest.NewRequest(http.MethodGet, "http://x/t/other/orders", nil), "198.51.100.1")
	if acmeOrders != acmeUsers || acmeOrders == other {
		t.Fatalf("tenant keys acmeOrders=%s acmeUsers=%s other=%s", acmeOrders, acmeUsers, other)
	}

	network := validTestBucket("net")
	network.Key = []KeyPart{{From: KeyFromIP, IPv6Prefix: 64}}
	req := httptest.NewRequest(http.MethodGet, "http://x/", nil)
	first, _ := testKeyOf(t, "edge", []BucketRule{network}, req, "2001:db8::1")
	second, _ := testKeyOf(t, "edge", []BucketRule{network}, req, "2001:db8::2")
	outside, _ := testKeyOf(t, "edge", []BucketRule{network}, req, "2001:db8:0:1::1")
	if first != second || first == outside {
		t.Fatalf("ipv6 /64 keys first=%s second=%s outside=%s", first, second, outside)
	}

	global := validTestBucket("global")
	global.Key = nil
	fixedA, foundA := testKeyOf(t, "edge", []BucketRule{global}, req, "198.51.100.1")
	fixedB, _ := testKeyOf(t, "edge", []BucketRule{global}, req, "203.0.113.9")
	if !foundA || fixedA != fixedB {
		t.Fatalf("empty key list must give one key: %s %s", fixedA, fixedB)
	}

	token := validTestBucket("token")
	token.Key = []KeyPart{{From: KeyFromHeader, Name: "Authorization"}}
	authReq := httptest.NewRequest(http.MethodGet, "http://x/", nil)
	authReq.Header.Set("Authorization", "Bearer secret-token")
	hashed, _ := testKeyOf(t, "edge", []BucketRule{token}, authReq, "198.51.100.1")
	if strings.Contains(hashed, "secret-token") || !regexp.MustCompile(`^rl:edge:token:[0-9a-f]{16}$`).MatchString(hashed) {
		t.Fatalf("redis key %q must be rl:edge:token:<16 hex>", hashed)
	}
	otherMiddleware, _ := testKeyOf(t, "edge-b", []BucketRule{token}, authReq, "198.51.100.1")
	if otherMiddleware == hashed {
		t.Fatal("two middleware names must not share a key")
	}
}
