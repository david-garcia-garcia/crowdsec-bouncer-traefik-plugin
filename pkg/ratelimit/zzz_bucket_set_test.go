package ratelimit

import (
	"strings"
	"testing"

	"github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pkg/httprule"
)

// validTestBucket is a catch-all bucket that passes NewBucketSet; cases change one field.
func validTestBucket(name string) BucketRule {
	return BucketRule{Name: name, Requests: 5, Window: "1m", Key: []KeyPart{{From: KeyFromIP}}}
}

// mustNewTestBucketSet compiles rules or fails the test.
func mustNewTestBucketSet(t *testing.T, rules []BucketRule) *BucketSet {
	t.Helper()
	set, err := NewBucketSet(rules)
	if err != nil {
		t.Fatal(err)
	}
	return set
}

// TestNewBucketSet_rejectsEachRowError proves every row check fails with its own stem and the bucket index.
func TestNewBucketSet_rejectsEachRowError(t *testing.T) {
	with := func(change func(*BucketRule)) []BucketRule {
		bucket := validTestBucket("b")
		change(&bucket)
		return []BucketRule{bucket}
	}
	tests := []struct {
		name    string
		rules   []BucketRule
		wantErr string
	}{
		{name: "empty name", rules: with(func(b *BucketRule) { b.Name = " " }), wantErr: "bucket 0: name: empty"},
		{name: "colon in name", rules: with(func(b *BucketRule) { b.Name = "a:b" }), wantErr: "bucket 0: name: contains colon"},
		{name: "duplicate name", rules: []BucketRule{validTestBucket("b"), validTestBucket("b")}, wantErr: "bucket 1: name: duplicate"},
		{name: "bad path RE2", rules: with(func(b *BucketRule) { b.Path = "(" }), wantErr: "bucket 0: path:"},
		{name: "bad header RE2", rules: with(func(b *BucketRule) { b.Headers = map[string]string{"X-A": "("} }), wantErr: "bucket 0: headers:"},
		{name: "double negation", rules: with(func(b *BucketRule) { b.Method = "!!" }), wantErr: "bucket 0: method: double negation"},
		{name: "bare negation", rules: with(func(b *BucketRule) { b.Method = "!" }), wantErr: "bucket 0: method: empty negation"},
		{name: "requests 0", rules: with(func(b *BucketRule) { b.Requests = 0 }), wantErr: "bucket 0: requests: must be at least 1"},
		{name: "window 500ms", rules: with(func(b *BucketRule) { b.Window = "500ms" }), wantErr: "bucket 0: window: must be at least 1s"},
		{name: "window 1500ms", rules: with(func(b *BucketRule) { b.Window = "1500ms" }), wantErr: "bucket 0: window: must be a whole number of seconds"},
		{name: "window abc", rules: with(func(b *BucketRule) { b.Window = "abc" }), wantErr: "bucket 0: window:"},
		{name: "window empty", rules: with(func(b *BucketRule) { b.Window = "" }), wantErr: "bucket 0: window:"},
		{name: "action deny", rules: with(func(b *BucketRule) { b.Action = "deny" }), wantErr: `bucket 0: action: must be one of "ratelimit", "captcha", or "log"`},
		{name: "action unknown", rules: with(func(b *BucketRule) { b.Action = "block" }), wantErr: `bucket 0: action: must be one of "ratelimit", "captcha", or "log"`},
		{name: "algorithm tokenBucket", rules: with(func(b *BucketRule) { b.Algorithm = "tokenBucket" }), wantErr: "bucket 0: algorithm: tokenBucket is not supported in this version"},
		{name: "algorithm unknown", rules: with(func(b *BucketRule) { b.Algorithm = "fixed" }), wantErr: "bucket 0: algorithm: must be"},
		{name: "burst set", rules: with(func(b *BucketRule) { b.Burst = 10 }), wantErr: "bucket 0: burst: is not supported in this version"},
		{name: "unknown from", rules: with(func(b *BucketRule) { b.Key = []KeyPart{{From: "body"}} }), wantErr: `bucket 0: key 0: from: unknown "body"`},
		{name: "header without name", rules: with(func(b *BucketRule) { b.Key = []KeyPart{{From: KeyFromHeader}} }), wantErr: "bucket 0: key 0: name: required"},
		{name: "cookie without name", rules: with(func(b *BucketRule) { b.Key = []KeyPart{{From: KeyFromCookie}} }), wantErr: "bucket 0: key 0: name: required"},
		{name: "query without name", rules: with(func(b *BucketRule) { b.Key = []KeyPart{{From: KeyFromQuery}} }), wantErr: "bucket 0: key 0: name: required"},
		{name: "ip with name", rules: with(func(b *BucketRule) { b.Key = []KeyPart{{From: KeyFromIP, Name: "x"}} }), wantErr: "bucket 0: key 0: name: not allowed"},
		{name: "ipv4Prefix 33", rules: with(func(b *BucketRule) { b.Key = []KeyPart{{From: KeyFromIP, IPv4Prefix: 33}} }), wantErr: "bucket 0: key 0: ipv4Prefix: must be between 1 and 32"},
		{name: "ipv6Prefix 129", rules: with(func(b *BucketRule) { b.Key = []KeyPart{{From: KeyFromIP, IPv6Prefix: 129}} }), wantErr: "bucket 0: key 0: ipv6Prefix: must be between 1 and 128"},
		{name: "negative ipv4Prefix", rules: with(func(b *BucketRule) { b.Key = []KeyPart{{From: KeyFromIP, IPv4Prefix: -1}} }), wantErr: "bucket 0: key 0: ipv4Prefix"},
		{name: "prefix on a path part", rules: with(func(b *BucketRule) { b.Key = []KeyPart{{From: KeyFromPath, IPv4Prefix: 24}} }), wantErr: "bucket 0: key 0: ipv4Prefix and ipv6Prefix: only allowed"},
		{name: "bad pattern", rules: with(func(b *BucketRule) { b.Key = []KeyPart{{From: KeyFromPath, Pattern: "("}} }), wantErr: "bucket 0: key 0: pattern:"},
		{name: "pattern without group", rules: with(func(b *BucketRule) { b.Key = []KeyPart{{From: KeyFromPath, Pattern: "^/t/[^/]+/"}} }), wantErr: "bucket 0: key 0: pattern: needs a capture group"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := NewBucketSet(tt.rules)
			if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("err=%v want %q", err, tt.wantErr)
			}
		})
	}
}

// TestNewBucketSet_acceptsCatchAllAndDefaults proves a row with no predicate passes, and that action and
// algorithm default to ratelimit and slidingWindow.
func TestNewBucketSet_acceptsCatchAllAndDefaults(t *testing.T) {
	set := mustNewTestBucketSet(t, []BucketRule{
		{Name: "per-ip", Requests: 300, Window: "1m", Key: []KeyPart{{From: KeyFromIP}}},
		{
			Name: "login", Requests: 5, Window: "60s", Action: ActionLog, Algorithm: AlgorithmSlidingWindow, Final: true,
			Rule: httprule.Rule{Method: "^POST$", Path: "^/login$"},
			Key:  []KeyPart{{From: KeyFromIP, IPv4Prefix: 24, IPv6Prefix: 64}, {From: KeyFromPath, Pattern: "^/t/([^/]+)/"}},
		},
	})
	if len(set.buckets) != 2 {
		t.Fatalf("buckets=%d", len(set.buckets))
	}
	if got := set.buckets[0]; got.action != ActionRateLimit || got.requests != 300 || got.window.Seconds() != 60 || got.final {
		t.Fatalf("bucket 0=%+v", got)
	}
	if got := set.buckets[1]; got.action != ActionLog || !got.final || len(got.key) != 2 || got.key[1].pattern == nil {
		t.Fatalf("bucket 1=%+v", got)
	}
	if _, err := NewBucketSet(nil); err != nil {
		t.Fatalf("empty list err=%v", err)
	}
	if set.HasCaptchaBucket() {
		t.Fatal("a set of ratelimit and log buckets must not report a captcha bucket")
	}
}

// TestNewBucketSet_acceptsEachAction proves ratelimit, captcha, and log compile as themselves, and that
// only a set with a captcha bucket reports one (a nil set reports none).
func TestNewBucketSet_acceptsEachAction(t *testing.T) {
	for _, action := range []string{ActionRateLimit, ActionCaptcha, ActionLog} {
		bucket := validTestBucket("b")
		bucket.Action = " " + action + " "
		set := mustNewTestBucketSet(t, []BucketRule{validTestBucket("first"), bucket})
		if got := set.buckets[1].action; got != action {
			t.Fatalf("action %q compiled as %q", action, got)
		}
		if got, want := set.HasCaptchaBucket(), action == ActionCaptcha; got != want {
			t.Fatalf("action %q: HasCaptchaBucket=%v want %v", action, got, want)
		}
	}
	var nilSet *BucketSet
	if nilSet.HasCaptchaBucket() {
		t.Fatal("a nil set must not report a captcha bucket")
	}
}
