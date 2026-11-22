package ratelimit

import (
	"errors"
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pkg/httprule"
)

// BucketSet is a compiled rateLimitBuckets list. Predicates of every bucket share one httprule.Set,
// so Matching returns the buckets that match a request in list order.
type BucketSet struct {
	buckets          []compiledBucket
	hasCaptchaBucket bool
	predicates       *httprule.Set
}

// compiledBucket is one bucket after validation: everything Charge needs besides its predicates.
// burst is the token bucket's size (requests when unset); the sliding window does not read it.
type compiledBucket struct {
	action   string
	burst    int64
	final    bool
	key      []compiledKeyPart
	name     string
	requests int64
	window   time.Duration
}

// compiledKeyPart is one validated key part. Nil pattern means the whole value is the key part.
type compiledKeyPart struct {
	from       string
	ipv4Prefix int
	ipv6Prefix int
	name       string
	pattern    *regexp.Regexp
}

// NewBucketSet validates every row for the owner's algorithm (empty means AlgorithmSlidingWindow) and
// compiles predicates and key patterns once. Inner errors are index-prefixed bucket %d. A row with no
// predicate matches every request.
func NewBucketSet(rules []BucketRule, algorithm string) (*BucketSet, error) {
	if err := ValidateAlgorithm(algorithm); err != nil {
		return nil, fmt.Errorf("rateLimitAlgorithm: %w", err)
	}
	algorithm = EffectiveAlgorithm(algorithm)
	set := &BucketSet{buckets: make([]compiledBucket, 0, len(rules))}
	predicateRows := make([]httprule.Rule, 0, len(rules))
	seenNames := make(map[string]struct{}, len(rules))
	for i, rule := range rules {
		compiled, err := compileBucket(rule, algorithm, seenNames)
		if err != nil {
			return nil, fmt.Errorf("bucket %d: %w", i, err)
		}
		seenNames[compiled.name] = struct{}{}
		set.buckets = append(set.buckets, compiled)
		set.hasCaptchaBucket = set.hasCaptchaBucket || compiled.action == ActionCaptcha
		predicateRows = append(predicateRows, rule.Rule)
	}
	// Every row compiled on its own above, so the whole list compiles too.
	predicates, err := httprule.NewWithCatchAll(predicateRows)
	if err != nil {
		return nil, err
	}
	set.predicates = predicates
	return set, nil
}

// HasCaptchaBucket reports whether a bucket of the set answers with a captcha. False on a nil set.
func (set *BucketSet) HasCaptchaBucket() bool {
	return set != nil && set.hasCaptchaBucket
}

// limits is the Limit of every bucket in list order: what a counter that keeps one limiter per bucket builds.
func (set *BucketSet) limits() []Limit {
	limits := make([]Limit, 0, len(set.buckets))
	for i := range set.buckets {
		limits = append(limits, set.buckets[i].limit())
	}
	return limits
}

// limit is what this bucket admits, as the counter reads it.
func (bucket *compiledBucket) limit() Limit {
	return Limit{Bucket: bucket.name, Burst: bucket.burst, Requests: bucket.requests, Window: bucket.window}
}

// EffectiveAlgorithm maps an empty rateLimitAlgorithm to AlgorithmSlidingWindow, the default.
func EffectiveAlgorithm(algorithm string) string {
	if trimmed := strings.TrimSpace(algorithm); trimmed != "" {
		return trimmed
	}
	return AlgorithmSlidingWindow
}

// ValidateAlgorithm accepts slidingWindow, tokenBucket, and empty (the default slidingWindow).
func ValidateAlgorithm(algorithm string) error {
	switch EffectiveAlgorithm(algorithm) {
	case AlgorithmSlidingWindow, AlgorithmTokenBucket:
		return nil
	default:
		return fmt.Errorf("must be %q or %q", AlgorithmSlidingWindow, AlgorithmTokenBucket)
	}
}

// compileBucket validates one row for algorithm. seen holds the names of the rows before it.
func compileBucket(rule BucketRule, algorithm string, seen map[string]struct{}) (compiledBucket, error) {
	name, err := httprule.CompileRowName(rule.Name, seen)
	if err != nil {
		return compiledBucket{}, err
	}
	// Predicates: compile this row alone so its error carries this bucket's index, not the httprule row index.
	if _, predicateErr := httprule.NewWithCatchAll([]httprule.Rule{rule.Rule}); predicateErr != nil {
		return compiledBucket{}, errors.Unwrap(predicateErr)
	}
	if strings.TrimSpace(rule.Algorithm) != "" {
		return compiledBucket{}, errors.New("algorithm: is not a bucket setting; set rateLimitAlgorithm on the rate-limit owner")
	}
	action, err := compileBucketAction(rule.Action)
	if err != nil {
		return compiledBucket{}, err
	}
	if rule.Requests < 1 {
		return compiledBucket{}, errors.New("requests: must be at least 1")
	}
	window, err := compileWindow(rule.Window)
	if err != nil {
		return compiledBucket{}, err
	}
	burst, err := compileBurst(rule.Burst, int64(rule.Requests), window, algorithm)
	if err != nil {
		return compiledBucket{}, err
	}
	key, err := compileKeyParts(rule.Key)
	if err != nil {
		return compiledBucket{}, err
	}
	return compiledBucket{
		action:   action,
		burst:    burst,
		final:    rule.Final,
		key:      key,
		name:     name,
		requests: int64(rule.Requests),
		window:   window,
	}, nil
}

// compileBurst returns the token bucket's size: requests when burst is unset (0), otherwise burst, which
// must be at least 1 and is read only by the token bucket, whose full refill must fit maxTokenBucketRefill.
func compileBurst(burst int, requests int64, window time.Duration, algorithm string) (int64, error) {
	if burst < 0 {
		return 0, errors.New("burst: must be at least 1")
	}
	if burst != 0 && algorithm != AlgorithmTokenBucket {
		return 0, fmt.Errorf("burst: only read when rateLimitAlgorithm is %q", AlgorithmTokenBucket)
	}
	compiled := requests
	if burst != 0 {
		compiled = int64(burst)
	}
	if algorithm != AlgorithmTokenBucket {
		return compiled, nil
	}
	refill := tokenBucketRefillSeconds(Limit{Burst: compiled, Requests: requests, Window: window})
	if refill > maxTokenBucketRefill.Seconds() {
		return 0, fmt.Errorf("burst: a full refill (burst x window / requests) must be at most %s", maxTokenBucketRefill)
	}
	return compiled, nil
}

// compileBucketAction maps empty to ratelimit and rejects anything but ratelimit, captcha, and log
// (the former deny value included), naming the accepted values.
func compileBucketAction(raw string) (string, error) {
	switch action := strings.TrimSpace(raw); action {
	case "":
		return ActionRateLimit, nil
	case ActionRateLimit, ActionCaptcha, ActionLog:
		return action, nil
	default:
		return "", fmt.Errorf("action: must be one of %q, %q, or %q", ActionRateLimit, ActionCaptcha, ActionLog)
	}
}

// compileWindow parses a Go duration that is at least one second and a whole number of seconds,
// the grid the sliding-window counter keys its windows on.
func compileWindow(raw string) (time.Duration, error) {
	window, err := time.ParseDuration(strings.TrimSpace(raw))
	if err != nil {
		return 0, fmt.Errorf("window: %w", err)
	}
	if window < time.Second {
		return 0, errors.New("window: must be at least 1s")
	}
	if window%time.Second != 0 {
		return 0, errors.New("window: must be a whole number of seconds")
	}
	return window, nil
}

// compileKeyParts validates each part. Inner errors are index-prefixed key %d.
func compileKeyParts(parts []KeyPart) ([]compiledKeyPart, error) {
	compiled := make([]compiledKeyPart, 0, len(parts))
	for i, part := range parts {
		keyPart, err := compileKeyPart(part)
		if err != nil {
			return nil, fmt.Errorf("key %d: %w", i, err)
		}
		compiled = append(compiled, keyPart)
	}
	return compiled, nil
}

// compileKeyPart checks from, name, the ip prefixes, and pattern for one part.
func compileKeyPart(part KeyPart) (compiledKeyPart, error) {
	from := strings.TrimSpace(part.From)
	name := strings.TrimSpace(part.Name)
	// Source and name: header, cookie, and query need a name; the other sources must not have one.
	switch from {
	case KeyFromHeader, KeyFromCookie, KeyFromQuery:
		if name == "" {
			return compiledKeyPart{}, fmt.Errorf("name: required for from %q", from)
		}
	case KeyFromIP, KeyFromHost, KeyFromPath, KeyFromMethod:
		if name != "" {
			return compiledKeyPart{}, fmt.Errorf("name: not allowed for from %q", from)
		}
	default:
		return compiledKeyPart{}, fmt.Errorf("from: unknown %q", from)
	}
	// Prefixes: only an ip part masks, and only within the family's bit length.
	if from != KeyFromIP && (part.IPv4Prefix != 0 || part.IPv6Prefix != 0) {
		return compiledKeyPart{}, fmt.Errorf("ipv4Prefix and ipv6Prefix: only allowed for from %q", KeyFromIP)
	}
	if part.IPv4Prefix != 0 && (part.IPv4Prefix < 1 || part.IPv4Prefix > 32) {
		return compiledKeyPart{}, errors.New("ipv4Prefix: must be between 1 and 32")
	}
	if part.IPv6Prefix != 0 && (part.IPv6Prefix < 1 || part.IPv6Prefix > 128) {
		return compiledKeyPart{}, errors.New("ipv6Prefix: must be between 1 and 128")
	}
	// Pattern: RE2 with a capture group, whose group 1 becomes the value.
	var pattern *regexp.Regexp
	if raw := strings.TrimSpace(part.Pattern); raw != "" {
		var err error
		pattern, err = regexp.Compile(raw)
		if err != nil {
			return compiledKeyPart{}, fmt.Errorf("pattern: %w", err)
		}
		if pattern.NumSubexp() < 1 {
			return compiledKeyPart{}, errors.New("pattern: needs a capture group")
		}
	}
	return compiledKeyPart{
		from:       from,
		ipv4Prefix: part.IPv4Prefix,
		ipv6Prefix: part.IPv6Prefix,
		name:       name,
		pattern:    pattern,
	}, nil
}
