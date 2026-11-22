// Package ratelimit is the rate-limit leg: bucket rows (which requests count, what each counter is per,
// and what happens over the limit) and the Redis-backed counter they are charged to, a sliding window or
// a token bucket per the owner's rateLimitAlgorithm.
package ratelimit

import "github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pkg/httprule"

// Key part sources: where the value of one KeyPart is read from.
const (
	KeyFromCookie = "cookie"
	KeyFromHeader = "header"
	KeyFromHost   = "host"
	KeyFromIP     = "ip"
	KeyFromMethod = "method"
	KeyFromPath   = "path"
	KeyFromQuery  = "query"
)

// Bucket actions over the limit. ActionRateLimit is the default.
// ActionRateLimit answers with the rate-limit status at once; ActionCaptcha answers with the subscribing
// router's captcha when no ratelimit bucket answers; ActionLog only logs.
const (
	ActionCaptcha   = "captcha"
	ActionLog       = "log"
	ActionRateLimit = "ratelimit"
)

// Counting algorithms of the whole limiter (rateLimitAlgorithm). AlgorithmSlidingWindow is the default:
// requests per rolling window, every hit counted. AlgorithmTokenBucket refills requests per window and
// holds up to burst tokens.
const (
	AlgorithmSlidingWindow = "slidingWindow"
	AlgorithmTokenBucket   = "tokenBucket"
)

// BucketRule is one authoring row of rateLimitBuckets: a unique name, the request predicates of an
// action rule (flat on the row, squashed like httprule.ActionRule), the key parts, and the limit.
// Window is a Go duration string because Traefik's plugin config decode has no duration hook.
// Burst is the token bucket's size (requests when unset). Algorithm exists only so NewBucketSet can
// reject it with a pointer to rateLimitAlgorithm, instead of Traefik dropping it silently.
type BucketRule struct {
	Action        string    `json:"action,omitempty"`
	Algorithm     string    `json:"algorithm,omitempty"`
	Burst         int       `json:"burst,omitempty"`
	Final         bool      `json:"final,omitempty"`
	Key           []KeyPart `json:"key,omitempty"`
	Name          string    `json:"name,omitempty"`
	Requests      int       `json:"requests,omitempty"`
	Window        string    `json:"window,omitempty"`
	httprule.Rule `json:",inline"             mapstructure:",squash"`
}

// KeyPart is one part of a bucket's counter key: a request value read from From (and Name for a
// header, cookie, or query parameter), optionally narrowed to capture group 1 of Pattern, or for an
// ip part masked to IPv4Prefix / IPv6Prefix bits.
type KeyPart struct {
	From       string `json:"from,omitempty"`
	IPv4Prefix int    `json:"ipv4Prefix,omitempty"`
	IPv6Prefix int    `json:"ipv6Prefix,omitempty"`
	Name       string `json:"name,omitempty"`
	Pattern    string `json:"pattern,omitempty"`
}
