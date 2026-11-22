package ratelimit

import (
	"context"
	"time"
)

// Status is what counting one hit returned, whatever the owner's algorithm: Allowed, and on a deny
// RetryAfter (the time until one more hit on the key is admitted with no other traffic). Each counter
// maps its library's status to it, so callers outside this package import neither vendored limiter.
type Status struct {
	Allowed    bool
	RetryAfter time.Duration
}

// Limit is what one bucket admits: Requests per Window (the sliding window's limit, the token bucket's
// refill rate) and, for the token bucket, at most Burst at once. Bucket names the bucket, so a counter
// that keeps one limiter per bucket picks it.
type Limit struct {
	Bucket   string
	Burst    int64
	Requests int64
	Window   time.Duration
}

// Counter counts one hit on key under limit and returns its Status. With the sliding window a hit over
// the limit still counts; with the token bucket it takes no token. *Client is the production Counter;
// tests pass a fake.
type Counter interface {
	Take(ctx context.Context, key string, limit Limit) (Status, error)
}
