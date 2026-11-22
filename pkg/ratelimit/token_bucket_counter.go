package ratelimit

import (
	"context"
	"fmt"
	"math"
	"time"

	"github.com/david-garcia-garcia/traefik-middleware-utilities/simpleredis"
	"github.com/david-garcia-garcia/traefik-middleware-utilities/tokenbucket"
)

const (
	// tokenBucketKeySuffix ends every token-bucket key (a Redis hash), so it never meets the sliding
	// window's keys of the same bucket, which end in the window start.
	tokenBucketKeySuffix = ":tb"
	// maxTokenBucketRefill bounds a bucket's full refill, which is also its Redis TTL.
	maxTokenBucketRefill = 8760 * time.Hour
)

// tokenBucketCounter is the Counter of rateLimitAlgorithm tokenBucket: one vendored Redis token bucket
// per bucket name, since rate and burst are fixed when a token bucket is built. It holds no goroutine
// and nothing to close besides the shared Redis client, which the Client owns.
type tokenBucketCounter struct {
	buckets map[string]*tokenbucket.Redis
}

// newTokenBucketCounter builds one token bucket per compiled bucket of set on redis: refill
// Requests / Window per second, Burst tokens, no queuing (maxDelay 0), and a TTL of one full refill.
func newTokenBucketCounter(redis *simpleredis.SimpleRedis, set *BucketSet) (*tokenBucketCounter, error) {
	counter := &tokenBucketCounter{buckets: map[string]*tokenbucket.Redis{}}
	for _, limit := range set.limits() {
		bucket, err := tokenbucket.NewRedis(redis, tokenBucketRate(limit), limit.Burst, 0, tokenBucketTTL(limit))
		if err != nil {
			return nil, fmt.Errorf("bucket %s: %w", limit.Bucket, err)
		}
		counter.buckets[limit.Bucket] = bucket
	}
	return counter, nil
}

// Take takes one token for key from the token bucket of limit.Bucket. A hit that finds no whole token is
// denied and refunded, so it takes nothing; RetryAfter is the time until one token is back.
func (counter *tokenBucketCounter) Take(ctx context.Context, key string, limit Limit) (Status, error) {
	bucket, found := counter.buckets[limit.Bucket]
	if !found {
		return Status{}, fmt.Errorf("no token bucket for bucket %s", limit.Bucket)
	}
	status, err := bucket.Allow(ctx, key+tokenBucketKeySuffix)
	if err != nil {
		return Status{}, err
	}
	return Status{Allowed: status.Allowed, RetryAfter: status.RetryAfter}, nil
}

// tokenBucketRate is the refill rate of limit in tokens per second: Requests per Window.
func tokenBucketRate(limit Limit) float64 {
	return float64(limit.Requests) / limit.Window.Seconds()
}

// tokenBucketRefillSeconds is how long an empty bucket of limit takes to be full again:
// Burst x Window / Requests, in seconds.
func tokenBucketRefillSeconds(limit Limit) float64 {
	return float64(limit.Burst) * limit.Window.Seconds() / float64(limit.Requests)
}

// tokenBucketTTL is the Redis TTL of one token-bucket hash: one full refill rounded up to whole seconds,
// at least 1s. Stored tokens never drop below 0 without queuing, so an expired hash and a full bucket are
// the same state. NewBucketSet bounds the refill, so the duration cannot overflow.
func tokenBucketTTL(limit Limit) time.Duration {
	seconds := math.Ceil(tokenBucketRefillSeconds(limit))
	if seconds < 1 {
		return time.Second
	}
	return time.Duration(seconds) * time.Second
}
