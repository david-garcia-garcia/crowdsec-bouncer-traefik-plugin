package ratelimit

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"time"
)

// ExceededBucket is a log bucket that was over its limit for one request.
type ExceededBucket struct {
	Name     string
	Requests int64
	Window   time.Duration
}

// Verdict is what charging one request decided.
// DenyBucket is the deny bucket that answers the request; empty means no bucket denied.
// RetryAfter is the time to that bucket's next window boundary (at least 1s).
// Exceeded lists the log buckets over their limit, in list order.
// Err is the first counter error; the walk stopped there and the caller applies the failure action.
type Verdict struct {
	DenyBucket string
	Err        error
	Exceeded   []ExceededBucket
	RetryAfter time.Duration
}

// Charge walks the buckets that match httpReq in list order and counts one hit on each bucket whose
// key has a value. The first deny bucket over its limit stops the walk; a log bucket over its limit is
// recorded and the walk goes on; a matching final bucket stops the walk after it; the first counter
// error stops the walk and is returned. clientIP is the address GetRemoteIP resolved for the request.
// A nil set or counter charges nothing.
func (set *BucketSet) Charge(ctx context.Context, counter Counter, middlewareName string, httpReq *http.Request, clientIP net.IP) Verdict {
	var verdict Verdict
	if set == nil || counter == nil {
		return verdict
	}
	source := &keySource{httpReq: httpReq, clientIP: clientIP}
	for _, i := range set.predicates.Matching(httpReq) {
		bucket := &set.buckets[i]
		// A part without a value skips this bucket, its final included.
		key, found := bucket.counterKey(middlewareName, source)
		if !found {
			continue
		}
		// Count, then compare: a denied hit still counts, so a client that keeps sending stays limited.
		allowed, _, err := counter.Take(ctx, key, bucket.requests, bucket.window)
		if err != nil {
			verdict.Err = fmt.Errorf("bucket %s: %w", bucket.name, err)
			return verdict
		}
		if !allowed && bucket.action == ActionDeny {
			verdict.DenyBucket = bucket.name
			verdict.RetryAfter = retryAfterAt(set.now(), bucket.window)
			return verdict
		}
		if !allowed && bucket.action == ActionLog {
			verdict.Exceeded = append(verdict.Exceeded, ExceededBucket{Name: bucket.name, Requests: bucket.requests, Window: bucket.window})
		}
		if bucket.final {
			return verdict
		}
	}
	return verdict
}

// retryAfterAt is the time from now to the end of the current window, on the whole-second grid the
// sliding-window counter starts its windows on (unix seconds divided by the window). At least 1s.
// The next request is not promised to pass: the previous window still weighs in.
func retryAfterAt(now time.Time, window time.Duration) time.Duration {
	windowSec := int64(window / time.Second)
	if windowSec < 1 {
		return time.Second
	}
	remaining := windowSec - now.Unix()%windowSec
	if remaining < 1 {
		remaining = 1
	}
	return time.Duration(remaining) * time.Second
}
