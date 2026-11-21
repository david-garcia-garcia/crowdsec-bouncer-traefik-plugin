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
// RetryAfter is the counter's RetryAfter for that bucket, rounded up to whole seconds (at least 1s): when
// one more request from the same key is admitted if the client sends nothing else meanwhile.
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
		status, err := counter.Take(ctx, key, bucket.requests, bucket.window)
		if err != nil {
			verdict.Err = fmt.Errorf("bucket %s: %w", bucket.name, err)
			return verdict
		}
		if !status.Allowed && bucket.action == ActionDeny {
			verdict.DenyBucket = bucket.name
			verdict.RetryAfter = wholeSecondsAtLeastOne(status.RetryAfter)
			return verdict
		}
		if !status.Allowed && bucket.action == ActionLog {
			verdict.Exceeded = append(verdict.Exceeded, ExceededBucket{Name: bucket.name, Requests: bucket.requests, Window: bucket.window})
		}
		if bucket.final {
			return verdict
		}
	}
	return verdict
}

// wholeSecondsAtLeastOne rounds d up to whole seconds, at least 1s: Retry-After is whole seconds, and
// rounding down would send the client back before the counter admits it.
func wholeSecondsAtLeastOne(d time.Duration) time.Duration {
	if d <= time.Second {
		return time.Second
	}
	return (d + time.Second - 1).Truncate(time.Second)
}
