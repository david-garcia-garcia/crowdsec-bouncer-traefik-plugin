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

// AnsweringBucket is a bucket over its limit that answers the request, and the counter's RetryAfter for
// that hit rounded up to whole seconds (at least 1s): when one more request from the same key is admitted
// if the client sends nothing else meanwhile. An empty Name means no such bucket.
type AnsweringBucket struct {
	Name       string
	RetryAfter time.Duration
}

// Verdict is what charging one request decided. The caller reads Err first, then RateLimit, then Captcha:
// Err is the first counter error, the walk stopped there and the failure action applies even when a
// captcha bucket was kept; RateLimit is the ratelimit bucket that stopped the walk; Captcha is the first
// captcha bucket over its limit, which answers only when no ratelimit bucket did.
// Exceeded lists the log buckets over their limit, in list order, whatever else the verdict holds.
type Verdict struct {
	Captcha   AnsweringBucket
	Err       error
	Exceeded  []ExceededBucket
	RateLimit AnsweringBucket
}

// Charge walks the buckets that match httpReq in list order and counts one hit on each bucket whose
// key has a value. A ratelimit bucket over its limit stops the walk; the first captcha bucket over its
// limit is kept and the walk goes on; a log bucket over its limit is recorded and the walk goes on; a
// matching final bucket stops the walk after it; the first counter error stops the walk and is returned.
// gateCleared (the client holds this router's valid captcha gate) skips every captcha bucket: it is not
// charged, cannot answer, and its final does not apply, as for a bucket whose key has no value.
// clientIP is the address GetRemoteIP resolved for the request. A nil set or counter charges nothing.
func (set *BucketSet) Charge(ctx context.Context, counter Counter, middlewareName string, httpReq *http.Request, clientIP net.IP, gateCleared bool) Verdict {
	var verdict Verdict
	if set == nil || counter == nil {
		return verdict
	}
	source := &keySource{httpReq: httpReq, clientIP: clientIP}
	for _, i := range set.predicates.Matching(httpReq) {
		bucket := &set.buckets[i]
		// A solved client is not counted by captcha buckets.
		if gateCleared && bucket.action == ActionCaptcha {
			continue
		}
		// A part without a value skips this bucket, its final included.
		key, found := bucket.counterKey(middlewareName, source)
		if !found {
			continue
		}
		// Count, then compare: an answered hit still counts, so a client that keeps sending stays limited.
		status, err := counter.Take(ctx, key, bucket.requests, bucket.window)
		if err != nil {
			verdict.Err = fmt.Errorf("bucket %s: %w", bucket.name, err)
			return verdict
		}
		// Over the limit: ratelimit answers at once, the first captcha is kept, log is recorded.
		if !status.Allowed {
			switch bucket.action {
			case ActionRateLimit:
				verdict.RateLimit = AnsweringBucket{Name: bucket.name, RetryAfter: wholeSecondsAtLeastOne(status.RetryAfter)}
				return verdict
			case ActionCaptcha:
				if verdict.Captcha.Name == "" {
					verdict.Captcha = AnsweringBucket{Name: bucket.name, RetryAfter: wholeSecondsAtLeastOne(status.RetryAfter)}
				}
			case ActionLog:
				verdict.Exceeded = append(verdict.Exceeded, ExceededBucket{Name: bucket.name, Requests: bucket.requests, Window: bucket.window})
			}
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
