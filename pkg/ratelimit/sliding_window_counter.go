package ratelimit

import (
	"context"

	"github.com/david-garcia-garcia/traefik-middleware-utilities/windowcounter"
)

// slidingWindowCounter is the Counter of rateLimitAlgorithm slidingWindow: the vendored sliding-window
// limiter, which counts every hit (over the limit included), appends the window start to the key, and
// honors the sync rate it was built with.
type slidingWindowCounter struct {
	limiter *windowcounter.Limiter
}

// Take counts one hit on key against limit.Requests per limit.Window and maps the limiter's status.
func (counter *slidingWindowCounter) Take(ctx context.Context, key string, limit Limit) (Status, error) {
	status, err := counter.limiter.Take(ctx, key, limit.Requests, limit.Window)
	if err != nil {
		return Status{}, err
	}
	return Status{Allowed: status.Allowed, RetryAfter: status.RetryAfter}, nil
}
