package ratelimit

import (
	"context"
	"time"

	"github.com/david-garcia-garcia/traefik-middleware-utilities/windowcounter"
)

// Status is what counting one hit returned: Allowed, and on a deny RetryAfter (the time until one more
// hit on the key is admitted with no other traffic). It is windowcounter.Status, so callers outside this
// package do not import the vendored counter.
type Status = windowcounter.Status

// Counter counts one hit on key and returns its Status. The hit is counted even when it is over the
// limit. *Client is the production Counter; tests pass a fake.
type Counter interface {
	Take(ctx context.Context, key string, limit int64, window time.Duration) (Status, error)
}
