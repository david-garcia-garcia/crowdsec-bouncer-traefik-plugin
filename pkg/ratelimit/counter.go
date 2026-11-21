package ratelimit

import (
	"context"
	"time"
)

// Counter counts one hit on key and reports whether the sliding-window estimate is still within
// limit per window. The hit is counted even when it is over the limit. *Client is the production
// Counter; tests pass a fake.
type Counter interface {
	Take(ctx context.Context, key string, limit int64, window time.Duration) (allowed bool, estimated float64, err error)
}
