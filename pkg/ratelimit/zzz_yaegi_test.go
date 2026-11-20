package ratelimit

import (
	"testing"

	"github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pkg/yaegitest"
)

// TestYaegi_OpenChargeClose runs the rate-limit leg under Yaegi v0.16.1, the way Traefik loads it:
// Open (reclaim, simpleredis, vendored windowcounter) in exact and buffered mode against a dead
// address, a Charge through the Counter interface that must return the counter error, a Charge on an
// interpreted counter that must deny, and Close.
func TestYaegi_OpenChargeClose(t *testing.T) {
	yaegitest.Run(t, yaegitest.GoPath(t), yaegiRateLimitProgram)
}

// yaegiRateLimitProgram is the package main program TestYaegi_OpenChargeClose interprets.
const yaegiRateLimitProgram = `package main

import (
	"context"
	"log/slog"
	"net"
	"net/http/httptest"
	"os"
	"time"

	"github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pkg/ratelimit"
)

type denyAfterOne struct {
	hits map[string]int64
}

func (counter *denyAfterOne) Take(ctx context.Context, key string, limit int64, window time.Duration) (bool, float64, error) {
	counter.hits[key]++
	return counter.hits[key] <= 1, float64(counter.hits[key]), nil
}

func fail(message string) {
	println(message)
	os.Exit(1)
}

func main() {
	set, err := ratelimit.NewBucketSet([]ratelimit.BucketRule{{
		Name:     "per-ip",
		Requests: 1,
		Window:   "1m",
		Key:      []ratelimit.KeyPart{{From: ratelimit.KeyFromIP, IPv4Prefix: 24}},
	}})
	if err != nil {
		fail("NewBucketSet: " + err.Error())
	}
	clientIP := net.ParseIP("198.51.100.7")
	log := slog.New(slog.NewTextHandler(os.Stderr, nil))
	for _, syncRate := range []time.Duration{0, 200 * time.Millisecond} {
		client, err := ratelimit.Open(context.Background(), "yaegi", ratelimit.RedisSettings{Host: "127.0.0.1:1", SyncRate: syncRate}, log)
		if err != nil {
			fail("Open: " + err.Error())
		}
		var counter ratelimit.Counter = client
		ctx, cancel := context.WithTimeout(context.Background(), ratelimit.StepBudget)
		verdict := set.Charge(ctx, counter, "yaegi", httptest.NewRequest("GET", "http://example.com/", nil), clientIP)
		cancel()
		if verdict.Err == nil {
			fail("Charge against a dead address must return the counter error")
		}
		client.Close()
	}
	var fake ratelimit.Counter = &denyAfterOne{hits: map[string]int64{}}
	first := set.Charge(context.Background(), fake, "yaegi", httptest.NewRequest("GET", "http://example.com/", nil), clientIP)
	second := set.Charge(context.Background(), fake, "yaegi", httptest.NewRequest("GET", "http://example.com/", nil), clientIP)
	if first.DenyBucket != "" || second.DenyBucket != "per-ip" || second.RetryAfter < time.Second {
		fail("interpreted counter: want the second request denied by per-ip")
	}
}
`
