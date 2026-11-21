package ratelimit

import (
	"testing"

	"github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pkg/yaegitest"
)

// TestYaegi_OpenChargeClose runs the rate-limit leg under Yaegi v0.16.1, the way Traefik loads it:
// Open (reclaim, simpleredis, vendored windowcounter) in exact and buffered mode against a dead
// address (exact mode returns the counter error, buffered mode keeps the local limit), a Charge on an
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

func (counter *denyAfterOne) Take(ctx context.Context, key string, limit int64, window time.Duration) (ratelimit.Status, error) {
	counter.hits[key]++
	allowed := counter.hits[key] <= 1
	status := ratelimit.Status{Allowed: allowed, Limit: limit, Estimated: float64(counter.hits[key])}
	if !allowed {
		status.RetryAfter = 2500 * time.Millisecond
	}
	return status, nil
}

func exitWithFailure(message string) {
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
		exitWithFailure("NewBucketSet: " + err.Error())
	}
	clientIP := net.ParseIP("198.51.100.7")
	log := slog.New(slog.NewTextHandler(os.Stderr, nil))
	for _, syncRate := range []time.Duration{0, 200 * time.Millisecond} {
		client, err := ratelimit.Open(context.Background(), "yaegi", ratelimit.RedisSettings{Host: "127.0.0.1:1", SyncRate: syncRate}, log)
		if err != nil {
			exitWithFailure("Open: " + err.Error())
		}
		var counter ratelimit.Counter = client
		var verdicts [2]ratelimit.Verdict
		for i := range verdicts {
			ctx, cancel := context.WithTimeout(context.Background(), ratelimit.StepBudget)
			verdicts[i] = set.Charge(ctx, counter, "yaegi", httptest.NewRequest("GET", "http://example.com/", nil), clientIP)
			cancel()
		}
		if syncRate == 0 {
			if verdicts[0].Err == nil {
				exitWithFailure("exact Charge against a dead address must return the counter error")
			}
		} else if verdicts[0].Err != nil || verdicts[1].Err != nil || verdicts[0].DenyBucket != "" || verdicts[1].DenyBucket != "per-ip" {
			exitWithFailure("buffered Charge against a dead address must keep the local limit without an error")
		}
		client.Close()
	}
	var fake ratelimit.Counter = &denyAfterOne{hits: map[string]int64{}}
	first := set.Charge(context.Background(), fake, "yaegi", httptest.NewRequest("GET", "http://example.com/", nil), clientIP)
	second := set.Charge(context.Background(), fake, "yaegi", httptest.NewRequest("GET", "http://example.com/", nil), clientIP)
	if first.DenyBucket != "" || second.DenyBucket != "per-ip" || second.RetryAfter != 3*time.Second {
		exitWithFailure("interpreted counter: want the second request denied by per-ip")
	}
}
`
