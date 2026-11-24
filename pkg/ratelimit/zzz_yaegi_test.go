package ratelimit

import (
	"testing"

	"github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pkg/yaegitest"
)

// TestYaegi_OpenChargeClose runs the rate-limit leg under Yaegi v0.16.1, the way Traefik loads it:
// Open (reclaim, simpleredis, vendored windowcounter and tokenbucket) with buckets and a policy, for the
// sliding window in exact and buffered mode and for the token bucket, against a dead address (exact mode
// and the token bucket return the counter error, buffered mode keeps the local limit), the Client's
// buckets, policy, and incarnation, a nil Client's empty incarnation, a Charge on an interpreted counter
// whose ratelimit bucket must answer, the interpreted counter seeing each bucket's burst, stacked captcha
// and ratelimit buckets with and without a cleared gate, and Close.
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

	"github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pkg/clientrequest"
	"github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pkg/ratelimit"
)

type inMemoryCounter struct {
	hits      map[string]int64
	lastBurst int64
}

func (counter *inMemoryCounter) Take(ctx context.Context, key string, limit ratelimit.Limit) (ratelimit.Status, error) {
	counter.hits[key]++
	counter.lastBurst = limit.Burst
	allowed := counter.hits[key] <= limit.Requests
	status := ratelimit.Status{Allowed: allowed}
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
	buckets := []ratelimit.BucketRule{{
		Name:     "per-ip",
		Requests: 1,
		Window:   "1m",
		Key:      []ratelimit.KeyPart{{From: ratelimit.KeyFromIP, IPv4Prefix: 24}},
	}}
	policy := ratelimit.Policy{FailureAction: "ban", ResponseHeaders: true, StatusCode: 503}
	clientIP := net.ParseIP("198.51.100.7")
	log := slog.New(slog.NewTextHandler(os.Stderr, nil))
	if (*ratelimit.Client)(nil).Incarnation() != "" {
		exitWithFailure("a nil Client must have an empty incarnation")
	}
	var set *ratelimit.BucketSet
	algorithms := []string{ratelimit.AlgorithmSlidingWindow, ratelimit.AlgorithmSlidingWindow, ratelimit.AlgorithmTokenBucket}
	syncRates := []time.Duration{0, 200 * time.Millisecond, 200 * time.Millisecond}
	for i := range algorithms {
		syncRate := syncRates[i]
		algorithm := algorithms[i]
		client, err := ratelimit.Open(context.Background(), "yaegi", ratelimit.Settings{
			Algorithm:    algorithm,
			Buckets:      buckets,
			InstanceName: "shared",
			Policy:       policy,
			Redis:        ratelimit.RedisSettings{Host: "127.0.0.1:1", SyncRate: syncRate},
		}, log)
		if err != nil {
			exitWithFailure("Open: " + err.Error())
		}
		if client.Incarnation() == "" || client.Buckets() == nil || client.Policy() != policy {
			exitWithFailure("Open must keep an incarnation, the compiled buckets, and the policy")
		}
		set = client.Buckets()
		var counter ratelimit.Counter = client
		var verdicts [2]ratelimit.Verdict
		for i := range verdicts {
			ctx, cancel := context.WithTimeout(context.Background(), ratelimit.StepBudget)
			verdicts[i] = set.Charge(ctx, counter, "yaegi", clientrequest.New(httptest.NewRequest("GET", "http://example.com/", nil), clientIP.String(), clientIP), false)
			cancel()
		}
		if algorithm == ratelimit.AlgorithmTokenBucket {
			if verdicts[0].Err == nil || verdicts[1].Err == nil {
				exitWithFailure("token-bucket Charge against a dead address must return the counter error")
			}
		} else if syncRate == 0 {
			if verdicts[0].Err == nil {
				exitWithFailure("exact Charge against a dead address must return the counter error")
			}
		} else if verdicts[0].Err != nil || verdicts[1].Err != nil || verdicts[0].RateLimit.Name != "" || verdicts[1].RateLimit.Name != "per-ip" {
			exitWithFailure("buffered Charge against a dead address must keep the local limit without an error")
		}
		client.Close()
	}
	burstCounter := &inMemoryCounter{hits: map[string]int64{}}
	var fake ratelimit.Counter = burstCounter
	first := set.Charge(context.Background(), fake, "yaegi", clientrequest.New(httptest.NewRequest("GET", "http://example.com/", nil), clientIP.String(), clientIP), false)
	if burstCounter.lastBurst != 1 {
		exitWithFailure("the counter must see the bucket's burst (requests when unset)")
	}
	second := set.Charge(context.Background(), fake, "yaegi", clientrequest.New(httptest.NewRequest("GET", "http://example.com/", nil), clientIP.String(), clientIP), false)
	if first.RateLimit.Name != "" || second.RateLimit.Name != "per-ip" || second.RateLimit.RetryAfter != 3*time.Second {
		exitWithFailure("interpreted counter: want the second request answered by per-ip")
	}

	// Stacked: soft (captcha, 1) before hard (ratelimit, 2). Unsolved: request 2 keeps soft, request 3
	// meets hard. Cleared gate: soft is never charged and hard answers request 3.
	stacked, err := ratelimit.NewBucketSet([]ratelimit.BucketRule{
		{Name: "soft", Action: ratelimit.ActionCaptcha, Requests: 1, Window: "1m", Key: []ratelimit.KeyPart{{From: ratelimit.KeyFromIP}}},
		{Name: "hard", Action: ratelimit.ActionRateLimit, Requests: 2, Window: "1m", Key: []ratelimit.KeyPart{{From: ratelimit.KeyFromIP}}},
	}, ratelimit.AlgorithmSlidingWindow)
	if err != nil || !stacked.HasCaptchaBucket() {
		exitWithFailure("stacked buckets must compile and report a captcha bucket")
	}
	for _, gateCleared := range []bool{false, true} {
		fake = &inMemoryCounter{hits: map[string]int64{}}
		var answers [3]ratelimit.Verdict
		for i := range answers {
			answers[i] = stacked.Charge(context.Background(), fake, "yaegi", clientrequest.New(httptest.NewRequest("GET", "http://example.com/", nil), clientIP.String(), clientIP), gateCleared)
		}
		wantCaptcha := "soft"
		if gateCleared {
			wantCaptcha = ""
		}
		if answers[0].Captcha.Name != "" || answers[1].Captcha.Name != wantCaptcha || answers[1].RateLimit.Name != "" {
			exitWithFailure("stacked: request 2 must keep the captcha bucket only for an unsolved client")
		}
		if answers[2].RateLimit.Name != "hard" {
			exitWithFailure("stacked: request 3 must be answered by the ratelimit bucket")
		}
	}
}
`
