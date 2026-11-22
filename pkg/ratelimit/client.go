package ratelimit

import (
	"context"
	"encoding/json"
	"fmt"
	"hash/fnv"
	"log/slog"
	"strconv"
	"sync"
	"time"

	"github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pkg/reclaim"
	"github.com/david-garcia-garcia/traefik-middleware-utilities/simpleredis"
	"github.com/david-garcia-garcia/traefik-middleware-utilities/windowcounter"
)

const (
	// ownerKeyPrefix starts the reclaim-table key of one rate-limit Client.
	ownerKeyPrefix = "ratelimit:owner:"
	// StepBudget bounds the whole rate-limit step of one request, every bucket and every Redis
	// command (dial and retries included) together.
	StepBudget = 250 * time.Millisecond
	// redisDialTimeout is the per-attempt dial bound; a dial is also capped by what is left of StepBudget.
	redisDialTimeout = 200 * time.Millisecond
	// redisPoolSize caps live sockets to the rate-limit Redis per Client.
	redisPoolSize = 8
	// redisIdleTimeout is how long an idle socket may be reused.
	redisIdleTimeout = 30 * time.Second
)

// Log messages of the Client lifecycle, matching the other legs.
const (
	msgInstanceStarted  = "crowdsec ratelimit instance started"
	msgInstanceSleeping = "crowdsec ratelimit instance sleeping"
	msgInstanceWaking   = "crowdsec ratelimit instance waking"
	msgInstanceClosed   = "crowdsec ratelimit instance closed"
)

// RedisSettings are the Redis server, the resolved password, the database, and the sync rate the
// owner's counter writes through. Only the sliding window reads the sync rate.
type RedisSettings struct {
	Database string        `json:"database"`
	Host     string        `json:"host"`
	Password string        `json:"password"`
	SyncRate time.Duration `json:"syncRate"`
}

// Policy is how every subscriber of the owner's Client answers: the failure action when the counter
// errors, the status of a rate-limited request, and whether it carries Retry-After.
type Policy struct {
	FailureAction   string `json:"failureAction"`
	ResponseHeaders bool   `json:"responseHeaders"`
	StatusCode      int    `json:"statusCode"`
}

// Settings are everything the owner (rateLimitEnabled) puts on its Client: the counting algorithm
// (empty means AlgorithmSlidingWindow), the Redis counter, the bucket rows, the policy, and the instance
// name it is published under (logs only, not the key).
type Settings struct {
	Algorithm    string
	Buckets      []BucketRule
	InstanceName string
	Policy       Policy
	Redis        RedisSettings
}

// Client is the reclaim value of the rate-limit leg: the counter of the owner's algorithm (a sliding
// window, or one token bucket per bucket), the Redis client it writes through, and the owner's compiled
// buckets and policy. It is published under the owner's instance name, and every subscribing router
// charges its buckets and answers with its policy.
type Client struct {
	buckets     *BucketSet
	closed      bool
	counter     Counter // what Take charges: the algorithm's counter, or a fake on a NewTestClient
	incarnation string
	limiter     *windowcounter.Limiter // the sliding window's limiter (flush lifecycle); nil for the token bucket
	log         *slog.Logger
	mu          sync.Mutex
	policy      Policy
	redis       *simpleredis.SimpleRedis
}

// OwnershipKey is the reclaim-table key for the Client of middlewareName with settings: every
// setting except the instance name, so a rename keeps the Client and any other edit opens a new one.
// An empty algorithm keys as AlgorithmSlidingWindow, its default.
func OwnershipKey(middlewareName string, settings Settings) string {
	payload := struct {
		Algorithm      string        `json:"algorithm"`
		Buckets        []BucketRule  `json:"buckets"`
		MiddlewareName string        `json:"middlewareName"`
		Policy         Policy        `json:"policy"`
		Redis          RedisSettings `json:"redis"`
	}{
		Algorithm:      EffectiveAlgorithm(settings.Algorithm),
		Buckets:        settings.Buckets,
		MiddlewareName: middlewareName,
		Policy:         settings.Policy,
		Redis:          settings.Redis,
	}
	encoded, err := json.Marshal(payload)
	if err != nil {
		encoded = []byte(fmt.Sprint(payload))
	}
	hasher := fnv.New64a()
	_, _ = hasher.Write(encoded)
	return ownerKeyPrefix + strconv.FormatUint(hasher.Sum64(), 16)
}

// Open returns the Client held under OwnershipKey(middlewareName, settings), creating it on a first
// put: the bucket rows compile once there for the owner's algorithm, with the policy beside them. ctx is the holder lease: when
// it ends, the Client sleeps, then closes after the table grace.
// Open does not dial; an unreachable Redis is a request-time error.
func Open(ctx context.Context, middlewareName string, settings Settings, log *slog.Logger) (*Client, error) {
	key := OwnershipKey(middlewareName, settings)
	stored, err := reclaim.OpenWithHooks(ctx, key, log, func() (any, reclaim.Hooks, error) {
		buckets, err := NewBucketSet(settings.Buckets, settings.Algorithm)
		if err != nil {
			return nil, reclaim.Hooks{}, fmt.Errorf("ratelimit: buckets: %w", err)
		}
		clientLog := log.With("traefikName", middlewareName, "leg", "ratelimit", "instanceName", settings.InstanceName, "sessionKey", key)
		client, err := newClient(settings.Redis, EffectiveAlgorithm(settings.Algorithm), buckets, clientLog)
		if err != nil {
			return nil, reclaim.Hooks{}, err
		}
		client.policy = settings.Policy
		return client, reclaim.Hooks{Sleep: client.Sleep, Wake: client.Wake, Close: client.Close}, nil
	})
	if err != nil {
		return nil, err
	}
	client, ok := stored.(*Client)
	if !ok {
		return nil, fmt.Errorf("%s: reclaim: want *ratelimit.Client, got %T", middlewareName, stored)
	}
	return client, nil
}

// newClient builds the Redis client and, on it, the counter of algorithm for buckets: the sliding-window
// limiter with the sync rate, or one token bucket per bucket. It does not dial.
func newClient(settings RedisSettings, algorithm string, buckets *BucketSet, log *slog.Logger) (*Client, error) {
	redis, err := simpleredis.New(simpleredis.Config{
		Host:           settings.Host,
		Pass:           settings.Password,
		Database:       settings.Database,
		PoolSize:       redisPoolSize,
		MaxIdleConns:   redisPoolSize,
		IdleTimeout:    redisIdleTimeout,
		DialTimeout:    redisDialTimeout,
		CommandTimeout: StepBudget,
		Logger:         debugCappedLogger(log),
	})
	if err != nil {
		return nil, fmt.Errorf("ratelimit: redis: %w", err)
	}
	client := &Client{buckets: buckets, log: log, redis: redis}
	// The counter of the owner's algorithm, on the one Redis client.
	switch algorithm {
	case AlgorithmSlidingWindow:
		limiter, limiterErr := windowcounter.New(redis, settings.SyncRate)
		if limiterErr != nil {
			redis.Close()
			return nil, fmt.Errorf("ratelimit: %w", limiterErr)
		}
		client.counter = &slidingWindowCounter{limiter: limiter}
		client.limiter = limiter
	case AlgorithmTokenBucket:
		counter, counterErr := newTokenBucketCounter(redis, buckets)
		if counterErr != nil {
			redis.Close()
			return nil, fmt.Errorf("ratelimit: %w", counterErr)
		}
		client.counter = counter
	default:
		redis.Close()
		return nil, fmt.Errorf("ratelimit: unknown algorithm %q", algorithm)
	}
	client.incarnation = fmt.Sprintf("%p", client)
	log.Info(msgInstanceStarted, "incarnation", client.incarnation, "reason", "started", "algorithm", algorithm, "syncRate", settings.SyncRate.String())
	return client, nil
}

// Buckets is the owner's compiled bucket list every subscriber charges.
func (c *Client) Buckets() *BucketSet {
	return c.buckets
}

// Policy is the owner's failure action, status code, and Retry-After switch every subscriber answers with.
func (c *Client) Policy() Policy {
	return c.policy
}

// Incarnation identifies this Client in lifecycle and bind traces. Empty on a nil Client.
func (c *Client) Incarnation() string {
	if c == nil {
		return ""
	}
	return c.incarnation
}

// Take counts one hit on key with the owner's algorithm and returns whether it is within limit, with
// RetryAfter on a deny (Counter).
func (c *Client) Take(ctx context.Context, key string, limit Limit) (Status, error) {
	return c.counter.Take(ctx, key, limit)
}

// Sleep flushes buffered sliding-window hits and stops the flush timer when the last holder leaves.
// The token bucket has nothing to flush.
func (c *Client) Sleep() {
	if c.limiter != nil {
		c.limiter.Sleep()
	}
	c.log.Debug(msgInstanceSleeping, "incarnation", c.incarnation, "reason", "sleeping")
}

// Wake restarts the sliding window's flush timer when a holder binds again during the table grace.
func (c *Client) Wake() {
	if c.limiter != nil {
		c.limiter.Wake()
	}
	c.log.Debug(msgInstanceWaking, "incarnation", c.incarnation, "reason", "waking")
}

// Close closes the sliding-window limiter, if any (a last flush), and then the Redis client every
// counter writes through. Safe to call more than once.
func (c *Client) Close() {
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		return
	}
	c.closed = true
	c.mu.Unlock()
	if c.limiter != nil {
		c.limiter.Close()
	}
	c.redis.Close()
	c.log.Info(msgInstanceClosed, "incarnation", c.incarnation, "reason", "closed")
}
