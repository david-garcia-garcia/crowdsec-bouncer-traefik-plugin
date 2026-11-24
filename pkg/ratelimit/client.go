package ratelimit

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"hash/fnv"
	"log/slog"
	"strconv"
	"sync"
	"time"

	"github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pkg/admission"
	"github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pkg/logger"
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
	// gateKey is the admission leg name and gate key.
	gateKey = "ratelimit"
	// redisUnavailableInterval is how often MsgRedisUnavailable may repeat, as for ModSec's MsgUnavailable.
	redisUnavailableInterval = 5 * time.Second
)

const (
	// MsgBackoffStarted is the WARN line when the admission gate starts skipping the rate-limit Redis.
	MsgBackoffStarted = "crowdsec ratelimit backoff started"
	// MsgBackoffEnded is the INFO line when a Redis probe succeeds after a backoff.
	MsgBackoffEnded = "crowdsec ratelimit backoff ended"
	// MsgRedisUnavailable is the debounced ERROR line when a counter error reaches the plugin.
	MsgRedisUnavailable = "crowdsec ratelimit redis unavailable"
)

// ErrGateSkip means the admission gate is backing off and Redis was not called. The subscriber answers
// with the owner's BackOffAction, not its FailureAction.
var ErrGateSkip = errors.New("ratelimit:unhealthySkip")

// Log messages of the Client lifecycle, matching the other legs.
const (
	msgInstanceStarted  = "crowdsec ratelimit instance started"
	msgInstanceSleeping = "crowdsec ratelimit instance sleeping"
	msgInstanceWaking   = "crowdsec ratelimit instance waking"
	msgInstanceClosed   = "crowdsec ratelimit instance closed"
	// msgFailureActionBuffered is the WARN line of an owner whose blocking failure or backoff action a
	// Redis outage cannot reach.
	msgFailureActionBuffered = "crowdsec ratelimit failure action does not apply to a redis outage"
)

// The actions warnBufferedFailureAction reads (configuration.FailureAction*; configuration imports this
// package).
const (
	failureActionBan     = "ban"
	failureActionCaptcha = "captcha"
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
// errors, the backoff action while the gate skips Redis, the status of a rate-limited request, and whether
// it carries Retry-After.
type Policy struct {
	BackOffAction   string `json:"backOffAction"`
	FailureAction   string `json:"failureAction"`
	ResponseHeaders bool   `json:"responseHeaders"`
	StatusCode      int    `json:"statusCode"`
}

// Settings are everything the owner (rateLimitEnabled) puts on its Client: the counting algorithm
// (empty means AlgorithmSlidingWindow), the Redis counter, the bucket rows, the policy, the cooldown of the
// Redis admission gate (0 or less builds none), and the instance name it is published under (logs only,
// not the key).
type Settings struct {
	Algorithm         string
	BackOffPeriodSecs int64
	Buckets           []BucketRule
	InstanceName      string
	Policy            Policy
	Redis             RedisSettings
}

// Client is the reclaim value of the rate-limit leg: the counter of the owner's algorithm (a sliding
// window, or one token bucket per bucket), the Redis client it writes through, and the owner's compiled
// buckets and policy. It is published under the owner's instance name, and every subscribing router
// charges its buckets and answers with its policy.
type Client struct {
	buckets     *BucketSet
	closed      bool
	counter     Counter         // what Take charges: the algorithm's counter, or a fake on a NewTestClient
	gate        *admission.Gate // skips Redis after repeated failures; nil when off, buffered, or a NewTestClient
	host        string          // the Redis host, for MsgRedisUnavailable
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
		Algorithm         string        `json:"algorithm"`
		BackOffPeriodSecs int64         `json:"backOffPeriodSecs"`
		Buckets           []BucketRule  `json:"buckets"`
		MiddlewareName    string        `json:"middlewareName"`
		Policy            Policy        `json:"policy"`
		Redis             RedisSettings `json:"redis"`
	}{
		Algorithm:         EffectiveAlgorithm(settings.Algorithm),
		BackOffPeriodSecs: settings.BackOffPeriodSecs,
		Buckets:           settings.Buckets,
		MiddlewareName:    middlewareName,
		Policy:            settings.Policy,
		Redis:             settings.Redis,
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
		client, err := newClient(settings.Redis, EffectiveAlgorithm(settings.Algorithm), settings.BackOffPeriodSecs, buckets, clientLog)
		if err != nil {
			return nil, reclaim.Hooks{}, err
		}
		client.policy = settings.Policy
		warnBufferedFailureAction(clientLog, settings)
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
// limiter with the sync rate, or one token bucket per bucket. When gateApplies, it also builds the
// admission gate with backOffPeriodSecs (0 or less builds none). It does not dial.
func newClient(settings RedisSettings, algorithm string, backOffPeriodSecs int64, buckets *BucketSet, log *slog.Logger) (*Client, error) {
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
	client := &Client{buckets: buckets, host: settings.Host, log: log, redis: redis}
	if gateApplies(algorithm, settings.SyncRate) {
		gate, gateErr := admission.New(admission.Config{
			Leg:        gateKey,
			PeriodSecs: backOffPeriodSecs,
			MsgStarted: MsgBackoffStarted,
			MsgEnded:   MsgBackoffEnded,
		}, log)
		if gateErr != nil {
			redis.Close()
			return nil, gateErr
		}
		client.gate = gate
	}
	// The counter of the owner's algorithm, on the one Redis client.
	switch algorithm {
	case AlgorithmSlidingWindow:
		limiter, limiterErr := windowcounter.New(redis, settings.SyncRate)
		if limiterErr != nil {
			client.gate.Close()
			redis.Close()
			return nil, fmt.Errorf("ratelimit: %w", limiterErr)
		}
		client.counter = &slidingWindowCounter{limiter: limiter}
		client.limiter = limiter
	case AlgorithmTokenBucket:
		counter, counterErr := newTokenBucketCounter(redis, buckets)
		if counterErr != nil {
			client.gate.Close()
			redis.Close()
			return nil, fmt.Errorf("ratelimit: %w", counterErr)
		}
		client.counter = counter
	default:
		client.gate.Close()
		redis.Close()
		return nil, fmt.Errorf("ratelimit: unknown algorithm %q", algorithm)
	}
	client.incarnation = fmt.Sprintf("%p", client)
	log.Info(msgInstanceStarted, "incarnation", client.incarnation, "reason", "started", "algorithm", algorithm,
		"syncRate", settings.SyncRate.String(), "backOffPeriodSecs", backOffPeriodSecs, "gate", client.gate != nil)
	return client, nil
}

// gateApplies reports whether a counter of algorithm with syncRate calls Redis before answering, so a
// success proves Redis answered and the admission gate can end a backoff on it: the token bucket and the
// exact sliding window (syncRate 0). The buffered sliding window answers an outage from each replica's
// local count with no error and already skips Redis for one sync interval after a failure: a gate there
// would see no outage and could end a backoff on a local count.
func gateApplies(algorithm string, syncRate time.Duration) bool {
	return algorithm == AlgorithmTokenBucket || syncRate <= 0
}

// warnBufferedFailureAction logs WARN msgFailureActionBuffered once, when the Client is created, for a
// failure or backoff action that blocks (ban or captcha) on the buffered sliding window: that limiter
// answers a Redis outage from each replica's local count with no error, so the failure action applies
// only to a bucket reached after StepBudget, and there is no gate for the backoff action (gateApplies).
// The configuration is accepted.
func warnBufferedFailureAction(log *slog.Logger, settings Settings) {
	if gateApplies(EffectiveAlgorithm(settings.Algorithm), settings.Redis.SyncRate) {
		return
	}
	if !blocks(settings.Policy.FailureAction) && !blocks(settings.Policy.BackOffAction) {
		return
	}
	log.Warn(msgFailureActionBuffered, "failureAction", settings.Policy.FailureAction,
		"backOffAction", settings.Policy.BackOffAction,
		"algorithm", AlgorithmSlidingWindow, "syncRate", settings.Redis.SyncRate.String(),
		"detail", "while Redis is down each replica counts locally; the failure action applies only to a bucket reached after the 250ms budget, and the backoff action never applies",
		"hint", "set rateLimitSyncRate: 0 or rateLimitAlgorithm: tokenBucket to apply them")
}

// blocks reports whether action answers instead of letting the request through.
func blocks(action string) bool {
	return action == failureActionBan || action == failureActionCaptcha
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
// RetryAfter on a deny (Counter). While the admission gate backs off it calls no Redis and returns
// ErrGateSkip. A counter error is reported to the gate and logs MsgRedisUnavailable, debounced; a canceled
// request is neither reported nor logged.
func (c *Client) Take(ctx context.Context, key string, limit Limit) (Status, error) {
	ticket, err := c.gate.Admit(ctx)
	if err != nil {
		return Status{}, err
	}
	if !ticket.Admitted {
		return Status{}, ErrGateSkip
	}
	status, err := c.counter.Take(ctx, key, limit)
	if err != nil && (errors.Is(err, context.Canceled) || errors.Is(ctx.Err(), context.Canceled)) {
		return status, err
	}
	c.gate.Record(ticket, err == nil)
	if err != nil && c.log != nil {
		logger.Debounced(c.log, slog.LevelError, redisUnavailableInterval, MsgRedisUnavailable, "host", c.host, "error", err)
	}
	return status, err
}

// GateForTest is the admission gate, or nil when there is none.
func (c *Client) GateForTest() *admission.Gate {
	return c.gate
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
	c.gate.Close()
	c.redis.Close()
	c.log.Info(msgInstanceClosed, "incarnation", c.incarnation, "reason", "closed")
}
