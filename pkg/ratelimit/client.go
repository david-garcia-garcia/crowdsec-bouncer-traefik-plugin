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

// RedisSettings are the values that pick one rate-limit Client: the Redis server, the resolved
// password, the database, and the sync rate. Bucket rows and per-router answers are not part of it.
type RedisSettings struct {
	Database string        `json:"database"`
	Host     string        `json:"host"`
	Password string        `json:"password"`
	SyncRate time.Duration `json:"syncRate"`
}

// Client is the reclaim value of the rate-limit leg: one sliding-window counter and the Redis client
// it writes through, shared by every router of one middleware with the same RedisSettings.
type Client struct {
	closed      bool
	incarnation string
	limiter     *windowcounter.Limiter
	log         *slog.Logger
	mu          sync.Mutex
	redis       *simpleredis.SimpleRedis
}

// OwnershipKey is the reclaim-table key for the Client of middlewareName with settings.
func OwnershipKey(middlewareName string, settings RedisSettings) string {
	payload := struct {
		MiddlewareName string        `json:"middlewareName"`
		Settings       RedisSettings `json:"settings"`
	}{MiddlewareName: middlewareName, Settings: settings}
	encoded, err := json.Marshal(payload)
	if err != nil {
		encoded = []byte(fmt.Sprint(payload))
	}
	hasher := fnv.New64a()
	_, _ = hasher.Write(encoded)
	return ownerKeyPrefix + strconv.FormatUint(hasher.Sum64(), 16)
}

// Open returns the Client held under OwnershipKey(middlewareName, settings), creating it on a first
// put. ctx is the holder lease: when it ends, the Client sleeps, then closes after the table grace.
// Open does not dial; an unreachable Redis is a request-time error.
func Open(ctx context.Context, middlewareName string, settings RedisSettings, log *slog.Logger) (*Client, error) {
	key := OwnershipKey(middlewareName, settings)
	stored, err := reclaim.OpenWithHooks(ctx, key, log, func() (any, reclaim.Hooks, error) {
		client, err := newClient(settings, log.With("traefikName", middlewareName, "leg", "ratelimit", "sessionKey", key))
		if err != nil {
			return nil, reclaim.Hooks{}, err
		}
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

// newClient builds the Redis client and the sliding-window counter on it. It does not dial.
func newClient(settings RedisSettings, log *slog.Logger) (*Client, error) {
	redis, err := simpleredis.New(simpleredis.Config{
		Host:           settings.Host,
		Pass:           settings.Password,
		Database:       settings.Database,
		PoolSize:       redisPoolSize,
		MaxIdleConns:   redisPoolSize,
		IdleTimeout:    redisIdleTimeout,
		DialTimeout:    redisDialTimeout,
		CommandTimeout: StepBudget,
		Logger:         log,
	})
	if err != nil {
		return nil, fmt.Errorf("ratelimit: redis: %w", err)
	}
	limiter, err := windowcounter.New(redis, settings.SyncRate)
	if err != nil {
		redis.Close()
		return nil, fmt.Errorf("ratelimit: %w", err)
	}
	client := &Client{limiter: limiter, log: log, redis: redis}
	client.incarnation = fmt.Sprintf("%p", client)
	log.Info(msgInstanceStarted, "incarnation", client.incarnation, "reason", "started", "syncRate", settings.SyncRate.String())
	return client, nil
}

// Take counts one hit on key and reports whether it is within limit per window (Counter).
func (c *Client) Take(ctx context.Context, key string, limit int64, window time.Duration) (allowed bool, estimated float64, err error) {
	return c.limiter.Take(ctx, key, limit, window)
}

// Sleep flushes buffered hits and stops the flush timer when the last holder leaves.
func (c *Client) Sleep() {
	c.limiter.Sleep()
	c.log.Debug(msgInstanceSleeping, "incarnation", c.incarnation, "reason", "sleeping")
}

// Wake restarts the flush timer when a holder binds again during the table grace.
func (c *Client) Wake() {
	c.limiter.Wake()
	c.log.Debug(msgInstanceWaking, "incarnation", c.incarnation, "reason", "waking")
}

// Close closes the counter (a last flush) and then the Redis client it does not own. Safe to call more than once.
func (c *Client) Close() {
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		return
	}
	c.closed = true
	c.mu.Unlock()
	c.limiter.Close()
	c.redis.Close()
	c.log.Info(msgInstanceClosed, "incarnation", c.incarnation, "reason", "closed")
}
