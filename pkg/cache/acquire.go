package cache

import (
	"context"
	"errors"
	"strconv"

	simpleredis "github.com/david-garcia-garcia/traefik-middleware-utilities/simpleredis"
)

// acquireLeaseScript sets KEYS[1] only when absent (SET EX). Returns 1 on win, 0 on miss.
// Lua 5.1-safe for Dragonfly: numeric for, no unpack. Digest is ScriptSHA1Hex of this body at each Eval.
const acquireLeaseScript = `if redis.call('EXISTS', KEYS[1]) == 0 then
redis.call('SET', KEYS[1], ARGV[1], 'EX', tonumber(ARGV[2]))
return 1
end
return 0`

// Acquire tries to own key for duration seconds. Redis uses one Eval (EVALSHA, then EVAL on NOSCRIPT).
// Memory locks around miss+Set. No poller logic. No SetNX wrapper. Caller owns the TTL floor.
func (c *Client) Acquire(ctx context.Context, key, value string, duration int64) (bool, error) {
	if c == nil || c.cache == nil {
		return false, errors.New(CacheUnreachable)
	}
	if ctx == nil {
		ctx = context.Background()
	}
	c.log.Debug("cache:Acquire key:" + key)
	return c.cache.acquire(ctx, key, value, duration)
}

// acquire locks miss+Set so two goroutines cannot both treat an empty key as a win.
func (lc *localCache) acquire(_ context.Context, key, value string, duration int64) (bool, error) {
	lc.mu.Lock()
	defer lc.mu.Unlock()
	_, err := lc.get(key)
	if err == nil {
		return false, nil
	}
	if err.Error() != CacheMiss {
		return false, err
	}
	lc.set(key, value, duration)
	return true, nil
}

// acquire runs SET-if-absent on the writer with the prefixed key. Readers are not used.
func (rc *redisCache) acquire(ctx context.Context, key, value string, duration int64) (bool, error) {
	if rc.writer == nil {
		return false, errors.New(CacheUnreachable)
	}
	values, err := rc.writer.Eval(
		ctx,
		acquireLeaseScript,
		simpleredis.ScriptSHA1Hex(acquireLeaseScript),
		[]string{prefixed(rc.prefix, key)},
		[]string{value, strconv.FormatInt(duration, 10)},
	)
	if err != nil {
		if simpleredis.IsUnreachable(err) {
			return false, errors.New(CacheUnreachable)
		}
		return false, err
	}
	// Lua returns integer 1 or 0; SimpleRedis surfaces that as one decimal slot.
	if len(values) != 1 {
		return false, errors.New(CacheUnreachable)
	}
	won, convErr := strconv.ParseInt(string(values[0]), 10, 64)
	if convErr != nil {
		return false, errors.New(CacheUnreachable)
	}
	return won == 1, nil
}
