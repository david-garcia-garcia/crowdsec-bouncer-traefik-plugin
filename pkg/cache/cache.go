// Package cache implements utility routines for manipulating cache.
// It supports currently local file and redis cache.
package cache

import (
	"context"
	"errors"
	"fmt"
	"time"

	ttl_map "github.com/leprosus/golang-ttl-map"
	"github.com/redis/go-redis/v9"

	logger "github.com/maxlerebourg/crowdsec-bouncer-traefik-plugin/pkg/logger"
)

const (
	// BannedValue Banned string.
	BannedValue = "t"
	// NoBannedValue No banned string.
	NoBannedValue = "f"
	// CaptchaValue Need captcha string.
	CaptchaValue = "c"
	// CaptchaDoneValue Captcha done string.
	CaptchaDoneValue = "d"
	// CacheMiss error string when cache is miss.
	CacheMiss = "cache:miss"
	// CacheUnreachable error string when cache is unreachable.
	CacheUnreachable = "cache:unreachable"
)

//nolint:gochecknoglobals
var (
	redisClient *redis.Client
	cache       = ttl_map.New()
)

type localCache struct{}

func (localCache) get(ctx context.Context, key string) (string, error) {
	value, isCached := cache.Get(key)
	valueString, isValid := value.(string)
	if isCached && isValid && len(valueString) > 0 {
		return valueString, nil
	}
	return "", errors.New(CacheMiss)
}

func (localCache) set(ctx context.Context, key, value string, duration int64) {
	cache.Set(key, value, duration)
}

func (localCache) delete(ctx context.Context, key string) {
	cache.Del(key)
}

type redisCache struct {
	log *logger.Log
}

func (redisCache) get(ctx context.Context, key string) (string, error) {
	if redisClient == nil {
		return "", errors.New(CacheUnreachable)
	}

	value, err := redisClient.Get(ctx, key).Result()
	if err != nil {
		if err == redis.Nil {
			return "", errors.New(CacheMiss)
		}
		// Check if it's a connection error
		if err.Error() == "redis: client is closed" ||
			err.Error() == "dial tcp: lookup" ||
			err.Error() == "connection refused" ||
			err.Error() == "i/o timeout" {
			return "", errors.New(CacheUnreachable)
		}
		return "", errors.New(CacheUnreachable)
	}

	if len(value) > 0 {
		return value, nil
	}
	return "", errors.New(CacheMiss)
}

func (rc redisCache) set(ctx context.Context, key, value string, duration int64) {
	if redisClient == nil {
		rc.log.Error("cache:setDecisionRedisCache redis client not initialized")
		return
	}

	expiration := time.Duration(duration) * time.Second
	if err := redisClient.Set(ctx, key, value, expiration).Err(); err != nil {
		rc.log.Error("cache:setDecisionRedisCache " + err.Error())
	}
}

func (rc redisCache) delete(ctx context.Context, key string) {
	if redisClient == nil {
		rc.log.Error("cache:deleteDecisionRedisCache redis client not initialized")
		return
	}

	if err := redisClient.Del(ctx, key).Err(); err != nil {
		rc.log.Error("cache:deleteDecisionRedisCache " + err.Error())
	}
}

type cacheInterface interface {
	set(ctx context.Context, key, value string, duration int64)
	get(ctx context.Context, key string) (string, error)
	delete(ctx context.Context, key string)
}

// Client Cache client.
type Client struct {
	cache cacheInterface
	log   *logger.Log
}

// New Initialize cache client.
func (c *Client) New(log *logger.Log, isRedis bool, host, pass string, database int) {
	c.log = log
	if isRedis {
		redisClient = redis.NewClient(&redis.Options{
			Addr:     host,
			Password: pass,
			DB:       database,
		})

		// Test connection using background context only for initialization
		ctx := context.Background()
		_, err := redisClient.Ping(ctx).Result()
		if err != nil {
			c.log.Error("cache:New redis connection failed: " + err.Error())
		} else {
			c.log.Debug("cache:New redis connection successful")
		}

		c.cache = &redisCache{log: log}
	} else {
		c.cache = &localCache{}
	}
	c.log.Debug(fmt.Sprintf("cache:New initialized isRedis:%v", isRedis))
}

// Delete delete decision in cache.
func (c *Client) Delete(ctx context.Context, key string) {
	c.log.Trace(fmt.Sprintf("cache:Delete key:%v", key))
	c.cache.delete(ctx, key)
}

// Get check in the cache if the IP has the banned / not banned value.
// Otherwise return with an error to add the IP in cache if we are on.
func (c *Client) Get(ctx context.Context, key string) (string, error) {
	c.log.Trace(fmt.Sprintf("cache:Get key:%v", key))
	return c.cache.get(ctx, key)
}

// Set update the cache with the IP as key and the value banned / not banned.
func (c *Client) Set(ctx context.Context, key string, value string, duration int64) {
	c.log.Trace(fmt.Sprintf("cache:Set key:%v value:%v duration:%vs", key, value, duration))
	c.cache.set(ctx, key, value, duration)
}
