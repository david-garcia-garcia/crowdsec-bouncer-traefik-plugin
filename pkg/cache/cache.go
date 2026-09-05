// Package cache implements utility routines for manipulating cache.
// It supports currently local file and redis cache.
package cache

import (
	"errors"
	"fmt"
	"log/slog"
	"sync/atomic"

	ttl_map "github.com/leprosus/golang-ttl-map"
	simpleredis "github.com/maxlerebourg/crowdsec-bouncer-traefik-plugin/pkg/simpleredis"
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

// localCache is the per-Client in-memory TTL store.
type localCache struct {
	store *ttl_map.Heap
}

func (lc *localCache) heap() *ttl_map.Heap {
	if lc.store == nil {
		lc.store = ttl_map.New()
	}
	return lc.store
}

func (lc *localCache) get(key string) (string, error) {
	value, isCached := lc.heap().Get(key)
	valueString, isValid := value.(string)
	if isCached && isValid && len(valueString) > 0 {
		return valueString, nil
	}
	return "", errors.New(CacheMiss)
}

func (lc *localCache) set(key, value string, duration int64) {
	lc.heap().Set(key, value, duration)
}

func (lc *localCache) delete(key string) {
	lc.heap().Del(key)
}

// prefixed namespaces Redis keys so two Clients on one host do not share remediations.
func prefixed(prefix, key string) string {
	if prefix == "" {
		return key
	}
	return prefix + ":" + key
}

type redisCache struct {
	log     *slog.Logger
	prefix  string
	writer  *simpleredis.SimpleRedis
	readers []*simpleredis.SimpleRedis
	counter atomic.Uint64
}

func (rc *redisCache) nextReader() *simpleredis.SimpleRedis {
	n := len(rc.readers)
	if n == 0 {
		return rc.writer
	}
	idx := rc.counter.Add(1) % uint64(n)
	return rc.readers[idx]
}

func (rc *redisCache) get(key string) (string, error) {
	value, err := rc.nextReader().Get(prefixed(rc.prefix, key))
	if err != nil {
		switch err.Error() {
		case simpleredis.RedisMiss:
			return "", errors.New(CacheMiss)
		case simpleredis.RedisUnreachable:
			return "", errors.New(CacheUnreachable)
		default:
			return "", err
		}
	}
	valueString := string(value)
	if len(valueString) > 0 {
		return valueString, nil
	}
	return "", errors.New(CacheMiss)
}

func (rc *redisCache) set(key, value string, duration int64) {
	if err := rc.writer.Set(prefixed(rc.prefix, key), []byte(value), duration); err != nil {
		rc.log.Error("cache:setDecisionRedisCache" + err.Error())
	}
}

func (rc *redisCache) delete(key string) {
	if err := rc.writer.Del(prefixed(rc.prefix, key)); err != nil {
		rc.log.Error("cache:deleteDecisionRedisCache " + err.Error())
	}
}

type cacheInterface interface {
	set(key, value string, duration int64)
	get(key string) (string, error)
	delete(key string)
}

// Client Cache client.
type Client struct {
	cache cacheInterface
	log   *slog.Logger
}

// New Initialize cache client. keyPrefix namespaces Redis keys; memory clients ignore it and each own a map.
func (c *Client) New(log *slog.Logger, isRedis bool, writeHost string, readHosts []string, pass, database, keyPrefix string) {
	c.log = log
	if isRedis {
		rc := &redisCache{log: log, prefix: keyPrefix}
		// Hold each client by pointer after Init so the pool mutex is not copied.
		rc.writer = &simpleredis.SimpleRedis{}
		rc.writer.Init(writeHost, pass, database)
		for _, h := range readHosts {
			r := &simpleredis.SimpleRedis{}
			r.Init(h, pass, database)
			rc.readers = append(rc.readers, r)
		}
		c.cache = rc
	} else {
		c.cache = &localCache{store: ttl_map.New()}
	}
	c.log.Debug(fmt.Sprintf("cache:New initialized isRedis:%v writeHost:%v readHosts:%v prefix:%v", isRedis, writeHost, readHosts, keyPrefix))
}

// Delete delete decision in cache.
func (c *Client) Delete(key string) {
	c.log.Debug(fmt.Sprintf("cache:Delete key:%v", key))
	c.cache.delete(key)
}

// Get check in the cache if the IP has the banned / not banned value.
// Otherwise return with an error to add the IP in cache if we are on.
func (c *Client) Get(key string) (string, error) {
	c.log.Debug(fmt.Sprintf("cache:Get key:%v", key))
	return c.cache.get(key)
}

// Set update the cache with the IP as key and the value banned / not banned.
func (c *Client) Set(key string, value string, duration int64) {
	c.log.Debug(fmt.Sprintf("cache:Set key:%v value:%v duration:%vs", key, value, duration))
	c.cache.set(key, value, duration)
}
