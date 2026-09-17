// Package cache implements an in-process TTL map for CrowdSec remediations.
package cache

import (
	"errors"
	"fmt"
	"log/slog"

	ttl_map "github.com/leprosus/golang-ttl-map"
)

const (
	// CacheMiss error string when cache is miss.
	CacheMiss = "cache:miss"
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

func (lc *localCache) getMany(keys []string) (map[string]string, error) {
	out := make(map[string]string)
	for _, key := range keys {
		if key == "" {
			continue
		}
		value, err := lc.get(key)
		if err == nil {
			out[key] = value
		}
	}
	return out, nil
}

func (lc *localCache) set(key, value string, duration int64) {
	lc.heap().Set(key, value, duration)
}

func (lc *localCache) delete(key string) {
	lc.heap().Del(key)
}

// close is a no-op: the TTL map has no sockets or background goroutine.
func (lc *localCache) close() {}

type cacheInterface interface {
	set(key, value string, duration int64)
	get(key string) (string, error)
	getMany(keys []string) (map[string]string, error)
	delete(key string)
	close()
}

// Client Cache client.
type Client struct {
	cache cacheInterface
	log   *slog.Logger
}

// New initializes an in-memory cache client owned by one LAPI Client.
func (c *Client) New(log *slog.Logger) {
	c.log = log
	c.cache = &localCache{store: ttl_map.New()}
	c.log.Debug("cache:New initialized memory-only")
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

// GetMany returns the values for the given keys. Missing keys are omitted.
func (c *Client) GetMany(keys []string) (map[string]string, error) {
	c.log.Debug(fmt.Sprintf("cache:GetMany keys:%v", keys))
	return c.cache.getMany(keys)
}

// Set update the cache with the IP as key and the value banned / not banned.
func (c *Client) Set(key string, value string, duration int64) {
	c.log.Debug(fmt.Sprintf("cache:Set key:%v value:%v duration:%vs", key, value, duration))
	c.cache.set(key, value, duration)
}

// Close is a no-op for memory clients. Safe to call more than once.
func (c *Client) Close() {
	if c == nil || c.cache == nil {
		return
	}
	c.cache.close()
}
