// Package cache implements utility routines for manipulating cache.
// It supports currently local file and redis cache.
package cache

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"sync"
	"sync/atomic"
	"time"

	simpleredis "github.com/david-garcia-garcia/traefik-middleware-utilities/simpleredis"
	ttl_map "github.com/leprosus/golang-ttl-map"
)

const (
	// CacheMiss error string when cache is miss.
	CacheMiss = "cache:miss"
	// CacheUnreachable error string when cache is unreachable.
	CacheUnreachable = "cache:unreachable"
	// CacheBadTTL error string when a write was asked for a non-positive lifetime.
	CacheBadTTL = "cache:bad-ttl"
)

const (
	// writerPinWindow is how long a key that was just written reads from the Redis writer instead
	// of the read replicas. It bounds the read-your-writes window; it does not abolish staleness,
	// and a replica lagging longer than this is a broken deployment. Five seconds is an order of
	// magnitude above healthy replication lag and short against the 60s default update interval.
	writerPinWindow = 5 * time.Second
	// writerPinMaxKeys caps the pinned-key set. A burst past the cap - a startup=true stream pull
	// is exactly that - pins every read for the window instead of dropping keys and serving stale.
	writerPinMaxKeys = 4096
)

// localCache is the per-store in-memory TTL map.
type localCache struct {
	mu    sync.Mutex // acquire serializes miss+Set; vendored Heap Get and Set lock separately
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

// getConsistent is get: one in-process map has no replicas to lag behind it.
func (lc *localCache) getConsistent(key string) (string, error) {
	return lc.get(key)
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
			continue
		}
		if err.Error() == CacheUnreachable {
			return nil, err
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

	// pinMu guards the pinned set and pinAllUntil, the read-your-writes bookkeeping.
	pinMu       sync.Mutex
	pinned      map[string]int64
	pinAllUntil int64
	// pinWindow overrides writerPinWindow. Zero means the constant; only tests set it.
	pinWindow time.Duration
}

func (rc *redisCache) nextReader() *simpleredis.SimpleRedis {
	n := len(rc.readers)
	if n == 0 {
		return rc.writer
	}
	idx := rc.counter.Add(1) % uint64(n)
	return rc.readers[idx]
}

// readerFor picks the writer while any of keys is still inside its pin window, so a value this
// process just wrote is never read back from a replica that has not received it yet. Everything
// else keeps the round-robin, which is what the read hosts are for.
func (rc *redisCache) readerFor(keys []string) *simpleredis.SimpleRedis {
	if len(rc.readers) == 0 {
		return rc.writer
	}
	if rc.isPinned(keys) {
		return rc.writer
	}
	return rc.nextReader()
}

func (rc *redisCache) isPinned(keys []string) bool {
	now := time.Now().UnixNano()
	rc.pinMu.Lock()
	defer rc.pinMu.Unlock()
	if now < rc.pinAllUntil {
		return true
	}
	for _, key := range keys {
		if now < rc.pinned[key] {
			return true
		}
	}
	return false
}

// pin routes later reads of key to the writer for the pin window. Callers pin before the write
// goes out, so a read taken while that write is still in flight also lands on the writer.
func (rc *redisCache) pin(key string) {
	if len(rc.readers) == 0 {
		return
	}
	now := time.Now()
	deadline := now.Add(rc.window()).UnixNano()
	rc.pinMu.Lock()
	defer rc.pinMu.Unlock()
	if len(rc.pinned) >= writerPinMaxKeys {
		rc.dropExpiredPins(now.UnixNano())
	}
	if len(rc.pinned) >= writerPinMaxKeys {
		// Overflow fails toward the writer, never toward a stale replica.
		rc.pinAllUntil = deadline
		rc.pinned = nil
		return
	}
	if rc.pinned == nil {
		rc.pinned = make(map[string]int64)
	}
	rc.pinned[key] = deadline
}

// dropExpiredPins removes keys whose window has elapsed. Caller holds pinMu.
func (rc *redisCache) dropExpiredPins(now int64) {
	for key, deadline := range rc.pinned {
		if now >= deadline {
			delete(rc.pinned, key)
		}
	}
}

func (rc *redisCache) window() time.Duration {
	if rc.pinWindow > 0 {
		return rc.pinWindow
	}
	return writerPinWindow
}

func (rc *redisCache) get(key string) (string, error) {
	return rc.getFrom(rc.readerFor([]string{key}), key)
}

// getConsistent reads the writer, whatever the pin window says. It is for a read-modify-write and
// for a read whose staleness would change the remediation served for longer than that window.
func (rc *redisCache) getConsistent(key string) (string, error) {
	return rc.getFrom(rc.writer, key)
}

func (rc *redisCache) getFrom(from *simpleredis.SimpleRedis, key string) (string, error) {
	value, err := from.Get(context.Background(), prefixed(rc.prefix, key))
	if err != nil {
		if simpleredis.IsMiss(err) {
			return "", errors.New(CacheMiss)
		}
		if simpleredis.IsUnreachable(err) {
			return "", errors.New(CacheUnreachable)
		}
		return "", err
	}
	valueString := string(value)
	if len(valueString) > 0 {
		return valueString, nil
	}
	return "", errors.New(CacheMiss)
}

func (rc *redisCache) getMany(keys []string) (map[string]string, error) {
	logical := make([]string, 0, len(keys))
	prefixedNames := make([]string, 0, len(keys))
	for _, key := range keys {
		if key == "" {
			continue
		}
		logical = append(logical, key)
		prefixedNames = append(prefixedNames, prefixed(rc.prefix, key))
	}
	if len(prefixedNames) == 0 {
		return map[string]string{}, nil
	}
	values, err := rc.readerFor(logical).MGet(context.Background(), prefixedNames)
	if err != nil {
		if simpleredis.IsUnreachable(err) {
			return nil, errors.New(CacheUnreachable)
		}
		return nil, err
	}
	out := make(map[string]string)
	for i, key := range logical {
		if i >= len(values) || values[i] == nil || len(values[i]) == 0 {
			continue
		}
		out[key] = string(values[i])
	}
	return out, nil
}

func (rc *redisCache) set(key, value string, duration int64) {
	rc.pin(key)
	if err := rc.writer.Set(context.Background(), prefixed(rc.prefix, key), []byte(value), duration); err != nil {
		rc.log.Error("cache:setDecisionRedisCache" + err.Error())
	}
}

func (rc *redisCache) delete(key string) {
	rc.pin(key)
	if err := rc.writer.Del(context.Background(), prefixed(rc.prefix, key)); err != nil {
		rc.log.Error("cache:deleteDecisionRedisCache " + err.Error())
	}
}

// close drains the writer and every reader idle pool.
func (rc *redisCache) close() {
	if rc.writer != nil {
		rc.writer.Close()
	}
	for _, reader := range rc.readers {
		reader.Close()
	}
}

type cacheInterface interface {
	set(key, value string, duration int64)
	get(key string) (string, error)
	getConsistent(key string) (string, error)
	getMany(keys []string) (map[string]string, error)
	delete(key string)
	acquire(ctx context.Context, key, value string, duration int64) (bool, error)
	close()
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
		// Hold each client by pointer after New so the pool mutex is not copied.
		writer, err := simpleredis.New(redisClientConfig(writeHost, pass, database, log))
		if err != nil {
			log.Error("cache:New writer " + err.Error())
			return
		}
		rc.writer = writer
		for _, h := range readHosts {
			reader, readerErr := simpleredis.New(redisClientConfig(h, pass, database, log))
			if readerErr != nil {
				log.Error("cache:New reader " + readerErr.Error())
				continue
			}
			rc.readers = append(rc.readers, reader)
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

// GetConsistent reads the authoritative copy, bypassing the Redis read replicas and the pin
// window. Use it for a read-modify-write of a shared value, and for a read whose staleness keeps
// changing the remediation served after the pin window has elapsed. Memory clients are unaffected.
func (c *Client) GetConsistent(key string) (string, error) {
	c.log.Debug(fmt.Sprintf("cache:GetConsistent key:%v", key))
	return c.cache.getConsistent(key)
}

// GetMany returns the values for the given keys. Missing keys are omitted.
// Redis issues one MGET on a single reader. Unreachable returns CacheUnreachable.
func (c *Client) GetMany(keys []string) (map[string]string, error) {
	c.log.Debug(fmt.Sprintf("cache:GetMany keys:%v", keys))
	return c.cache.getMany(keys)
}

// Set update the cache with the IP as key and the value banned / not banned.
// A non-positive duration is a no-op: the in-memory backend stored it as an entry that never
// expires, so a cached ban outlived the decision that justified it, and Redis rejected the write
// outright. Neither is a lifetime any caller asked for.
func (c *Client) Set(key string, value string, duration int64) {
	c.log.Debug(fmt.Sprintf("cache:Set key:%v value:%v duration:%vs", key, value, duration))
	if duration <= 0 {
		c.log.Debug(fmt.Sprintf("cache:Set skipped key:%v duration:%vs is not a lifetime", key, duration))
		return
	}
	c.cache.set(key, value, duration)
}

// redisClientConfig keeps this plugin’s dial 2s and command 1s (not utilities zero-Config defaults).
func redisClientConfig(host, pass, database string, log *slog.Logger) simpleredis.Config {
	return simpleredis.Config{
		Host:           host,
		Pass:           pass,
		Database:       database,
		DialTimeout:    2 * time.Second,
		CommandTimeout: time.Second,
		IdleTimeout:    30 * time.Second,
		PoolSize:       8,
		MaxIdleConns:   8,
		Logger:         log,
	}
}

// Close drains Redis idle pools. Memory clients have nothing to stop. Safe to call more than once.
func (c *Client) Close() {
	if c == nil || c.cache == nil {
		return
	}
	c.cache.close()
}
