package decisionstore

import (
	"context"
	"errors"
	"log/slog"
	"net"
	"sync/atomic"
	"time"

	simpleredis "github.com/david-garcia-garcia/traefik-middleware-utilities/simpleredis"
)

const (
	// RangeIndexKey is the Redis key for the Range membership blob.
	RangeIndexKey = "range-index"
	rangeIndexTTL = 365 * 24 * 3600
)

// redis holds Ip, header-scope, and Range keys on SimpleRedis.
// Writer does SET/DEL. Readers (or the writer when none) do GET/MGET. A replica
// miss or error is not retried on the writer.
type redis struct {
	log     *slog.Logger
	prefix  string
	writer  *simpleredis.SimpleRedis
	readers []*simpleredis.SimpleRedis
	counter atomic.Uint64
}

// newRedis dials the writer and optional readers via simpleredis.New.
func newRedis(log *slog.Logger, writeHost string, readHosts []string, pass, database, keyPrefix string) *redis {
	red := &redis{log: log, prefix: keyPrefix}
	writer, err := simpleredis.New(redisClientConfig(writeHost, pass, database, log))
	if err != nil {
		if log != nil {
			log.Error("redis:New writer", "error", err)
		}
		return red
	}
	red.writer = writer
	for _, readHost := range readHosts {
		reader, readerErr := simpleredis.New(redisClientConfig(readHost, pass, database, log))
		if readerErr != nil {
			if log != nil {
				log.Error("redis:New reader", "error", readerErr)
			}
			continue
		}
		red.readers = append(red.readers, reader)
	}
	return red
}

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

func prefixed(prefix, key string) string {
	if prefix == "" {
		return key
	}
	return prefix + ":" + key
}

// nextReader returns the writer when readers is empty; otherwise a replica only.
func (r *redis) nextReader() *simpleredis.SimpleRedis {
	n := len(r.readers)
	if n == 0 {
		return r.writer
	}
	idx := r.counter.Add(1) % uint64(n)
	return r.readers[idx]
}

// get GETs one prefixed key from nextReader only.
func (r *redis) get(key string) (string, error) {
	reader := r.nextReader()
	if reader == nil {
		return "", ErrUnreachable
	}
	value, err := reader.Get(context.Background(), prefixed(r.prefix, key))
	if err != nil {
		if simpleredis.IsMiss(err) {
			return "", ErrMiss
		}
		if simpleredis.IsUnreachable(err) {
			return "", ErrUnreachable
		}
		return "", err
	}
	valueString := string(value)
	if len(valueString) > 0 {
		return valueString, nil
	}
	return "", ErrMiss
}

// getMany MGETs slot keys from nextReader only.
func (r *redis) getMany(keys []string) (map[string]string, error) {
	slotKeys := make([]string, 0, len(keys))
	prefixedNames := make([]string, 0, len(keys))
	for _, key := range keys {
		if key == "" {
			continue
		}
		slotKeys = append(slotKeys, key)
		prefixedNames = append(prefixedNames, prefixed(r.prefix, key))
	}
	if len(prefixedNames) == 0 {
		return map[string]string{}, nil
	}
	reader := r.nextReader()
	if reader == nil {
		return nil, ErrUnreachable
	}
	values, err := reader.MGet(context.Background(), prefixedNames)
	if err != nil {
		if simpleredis.IsUnreachable(err) {
			return nil, ErrUnreachable
		}
		return nil, err
	}
	out := make(map[string]string)
	for i, key := range slotKeys {
		if i >= len(values) || values[i] == nil || len(values[i]) == 0 {
			continue
		}
		out[key] = string(values[i])
	}
	return out, nil
}

// set writes the writer, logs a Redis error, and returns; Set is void.
func (r *redis) set(key, value string, duration int64) {
	if r.writer == nil {
		return
	}
	if err := r.writer.Set(context.Background(), prefixed(r.prefix, key), []byte(value), duration); err != nil && r.log != nil {
		r.log.Error("redis:set", "error", err)
	}
}

// deleteKey DELs one prefixed key on the writer and is void.
func (r *redis) deleteKey(key string) {
	if r.writer == nil {
		return
	}
	if err := r.writer.Del(context.Background(), prefixed(r.prefix, key)); err != nil && r.log != nil {
		r.log.Error("redis:delete", "error", err)
	}
}

// BeginTick is a no-op: Redis Set/Delete are already visible to other processes.
func (r *redis) BeginTick() {}

// PublishTick is a no-op: Redis key TTL is the expiry.
func (r *redis) PublishTick(int64) {}

// Put is SET of a kind+origin string with DurationSec as TTL.
func (r *redis) Put(item Decision) {
	if r == nil {
		return
	}
	key, _ := slotKeys(item.Scope, item.Value)
	if key == "" {
		return
	}
	r.set(key, KindOriginString(item.Kind, item.Origin), item.DurationSec)
}

// Delete is DEL of the canonical slot and a prior Ip spelling.
func (r *redis) Delete(scope, value string) {
	if r == nil {
		return
	}
	key, priorSpelling := slotKeys(scope, value)
	if key == "" {
		return
	}
	r.deleteKey(key)
	if priorSpelling != "" && priorSpelling != key {
		r.deleteKey(priorSpelling)
	}
}

// LookupRemediation reads Redis (Ip, header scopes) then merges Range from membership.
func (r *redis) LookupRemediation(remoteIP string, ipAddr net.IP, scopes map[string]string, membership *RangeMembership) (string, string, uint16, error) {
	if r == nil {
		return "", "", 0, ErrMiss
	}
	found, err := r.getMany(lookupKeys(remoteIP, scopes))
	if err != nil {
		return "", "", 0, err
	}
	kind, origin, originID := lookupHits(func(key string) any {
		value, ok := found[key]
		if !ok || value == "" {
			return nil
		}
		return value
	}, remoteIP, ipAddr, scopes, membership)
	if kind == "" {
		return "", "", 0, ErrMiss
	}
	return kind, origin, originID, nil
}

// ApplyRangeBatch upserts and removes Range lines with one Redis read and one write.
// A read that did not answer is not an empty index: writing the batch onto an empty base
// would drop every Range decision this poll did not carry.
func (r *redis) ApplyRangeBatch(upserts map[string]string, removals []string) error {
	if r == nil {
		return ErrMiss
	}
	if len(upserts) == 0 && len(removals) == 0 {
		return nil
	}
	index, err := r.RangeIndex()
	if err != nil {
		return err
	}
	next := ApplyRangeIndex(index, upserts, removals)
	if next == "" {
		r.deleteKey(RangeIndexKey)
		return nil
	}
	r.set(RangeIndexKey, next, rangeIndexTTL)
	return nil
}

// RangeIndex is the Redis range-index blob. A miss is empty and no error.
func (r *redis) RangeIndex() (string, error) {
	if r == nil {
		return "", ErrUnreachable
	}
	index, err := r.get(RangeIndexKey)
	if err != nil {
		if errors.Is(err, ErrMiss) {
			return "", nil
		}
		return "", err
	}
	return index, nil
}

func (r *redis) close() {
	if r == nil {
		return
	}
	if r.writer != nil {
		r.writer.Close()
	}
	for _, reader := range r.readers {
		reader.Close()
	}
}
