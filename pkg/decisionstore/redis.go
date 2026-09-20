package decisionstore

import (
	"context"
	"errors"
	"log/slog"
	"net"
	"sync/atomic"
	"time"

	simpleredis "github.com/david-garcia-garcia/traefik-middleware-utilities/simpleredis"

	"github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pkg/intern"
	"github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pkg/ip"
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
	log         *slog.Logger
	prefix      string
	writer      *simpleredis.SimpleRedis
	readers     []*simpleredis.SimpleRedis
	counter     atomic.Uint64
	origins     *intern.Table     // in-process intern of MGET origin names; ids are not persisted
	active      *activeCountState // same pointer as Store; adjusted after MGET under the count mutex
	countActive bool              // false for live/none
}

// newRedis dials the writer and optional readers via simpleredis.New.
func newRedis(log *slog.Logger, writeHost string, readHosts []string, pass, database, keyPrefix string, origins *intern.Table, active *activeCountState, countActive bool) *redis {
	red := &redis{log: log, prefix: keyPrefix, origins: origins, active: active, countActive: countActive}
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
func (r *redis) PublishTick(int32) {}

// PutMany is SET of kind+origin strings. Same DurationSec share one MSetEX, chunked at PutManyChunk.
// When countActive, MGET the previous canonical KindOriginString, intern the origin name in-process, then adjust.
func (r *redis) PutMany(items []Decision) {
	if r == nil || r.writer == nil || len(items) == 0 {
		return
	}
	canonicalKeys := make([]string, 0, len(items))
	for _, item := range items {
		key, _ := slotKeys(item.Scope, item.Value)
		if key == "" {
			continue
		}
		canonicalKeys = append(canonicalKeys, key)
	}
	previous, _ := r.getMany(canonicalKeys)
	r.adjustPutCounts(items, previous)
	namesByTTL := map[int64][]string{}
	valuesByTTL := map[int64][][]byte{}
	for _, item := range items {
		key, _ := slotKeys(item.Scope, item.Value)
		if key == "" {
			continue
		}
		ttl := item.DurationSec
		namesByTTL[ttl] = append(namesByTTL[ttl], prefixed(r.prefix, key))
		valuesByTTL[ttl] = append(valuesByTTL[ttl], []byte(KindOriginString(item.Kind, item.Origin)))
	}
	for ttl, names := range namesByTTL {
		r.msetexGrouped(names, valuesByTTL[ttl], ttl)
	}
}

// msetexGrouped writes one TTL group in PutManyChunk MSetEX calls. Set is void.
func (r *redis) msetexGrouped(names []string, values [][]byte, seconds int64) {
	for start := 0; start < len(names); start += PutManyChunk {
		end := start + PutManyChunk
		if end > len(names) {
			end = len(names)
		}
		if err := r.writer.MSetEX(context.Background(), names[start:end], values[start:end], seconds); err != nil && r.log != nil {
			r.log.Error("redis:msetex", "error", err)
		}
	}
}

// DeleteMany is DEL of each canonical slot and a prior Ip spelling. SimpleRedis has no multi-DEL.
// Gauge follows the canonical key only: a prior-spelling extra DEL is not a second event.
func (r *redis) DeleteMany(items []Decision) {
	if r == nil || len(items) == 0 {
		return
	}
	canonicalKeys := make([]string, 0, len(items))
	for _, item := range items {
		key, _ := slotKeys(item.Scope, item.Value)
		if key == "" {
			continue
		}
		canonicalKeys = append(canonicalKeys, key)
	}
	previous, _ := r.getMany(canonicalKeys)
	r.adjustDeleteCounts(items, previous)
	for _, item := range items {
		key, priorSpelling := slotKeys(item.Scope, item.Value)
		if key == "" {
			continue
		}
		r.deleteKey(key)
		if priorSpelling != "" && priorSpelling != key {
			r.deleteKey(priorSpelling)
		}
	}
}

// adjustPutCounts decrements the previous origin×family group then increments the new.
// previous is updated in-process so a second Put of the same key in this batch is an overwrite.
func (r *redis) adjustPutCounts(items []Decision, previous map[string]string) {
	if !r.countActive {
		return
	}
	if previous == nil {
		previous = map[string]string{}
	}
	for _, item := range items {
		key, _ := slotKeys(item.Scope, item.Value)
		if key == "" {
			continue
		}
		family := ip.FamilyOfHostOrCIDR(item.Value)
		if stored, ok := previous[key]; ok && stored != "" {
			r.active.add(ActiveCountKey{OriginID: r.originID(splitOriginName(stored)), Family: family}, -1)
		}
		r.active.add(ActiveCountKey{OriginID: r.originID(item.Origin), Family: family}, 1)
		previous[key] = KindOriginString(item.Kind, item.Origin)
	}
}

// adjustDeleteCounts decrements the canonical previous group once. Missing delete is a no-op.
func (r *redis) adjustDeleteCounts(items []Decision, previous map[string]string) {
	if !r.countActive || previous == nil {
		return
	}
	for _, item := range items {
		key, _ := slotKeys(item.Scope, item.Value)
		if key == "" {
			continue
		}
		stored, ok := previous[key]
		if !ok || stored == "" {
			continue
		}
		family := ip.FamilyOfHostOrCIDR(item.Value)
		r.active.add(ActiveCountKey{OriginID: r.originID(splitOriginName(stored)), Family: family}, -1)
		delete(previous, key)
	}
}

// originID interns an origin name in-process. Overflow Warns and returns 0.
func (r *redis) originID(name string) uint16 {
	if r.origins == nil {
		return 0
	}
	originID, ok := r.origins.ID(name)
	if ok {
		return originID
	}
	if r.log != nil {
		r.log.Warn("decisionstore:intern overflow", "origin", name)
	}
	return 0
}

// splitOriginName is the origin suffix of a KindOriginString (empty when letter-only).
func splitOriginName(stored string) string {
	_, origin := splitKindOrigin(stored)
	return origin
}

// LookupRemediation reads Redis (Ip, header scopes) then merges Range from membership.
func (r *redis) LookupRemediation(remoteIP string, ipAddr net.IP, scopes map[string]string, membership *RangeMembership) (kind string, origin string, originID uint16, err error) {
	if r == nil {
		return "", "", 0, nil
	}
	found, err := r.getMany(lookupKeys(remoteIP, scopes))
	if err != nil {
		return "", "", 0, err
	}
	kind, origin, originID = lookupHits(func(key string) any {
		value, ok := found[key]
		if !ok || value == "" {
			return nil
		}
		return value
	}, remoteIP, ipAddr, scopes, membership)
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
