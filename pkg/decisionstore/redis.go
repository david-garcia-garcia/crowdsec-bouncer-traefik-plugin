package decisionstore

import (
	"net"

	cache "github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pkg/cache"
	"github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pkg/decisionscope"
)

type redis struct {
	cache *cache.Client
}

func newRedis(cacheClient *cache.Client) *redis {
	return &redis{cache: cacheClient}
}

// BeginTick is a no-op: Redis Set/Delete are already visible to other processes.
func (r *redis) BeginTick() {}

// PublishTick is a no-op: Redis key TTL is the expiry.
func (r *redis) PublishTick(int64) {}

// Put is cache.Set of a leftover kind+origin string with DurationSec as TTL.
func (r *redis) Put(item Decision) {
	if r == nil || r.cache == nil {
		return
	}
	key, _ := slotKeys(item.Scope, item.Value)
	if key == "" {
		return
	}
	r.cache.Set(key, decisionscope.RemediationWithOrigin(item.Kind, item.Origin), item.DurationSec)
}

// Delete is cache.Delete of the canonical slot and a prior Ip spelling.
func (r *redis) Delete(scope, value string) {
	if r == nil || r.cache == nil {
		return
	}
	key, legacy := slotKeys(scope, value)
	if key == "" {
		return
	}
	r.cache.Delete(key)
	if legacy != "" && legacy != key {
		r.cache.Delete(legacy)
	}
}

// LookupRemediation reads cache.Client (Ip, header scopes, Range).
func (r *redis) LookupRemediation(remoteIP string, ipAddr net.IP, scopes map[string]string, membership *decisionscope.RangeMembership) (string, string, uint16, error) {
	if r == nil || r.cache == nil {
		return "", "", 0, cache.ErrMiss
	}
	return decisionscope.LookupCachedRemediation(r.cache, remoteIP, ipAddr, scopes, membership)
}
