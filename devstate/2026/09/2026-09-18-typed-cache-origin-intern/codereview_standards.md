# Standards

1. [hard] Consume before produce — `pkg/lapi/client_metrics.go:189` — `originNameOf` is a second thin store forward with the same body as `Client.OriginName`
   ```
   func (c *Client) originNameOf(id uint16) string {
   	if c == nil || c.decisionStore == nil {
   		return ""
   	}
   	return c.decisionStore.OriginName(id)
   }
   ```
   → Delete `originNameOf`; pass `c.OriginName`
   Status: done
   Argument: 4d358dce.
2. [hard] One job, one owner — `pkg/lapi/client_metrics.go:198` — reporter remember/forget/slotMetricKey grow `originName` plus `originNameOf` when `rec` already has leftover or id
   ```
   func (r *MetricsReporter) rememberActiveDecision(slot string, rec activeDecisionSlot, originName string, originNameOf func(uint16) string)
   ```
   → Bind `OriginName` once on the reporter; key new and previous slots with `slotMetricKey` only
   Status: done
   Argument: 4d358dce.
3. [hard] Name for the scope — `pkg/lapi/client_metrics.go:174` — `rec` is a placeholder for the compact gauge slot
   ```
   rec := activeDecisionSlot{ipType: ip.FamilyOfHostOrCIDR(decisionValue)}
   ```
   → Rename to `decisionSlot` (and the reporter parameters that retarget it)
   Status: done
   Argument: 4d358dce.
4. [hard] Name for the scope — `pkg/lapi/decisionstore.go:46` — `redis` is a flag; PackMemory uses it as “skip memory packing”
   ```
   redis bool
   ```
   → Rename to `redisBacked`
   Status: done
   Argument: 4d358dce.
5. [hard] Fix the cause — `pkg/lapi/client_decisions.go:115` — range-index needs an intern id, so the call site packs a word and unpacks it
   ```
   if word, ok := c.packMemoryRemediation(kind, origin); ok {
   	_, originID := decisionscope.UnpackWord(word)
   	return decisionscope.PackedRemediationLine(kind, originID)
   }
   ```
   → Intern on the store (or a store method that returns the packed line); do not unpack a word to rebuild a string
   Status: done
   Argument: 4d358dce.
6. [hard] Leave a trail — `pkg/lapi/client_decisions.go:131` — comment says the forward exists so tests can avoid DecisionStore; production `storePackedOrLeftover` and `rangeIndexRemediation` call it
   ```
   // packMemoryRemediation is a thin store forward so tests can intern without calling DecisionStore.
   ```
   → Comment the production job (Client to DecisionStore.PackMemory)
   Status: done
   Argument: 4d358dce.
7. [hard] Leave a trail — `pkg/cache/cache.go:80` — new `setInt` methods have no job comment (`localCache` and `redisCache:183`)
   ```
   func (lc *localCache) setInt(key string, value uint32, duration int64) {
   	lc.heap().Set(key, value, duration)
   }
   ```
   → Add a one-line job comment on each (memory word vs decimal ASCII)
   Status: done
   Argument: 4d358dce.
8. [hard] Leave a trail — `pkg/decisionscope/rangemembership.go:14` — field comment still says leftover suffix after packed letter+id lines land in the same map
   ```
   storedByCIDR map[string]string // cidr -> stored letter or letter plus origin suffix
   ```
   → Name leftover suffix and packed letter+decimal id
   Status: done
   Argument: 4d358dce.
9. [hard] Leave a trail — `knowledge/devdocs/core_plugin_decisionscope.md:43` — edited packet still shows the old 3-return lookup; How-to still says Range writes `RemediationWithOrigin`
   ```
   kind, origin, err := decisionscope.LookupCachedRemediation(cacheClient, req.remoteIP, req.ipAddr, scopes, lapiClient.RangeMembership())
   ```
   → Update the snippet to `originID` and the How-to to `rangeIndexRemediation`
   Status: done
   Argument: 4d358dce.
