# Standards

1. [hard] Leave a trail — `pkg/lapi/client_metrics.go:189` — locked block no longer snapshots gauge items; comment still says it does
   ```go
   // Snapshot dropped and gauge items, then swap processed atomics.
   r.metricsMu.Lock()
   window := r.windowCounters
   r.windowCounters = make(map[usageMetricKey]int64)
   items := make([]map[string]interface{}, 0, len(window)+3)
   for key, value := range window {
   	items = append(items, usageMetricItem(key, value))
   }
   r.metricsMu.Unlock()
   items = append(items, r.activeDecisionItems()...)
   ```
   → Say this lock copies dropped counters; gauge snapshot is `activeDecisionItems` after unlock
   Status: done
   Argument: comment now says lock copies dropped counters; gauge is after unlock.
2. [judgement] Duplicated Code — `pkg/decisionstore/memory.go:191` — `incrementActive` and `decrementActive` are the same body with `+1` vs `-1`
   ```go
   func (m *memory) incrementActive(decisionValue string, word uint32) {
   	if !m.countActive {
   		return
   	}
   	_, _, originID := unpackWord(word)
   	m.active.add(ActiveCountKey{OriginID: originID, Family: ip.FamilyOfHostOrCIDR(decisionValue)}, 1)
   }

   func (m *memory) decrementActive(decisionValue string, word uint32) {
   	if !m.countActive {
   		return
   	}
   	_, _, originID := unpackWord(word)
   	m.active.add(ActiveCountKey{OriginID: originID, Family: ip.FamilyOfHostOrCIDR(decisionValue)}, -1)
   }
   ```
   → One `adjustActive(decisionValue, word, delta)` both call
   Status: skipped
   Argument: judgement; two named one-line wrappers keep +1/-1 obvious.
3. [judgement] Duplicated Code — `pkg/decisionstore/redis.go:182` — PutMany and DeleteMany both build `canonicalKeys` then MGET
   ```go
   canonicalKeys := make([]string, 0, len(items))
   for _, item := range items {
   	key, _ := slotKeys(item.Scope, item.Value)
   	if key == "" {
   		continue
   	}
   	canonicalKeys = append(canonicalKeys, key)
   }
   previous, _ := r.getMany(canonicalKeys)
   ```
   → Extract `canonicalSlotKeys` (and the MGET) once; PutMany/DeleteMany call it
   Status: skipped
   Argument: judgement; PutMany/DeleteMany stay symmetric without a third helper.
