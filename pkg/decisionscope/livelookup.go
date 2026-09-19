package decisionscope

import (
	"net"

	cache "github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pkg/cache"
)

// LookupStreamMapRemediation merges Ip, header scopes, and Range from a published memory stream map.
// Ban on Ip skips Range membership. Nil or empty snapshot is a miss when nothing else hits.
func LookupStreamMapRemediation(snapshot map[string]LiveSlot, remoteIP string, ipAddr net.IP, scopes map[string]string, membership *RangeMembership) (string, string, uint16, error) {
	var chosen lookupHit
	if snapshot != nil {
		if slot, ok := snapshot[remoteIP]; ok {
			chosen = mergeLookupHit(chosen, HitFromLiveSlot(slot))
		}
		for scope, identifier := range scopes {
			if identifier == "" {
				continue
			}
			if slot, ok := snapshot[HeaderScopeKey(scope, identifier)]; ok {
				chosen = mergeLookupHit(chosen, HitFromLiveSlot(slot))
			}
		}
	}
	if RemediationKind(chosen.stored) != BannedValue {
		chosen = mergeLookupHit(chosen, hitFromPayload(membership.Remediation(ipAddr)))
	}
	if chosen.stored != "" {
		return RemediationKind(chosen.stored), chosen.origin, chosen.originID, nil
	}
	return "", "", 0, cache.ErrMiss
}
