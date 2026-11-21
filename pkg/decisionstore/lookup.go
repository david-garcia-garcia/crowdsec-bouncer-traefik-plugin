package decisionstore

import (
	"net"
	"time"

	"github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pkg/decisionscope"
)

// lookupHit is the decision both encodings pack and unpack: kind, origin name, scenario name.
// left is the time left on that decision at lookup, set by the engine that read the slot (0 = unknown).
type lookupHit struct {
	kind     string
	origin   string
	scenario string
	left     time.Duration
}

// mergeLookupHit keeps ban over captcha and remembers the winner's origin name and time left.
func mergeLookupHit(chosen lookupHit, incoming lookupHit) lookupHit {
	if incoming.kind == "" {
		return chosen
	}
	next := decisionscope.PreferRemediation(chosen.kind, incoming.kind)
	if next == chosen.kind {
		return chosen
	}
	return incoming
}

// lookupHits merges Ip, present header scopes, and Range. Ban on Ip skips Range membership.
// hitForKey returns the unpacked slot. A zero hit is a miss.
// Returns the winner's kind, origin, and time left. A Range winner has no end, so its time left is zero.
func lookupHits(hitForKey func(string) lookupHit, remoteIP string, ipAddr net.IP, scopes map[string]string, membership *RangeMembership) (string, string, time.Duration) {
	if hitForKey == nil {
		hitForKey = func(string) lookupHit { return lookupHit{} }
	}
	var chosen lookupHit
	chosen = mergeLookupHit(chosen, hitForKey(remoteIP))
	for scope, identifier := range scopes {
		if identifier == "" {
			continue
		}
		chosen = mergeLookupHit(chosen, hitForKey(HeaderScopeKey(scope, identifier)))
	}
	if membership != nil && decisionscope.RemediationKind(chosen.kind) != decisionscope.BannedValue {
		rangeHit, _ := unpackFromString(membership.Remediation(ipAddr))
		chosen = mergeLookupHit(chosen, rangeHit)
	}
	if chosen.kind == "" {
		return "", "", 0
	}
	return decisionscope.RemediationKind(chosen.kind), chosen.origin, chosen.left
}

// lookupKeys is the IP and present header-scope keys lookupHits reads. Range is membership, not a slot.
func lookupKeys(remoteIP string, scopes map[string]string) []string {
	keys := []string{remoteIP}
	for scope, identifier := range scopes {
		if identifier != "" {
			keys = append(keys, HeaderScopeKey(scope, identifier))
		}
	}
	return keys
}
