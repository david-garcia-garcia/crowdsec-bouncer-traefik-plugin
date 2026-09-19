package decisionstore

import (
	"net"

	"github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pkg/decisionscope"
)

// lookupHit is one Ip, header, or Range candidate while merging ban over captcha.
type lookupHit struct {
	stored   string
	origin   string
	originID uint16
}

// mergeLookupHit keeps ban over captcha and remembers the winner's origin name or packed id.
func mergeLookupHit(chosen lookupHit, incoming lookupHit) lookupHit {
	if incoming.stored == "" {
		return chosen
	}
	next := decisionscope.PreferRemediation(chosen.stored, incoming.stored)
	if next == chosen.stored {
		return chosen
	}
	return incoming
}

// hitFromPayload unpacks a Pack word or a kind+origin string.
func hitFromPayload(payload any) lookupHit {
	if payload == nil {
		return lookupHit{}
	}
	kind, origin, originID := Unpack(payload)
	stored, isString := payload.(string)
	if !isString {
		stored = kind
	}
	return lookupHit{stored: stored, origin: origin, originID: originID}
}

// lookupHits merges Ip, present header scopes, and Range. Ban on Ip skips Range membership.
// get returns a Pack word, kind+origin string, or nil when the key is absent. Empty kind is a miss.
func lookupHits(get func(string) any, remoteIP string, ipAddr net.IP, scopes map[string]string, membership *RangeMembership) (string, string, uint16) {
	if get == nil {
		get = func(string) any { return nil }
	}
	var chosen lookupHit
	chosen = mergeLookupHit(chosen, hitFromPayload(get(remoteIP)))
	for scope, identifier := range scopes {
		if identifier == "" {
			continue
		}
		chosen = mergeLookupHit(chosen, hitFromPayload(get(HeaderScopeKey(scope, identifier))))
	}
	if decisionscope.RemediationKind(chosen.stored) != decisionscope.BannedValue {
		chosen = mergeLookupHit(chosen, hitFromPayload(membership.Remediation(ipAddr)))
	}
	if chosen.stored == "" {
		return "", "", 0
	}
	return decisionscope.RemediationKind(chosen.stored), chosen.origin, chosen.originID
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
