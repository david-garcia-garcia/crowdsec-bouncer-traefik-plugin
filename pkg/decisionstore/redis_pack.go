package decisionstore

import (
	"strings"

	"github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pkg/decisionscope"
)

const kindOriginSep = "\n"

// KindOriginString is the Redis SET value and the Range blob remediation: kind, then newline, then origin.
func KindOriginString(kind, origin string) string {
	return packToString(lookupHit{kind: kind, origin: origin})
}

// packToString writes a hit as kind, origin, and scenario. Empty scenario keeps the two-field value.
func packToString(hit lookupHit) string {
	if hit.origin == "" && hit.scenario == "" {
		return hit.kind
	}
	if hit.scenario == "" {
		return hit.kind + kindOriginSep + hit.origin
	}
	return hit.kind + kindOriginSep + hit.origin + kindOriginSep + hit.scenario
}

// unpackFromString reads a kind/origin string, with an optional scenario field.
func unpackFromString(stored string) lookupHit {
	if stored == "" {
		return lookupHit{}
	}
	kind, rest, ok := strings.Cut(stored, kindOriginSep)
	if !ok {
		return lookupHit{kind: decisionscope.RemediationKind(stored)}
	}
	origin, scenario, _ := strings.Cut(rest, kindOriginSep)
	return lookupHit{kind: decisionscope.RemediationKind(kind), origin: origin, scenario: scenario}
}
