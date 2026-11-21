package decisionstore

import (
	"strconv"
	"strings"

	"github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pkg/decisionscope"
)

const kindOriginSep = "\n"

// KindOriginString is the Range blob remediation: kind, then newline, then origin. It carries no end.
func KindOriginString(kind, origin string) string {
	return packToString(lookupHit{kind: kind, origin: origin}, 0)
}

// packToString writes a hit as the Redis slot value: kind, origin, scenario, then the decision end
// in wall-clock Unix seconds. Trailing unset lines are omitted; a line before a set line is written
// empty. Readers from v1.9.4 cut kind and origin and fold the rest into the scenario they never return.
func packToString(hit lookupHit, endUnix int64) string {
	if endUnix > 0 {
		return hit.kind + kindOriginSep + hit.origin + kindOriginSep + hit.scenario + kindOriginSep + strconv.FormatInt(endUnix, 10)
	}
	if hit.origin == "" && hit.scenario == "" {
		return hit.kind
	}
	if hit.scenario == "" {
		return hit.kind + kindOriginSep + hit.origin
	}
	return hit.kind + kindOriginSep + hit.origin + kindOriginSep + hit.scenario
}

// unpackFromString reads a kind/origin string, with optional scenario and decision-end lines.
// endUnix is 0 when the value has no end line or that line is not a positive integer.
func unpackFromString(stored string) (lookupHit, int64) {
	if stored == "" {
		return lookupHit{}, 0
	}
	kind, rest, ok := strings.Cut(stored, kindOriginSep)
	if !ok {
		return lookupHit{kind: decisionscope.RemediationKind(stored)}, 0
	}
	origin, afterOrigin, _ := strings.Cut(rest, kindOriginSep)
	scenario, endUnix := splitScenarioEnd(afterOrigin)
	return lookupHit{kind: decisionscope.RemediationKind(kind), origin: origin, scenario: scenario}, endUnix
}

// splitScenarioEnd splits the text after the origin line at its last newline. The tail is the
// decision end only when it parses as a positive integer; otherwise the whole text is the scenario.
// A three-line value has no newline here, so a numeric scenario is never read as an end.
func splitScenarioEnd(afterOrigin string) (string, int64) {
	cut := strings.LastIndex(afterOrigin, kindOriginSep)
	if cut < 0 {
		return afterOrigin, 0
	}
	endUnix, err := strconv.ParseInt(afterOrigin[cut+len(kindOriginSep):], 10, 64)
	if err != nil || endUnix <= 0 {
		return afterOrigin, 0
	}
	return afterOrigin[:cut], endUnix
}
