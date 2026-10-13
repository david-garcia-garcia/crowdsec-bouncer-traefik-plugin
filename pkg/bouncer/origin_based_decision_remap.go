package bouncer

import (
	"strings"

	"github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pkg/configuration"
	"github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pkg/decisionscope"
)

const listsOriginPrefix = "lists:"

const originBasedDecisionRemapToPass = "pass"

// copyOriginBasedDecisionRemap copies trimmed weaken remaps for Bouncer New.
// Inner values are applied kind letters (captcha `c`, pass empty). Invalid edges are dropped.
func copyOriginBasedDecisionRemap(src map[string]map[string]string) map[string]map[string]string {
	if len(src) == 0 {
		return nil
	}
	copied := make(map[string]map[string]string, len(src))
	for origin, edges := range src {
		originKey := strings.TrimSpace(origin)
		if originKey == "" || len(edges) == 0 {
			continue
		}
		copiedEdges := make(map[string]string, len(edges))
		for from, to := range edges {
			fromType := strings.ToLower(strings.TrimSpace(from))
			toType := strings.ToLower(strings.TrimSpace(to))
			if !configuration.OriginBasedDecisionRemapAllowed(fromType, toType) {
				continue
			}
			copiedEdges[fromType] = originBasedDecisionRemapAppliedKind(toType)
		}
		if len(copiedEdges) == 0 {
			continue
		}
		copied[originKey] = copiedEdges
	}
	if len(copied) == 0 {
		return nil
	}
	return copied
}

// originBasedDecisionRemapAppliedKind maps an operator to-token to the kind letter ServeHTTP uses.
// pass is NoBannedValue so the request takes the AppSec/next path.
func originBasedDecisionRemapAppliedKind(to string) string {
	if to == originBasedDecisionRemapToPass {
		return decisionscope.NoBannedValue
	}
	return decisionscope.RemediationValue(to)
}

// applyOriginBasedDecisionRemap is one hop on the LAPI stored letter for this router.
func (b *Bouncer) applyOriginBasedDecisionRemap(kind, metricsOrigin string) string {
	if kind == "" || kind == decisionscope.NoBannedValue {
		return kind
	}
	if b == nil {
		return kind
	}
	fromType := originBasedDecisionRemapFromKind(kind)
	if fromType == "" {
		return kind
	}
	mapped, ok := originBasedDecisionRemapTo(b.originBasedDecisionRemap, metricsOrigin, fromType)
	if !ok {
		return kind
	}
	return mapped
}

// originBasedDecisionRemapFromKind is the LAPI type token for a stored kind letter.
func originBasedDecisionRemapFromKind(kind string) string {
	switch decisionscope.RemediationKind(kind) {
	case decisionscope.BannedValue:
		return "ban"
	case decisionscope.CaptchaValue:
		return "captcha"
	default:
		return ""
	}
}

// originBasedDecisionRemapTo is the applied kind when metricsOrigin has an edge for fromType.
func originBasedDecisionRemapTo(table map[string]map[string]string, metricsOrigin, fromType string) (string, bool) {
	edges := originBasedDecisionRemapEdges(metricsOrigin, table)
	if len(edges) == 0 {
		return "", false
	}
	mapped, ok := edges[strings.ToLower(fromType)]
	return mapped, ok
}

// originBasedDecisionRemapEdges is the from→kind map for metricsOrigin.
// Exact key wins; config "lists" also matches any "lists:" prefix.
func originBasedDecisionRemapEdges(metricsOrigin string, table map[string]map[string]string) map[string]string {
	if metricsOrigin == "" || len(table) == 0 {
		return nil
	}
	if edges, ok := table[metricsOrigin]; ok {
		return edges
	}
	if strings.HasPrefix(metricsOrigin, listsOriginPrefix) {
		if edges, ok := table["lists"]; ok {
			return edges
		}
	}
	return nil
}

// appliedLAPIRemediation remaps a lookup/live LAPI kind for this router and resolves packed origin.
func (b *Bouncer) appliedLAPIRemediation(kind, origin string, originID uint16) (string, string) {
	if b == nil || len(b.originBasedDecisionRemap) == 0 {
		return kind, origin
	}
	if origin == "" {
		origin = b.resolveDroppedOrigin("", originID)
	}
	return b.applyOriginBasedDecisionRemap(kind, origin), origin
}
