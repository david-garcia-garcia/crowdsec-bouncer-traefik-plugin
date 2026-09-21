package lapi

import (
	"strings"

	"github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pkg/configuration"
	"github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pkg/decisionscope"
)

const listsOriginPrefix = "lists:"

const originBasedDecisionRemapToPass = "pass"

// copyOriginBasedDecisionRemap copies trimmed weaken remaps for Client New.
// Inner values are stored kind letters (captcha `c`, pass empty). Invalid edges are dropped.
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
			copiedEdges[fromType] = originBasedDecisionRemapStoredKind(toType)
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

// originBasedDecisionRemapStoredKind maps an operator to-token to the stored kind letter.
// pass is empty so stream/range skip store, same as an unknown LAPI type.
func originBasedDecisionRemapStoredKind(to string) string {
	if to == originBasedDecisionRemapToPass {
		return ""
	}
	return decisionscope.RemediationValue(to)
}

// remediationKind is the stored kind letter for a LAPI decision after Client rules.
// Dest RemediationValue maps type only. OriginBasedDecisionRemap applies one hop on the original type.
func (c *Client) remediationKind(decisionType, metricsOrigin string) string {
	kind := decisionscope.RemediationValue(decisionType)
	if kind == "" {
		return ""
	}
	if c == nil {
		return kind
	}
	mapped, ok := originBasedDecisionRemapTo(c.originBasedDecisionRemap, metricsOrigin, decisionType)
	if !ok {
		return kind
	}
	return mapped
}

// originBasedDecisionRemapTo is the remapped stored kind when metricsOrigin has an edge for decisionType.
func originBasedDecisionRemapTo(table map[string]map[string]string, metricsOrigin, decisionType string) (string, bool) {
	edges := originBasedDecisionRemapEdges(metricsOrigin, table)
	if len(edges) == 0 {
		return "", false
	}
	mapped, ok := edges[strings.ToLower(decisionType)]
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
