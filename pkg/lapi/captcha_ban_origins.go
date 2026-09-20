package lapi

import (
	"strings"

	"github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pkg/decisionscope"
)

const listsOriginPrefix = "lists:"

// copyCaptchaBanOrigins copies trimmed non-empty CaptchaBanOrigins entries for Client New.
func copyCaptchaBanOrigins(entries []string) []string {
	if len(entries) == 0 {
		return nil
	}
	copied := make([]string, 0, len(entries))
	for _, entry := range entries {
		trimmed := strings.TrimSpace(entry)
		if trimmed == "" {
			continue
		}
		copied = append(copied, trimmed)
	}
	if len(copied) == 0 {
		return nil
	}
	return copied
}

// remediationKindForOrigin maps a LAPI decision type plus MetricsOrigin string to the stored kind letter.
// A ban whose origin is listed in CaptchaBanOrigins is stored as captcha.
func (c *Client) remediationKindForOrigin(decisionType, metricsOrigin string) string {
	kind := decisionscope.RemediationValue(decisionType)
	if kind != decisionscope.BannedValue {
		return kind
	}
	if c != nil && captchaBanOriginListed(metricsOrigin, c.captchaBanOrigins) {
		return decisionscope.CaptchaValue
	}
	return decisionscope.BannedValue
}

// captchaBanOriginListed reports whether metricsOrigin matches a CaptchaBanOrigins entry.
// Exact equality, or config "lists" matching "lists" and any "lists:" prefix.
func captchaBanOriginListed(metricsOrigin string, entries []string) bool {
	if metricsOrigin == "" {
		return false
	}
	for _, entry := range entries {
		if metricsOrigin == entry {
			return true
		}
		if entry == "lists" && strings.HasPrefix(metricsOrigin, listsOriginPrefix) {
			return true
		}
	}
	return false
}
