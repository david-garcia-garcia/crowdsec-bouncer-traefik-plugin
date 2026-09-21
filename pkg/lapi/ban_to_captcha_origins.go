package lapi

import (
	"strings"

	"github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pkg/decisionscope"
)

const listsOriginPrefix = "lists:"

// copyBanToCaptchaOrigins copies trimmed non-empty BanToCaptchaOrigins entries for Client New.
func copyBanToCaptchaOrigins(entries []string) []string {
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

// remediationKind is the stored kind letter for a LAPI decision after Client rules.
// Dest RemediationValue maps type only. A ban whose metrics origin is listed in BanToCaptchaOrigins is stored as captcha.
func (c *Client) remediationKind(decisionType, metricsOrigin string) string {
	kind := decisionscope.RemediationValue(decisionType)
	if kind != decisionscope.BannedValue {
		return kind
	}
	if c != nil && banToCaptchaOriginListed(metricsOrigin, c.banToCaptchaOrigins) {
		return decisionscope.CaptchaValue
	}
	return decisionscope.BannedValue
}

// banToCaptchaOriginListed reports whether metricsOrigin matches a BanToCaptchaOrigins entry.
// Exact equality, or config "lists" matching "lists" and any "lists:" prefix.
func banToCaptchaOriginListed(metricsOrigin string, entries []string) bool {
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
