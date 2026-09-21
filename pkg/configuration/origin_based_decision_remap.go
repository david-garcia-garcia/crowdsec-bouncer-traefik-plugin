package configuration

import (
	"errors"
	"fmt"
	"strings"
)

// Operator tokens for OriginBasedDecisionRemap from/to (LAPI types plus pass).
const (
	originBasedDecisionRemapBan     = "ban"
	originBasedDecisionRemapCaptcha = "captcha"
	originBasedDecisionRemapPass    = "pass"
)

// validateOriginBasedDecisionRemap rejects empty origin keys and from→to edges that are not a weaken.
// Unknown origin tokens are allowed. captchaProvider is not required.
func validateOriginBasedDecisionRemap(config *Config) error {
	if config == nil {
		return nil
	}
	for origin, edges := range config.OriginBasedDecisionRemap {
		if strings.TrimSpace(origin) == "" {
			return errors.New("originBasedDecisionRemap: origin cannot be empty")
		}
		if len(edges) == 0 {
			return fmt.Errorf("originBasedDecisionRemap: %q has no mappings", origin)
		}
		for from, to := range edges {
			fromType := strings.ToLower(strings.TrimSpace(from))
			toType := strings.ToLower(strings.TrimSpace(to))
			if fromType != originBasedDecisionRemapBan && fromType != originBasedDecisionRemapCaptcha {
				return fmt.Errorf("originBasedDecisionRemap: %q from %q must be ban or captcha", origin, from)
			}
			if !OriginBasedDecisionRemapAllowed(fromType, toType) {
				return fmt.Errorf("originBasedDecisionRemap: %q cannot map %s to %s", origin, fromType, toType)
			}
		}
	}
	return nil
}

// OriginBasedDecisionRemapAllowed reports whether from→to is a one-hop weaken of stored kind.
func OriginBasedDecisionRemapAllowed(from, to string) bool {
	switch from {
	case originBasedDecisionRemapBan:
		return to == originBasedDecisionRemapCaptcha || to == originBasedDecisionRemapPass
	case originBasedDecisionRemapCaptcha:
		return to == originBasedDecisionRemapPass
	default:
		return false
	}
}
