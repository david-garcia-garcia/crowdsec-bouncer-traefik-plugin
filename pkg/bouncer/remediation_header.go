package bouncer

import (
	"strings"

	"github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pkg/appsec"
	"github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pkg/lapi"
)

// Closed header kind and reason tokens for bouncerRemediationHeadersCustomName.
const (
	headerKindBan     = "ban"
	headerKindCaptcha = "captcha"
	headerKindError   = "error"

	headerReasonLAPI                 = "lapi"
	headerReasonDecisionHeader       = "decision-header"
	headerReasonLAPIFailure          = "lapi-failure"
	headerReasonStreamUnhealthy      = "stream-unhealthy"
	headerReasonCacheFail            = "cache-fail"
	headerReasonUnparseableRequest   = "unparseable-request"
	headerReasonAppsec               = "appsec"
	headerReasonAppsecChallengeEmpty = "appsec-challenge-empty"
	headerReasonAppsecFailure        = "appsec-failure"
	headerReasonCaptchaDowngrade     = "captcha-downgrade"
	headerReasonChallenge            = "challenge"
	headerReasonClientDisconnected   = "client-disconnected"

	listsHeaderPrefix = "lists_"
)

// formatRemediationHeader joins kind:reason, or kind:reason:origin when reason is lapi and origin is non-empty.
// Empty kind or reason returns empty; it does not invent allow: pass.
func formatRemediationHeader(kind, reason, origin string) string {
	if kind == "" || reason == "" {
		return ""
	}
	encoded := encodeHeaderOrigin(origin)
	if reason == headerReasonLAPI && encoded != "" {
		return kind + ":" + reason + ":" + encoded
	}
	return kind + ":" + reason
}

// encodeHeaderOrigin strips CR/LF/TAB and rewrites only the lists: prefix to lists_.
func encodeHeaderOrigin(origin string) string {
	origin = stripHeaderCtl(origin)
	if strings.HasPrefix(origin, listsOriginPrefix) {
		return listsHeaderPrefix + origin[len(listsOriginPrefix):]
	}
	return origin
}

// headerReasonFromOrigin maps a metrics origin to a closed header reason.
// Plugin origins stay a reason token. Every other origin is lapi (third field is that origin).
func headerReasonFromOrigin(origin string) string {
	switch origin {
	case lapi.OriginPluginForcedDecision:
		return headerReasonDecisionHeader
	case lapi.OriginPluginLapiFailure:
		return headerReasonLAPIFailure
	case lapi.OriginPluginTechStreamFail:
		return headerReasonStreamUnhealthy
	case lapi.OriginPluginAppsecFailure:
		return headerReasonAppsecFailure
	default:
		return headerReasonLAPI
	}
}

// formatAppsecRelayHeader is the structured header for a non-ban AppSec envelope.
func formatAppsecRelayHeader(action string) string {
	switch action {
	case appsec.ActionCaptcha:
		return formatRemediationHeader(headerKindCaptcha, headerReasonAppsec, "")
	case appsec.ActionChallenge:
		return formatRemediationHeader(headerKindCaptcha, headerReasonChallenge, "")
	default:
		return formatRemediationHeader(sanitizeAppsecAction(action), headerReasonAppsec, "")
	}
}

// sanitizeAppsecAction keeps an unknown AppSec action as one kind field.
func sanitizeAppsecAction(action string) string {
	action = strings.TrimSpace(action)
	action = stripHeaderCtl(action)
	return strings.ReplaceAll(action, ":", "_")
}

// stripHeaderCtl removes CR, LF, and TAB so the value cannot split Traefik log lines.
func stripHeaderCtl(value string) string {
	return strings.NewReplacer("\r", "", "\n", "", "\t", "").Replace(value)
}
