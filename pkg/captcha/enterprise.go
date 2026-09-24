package captcha

import (
	"net/http"
	"strconv"
	"strings"

	"github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pkg/configuration"
)

// Enterprise is the recaptcha-enterprise knobs Client.New switches on with the provider name.
type Enterprise struct {
	Action    string
	APIKey    string
	KeyType   string
	MinScore  string
	ProjectID string
}

// pairEnterprise builds the recaptcha-enterprise widget and assessments verifier.
func pairEnterprise(httpClient *http.Client, siteKey string, enterprise Enterprise) (Widget, *assessmentsVerifier) {
	action := strings.TrimSpace(enterprise.Action)
	minScore := parseEnterpriseMinScore(enterprise.MinScore)
	verifier := newAssessmentsVerifier(httpClient, enterprise.ProjectID, enterprise.APIKey, siteKey, action, minScore)
	if enterprise.KeyType == configuration.CaptchaEnterpriseKeyTypeScore {
		return enterpriseScoreWidget(siteKey, action), verifier
	}
	return enterpriseCheckboxWidget(action), verifier
}

// parseEnterpriseMinScore reads a configured minimum; empty or invalid is unset (0).
func parseEnterpriseMinScore(raw string) float64 {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return 0
	}
	parsed, err := strconv.ParseFloat(trimmed, 64)
	if err != nil {
		return 0
	}
	return parsed
}
