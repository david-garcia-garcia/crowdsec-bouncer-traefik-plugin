package captcha

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"

	"github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pkg/configuration"
)

const (
	enterpriseScriptURL            = "https://www.google.com/recaptcha/enterprise.js"
	enterpriseCheckboxClass        = "g-recaptcha"
	recaptchaResponseField         = "g-recaptcha-response"
	enterpriseAssessmentsURLPrefix = "https://recaptchaenterprise.googleapis.com/v1/projects/"
	enterpriseAPIKeyHeader         = "X-Goog-Api-Key" //nolint:gosec // header name, not a credential
	enterpriseResponseBodyLimit    = 64 << 10
)

// Enterprise is the recaptcha-enterprise knobs Client.New switches on with the provider name.
type Enterprise struct {
	Action    string
	APIKey    string
	KeyType   string
	MinScore  string
	ProjectID string
}

// pairEnterprise builds the recaptcha-enterprise widget and enterprise verifier.
func pairEnterprise(httpClient *http.Client, siteKey string, enterprise Enterprise) (Widget, *enterpriseVerifier) {
	action := strings.TrimSpace(enterprise.Action)
	minScore := parseEnterpriseMinScore(enterprise.MinScore)
	verifier := newEnterpriseVerifier(httpClient, enterprise.ProjectID, enterprise.APIKey, siteKey, action, minScore)
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

// enterpriseCheckboxWidget loads enterprise.js with a g-recaptcha checkbox and retry.
func enterpriseCheckboxWidget(action string) Widget {
	return Widget{
		ScriptURL:        enterpriseScriptURL,
		Class:            enterpriseCheckboxClass,
		TokenField:       recaptchaResponseField,
		Action:           action,
		RetryAfterReject: true,
	}
}

// enterpriseScoreWidget loads enterprise.js?render=siteKey with a fixed execute boot and no retry.
func enterpriseScoreWidget(siteKey, action string) Widget {
	return Widget{
		ScriptURL:        enterpriseScriptURL + "?render=" + siteKey,
		TokenField:       recaptchaResponseField,
		Action:           action,
		BootScript:       scoreBootScript(siteKey, action),
		RetryAfterReject: false,
	}
}

// scoreBootScript is the fixed score-key boot: ready, execute, write the token, submit.
func scoreBootScript(siteKey, action string) string {
	quotedSiteKey := quoteJSString(siteKey)
	quotedAction := quoteJSString(action)
	return "grecaptcha.enterprise.ready(function(){grecaptcha.enterprise.execute(" +
		quotedSiteKey + ",{action:" + quotedAction +
		"}).then(function(token){document.getElementById(\"g-recaptcha-response\").value=token;document.getElementById(\"captcha-form\").submit();});});"
}

// quoteJSString JSON-quotes value so it is safe inside the fixed boot script.
func quoteJSString(value string) string {
	quoted, err := json.Marshal(value)
	if err != nil {
		return `""`
	}
	return string(quoted)
}

// enterpriseVerifier POSTs a solver token to reCAPTCHA Enterprise assessments.
type enterpriseVerifier struct {
	httpClient *http.Client
	projectID  string
	apiKey     string
	siteKey    string
	action     string
	minScore   float64
}

// newEnterpriseVerifier stores the Cloud assessments URL knobs and pass thresholds.
func newEnterpriseVerifier(httpClient *http.Client, projectID, apiKey, siteKey, action string, minScore float64) *enterpriseVerifier {
	return &enterpriseVerifier{
		httpClient: httpClient,
		projectID:  projectID,
		apiKey:     apiKey,
		siteKey:    siteKey,
		action:     action,
		minScore:   minScore,
	}
}

// enterpriseAssessmentEvent is the reCAPTCHA Enterprise request event object.
type enterpriseAssessmentEvent struct {
	Token          string `json:"token"`
	SiteKey        string `json:"siteKey"`
	UserIPAddress  string `json:"userIpAddress,omitempty"`
	ExpectedAction string `json:"expectedAction,omitempty"`
}

// enterpriseAssessmentRequest is the reCAPTCHA Enterprise assessments POST body.
type enterpriseAssessmentRequest struct {
	Event enterpriseAssessmentEvent `json:"event"`
}

// enterpriseTokenProperties is the Assessment tokenProperties object.
type enterpriseTokenProperties struct {
	Valid  bool   `json:"valid"`
	Action string `json:"action"`
}

// enterpriseRiskAnalysis is the Assessment riskAnalysis object.
type enterpriseRiskAnalysis struct {
	Score float64 `json:"score"`
}

// enterpriseAssessmentResponse is a successful Assessment body.
type enterpriseAssessmentResponse struct {
	TokenProperties *enterpriseTokenProperties `json:"tokenProperties"`
	RiskAnalysis    *enterpriseRiskAnalysis    `json:"riskAnalysis"`
}

// assessmentsURL is the Cloud assessments create URL for this project.
func (v *enterpriseVerifier) assessmentsURL() string {
	return enterpriseAssessmentsURLPrefix + v.projectID + "/assessments"
}

// Pass POSTs token to reCAPTCHA Enterprise and applies valid, then action, then score.
// userAgent is unused; Enterprise does not send it.
func (v *enterpriseVerifier) Pass(token, remoteIP, userAgent string) (bool, error) {
	_ = userAgent
	event := enterpriseAssessmentEvent{Token: token, SiteKey: v.siteKey}
	if remoteIP != "" {
		event.UserIPAddress = remoteIP
	}
	if v.action != "" {
		event.ExpectedAction = v.action
	}
	payload, err := json.Marshal(enterpriseAssessmentRequest{Event: event})
	if err != nil {
		return false, err
	}
	req, err := http.NewRequest(http.MethodPost, v.assessmentsURL(), bytes.NewReader(payload))
	if err != nil {
		return false, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set(enterpriseAPIKeyHeader, v.apiKey)
	res, err := v.httpClient.Do(req)
	if err != nil {
		return false, err
	}
	defer func() {
		_ = res.Body.Close()
	}()
	if res.StatusCode < 200 || res.StatusCode > 299 {
		return false, fmt.Errorf("enterprise: status %d", res.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(res.Body, enterpriseResponseBodyLimit+1))
	if err != nil {
		return false, err
	}
	if len(body) > enterpriseResponseBodyLimit {
		return false, errors.New("enterprise: response body too large")
	}
	if len(bytes.TrimSpace(body)) == 0 {
		return false, errors.New("enterprise: empty body")
	}
	var parsed enterpriseAssessmentResponse
	if err := json.Unmarshal(body, &parsed); err != nil {
		return false, err
	}
	if parsed.TokenProperties == nil {
		return false, errors.New("enterprise: missing tokenProperties")
	}
	return v.passOrder(parsed.TokenProperties, parsed.RiskAnalysis), nil
}

// passOrder is valid, then action when configured, then score when a minimum is set.
func (v *enterpriseVerifier) passOrder(props *enterpriseTokenProperties, risk *enterpriseRiskAnalysis) bool {
	if !props.Valid {
		return false
	}
	if v.action != "" && !strings.EqualFold(props.Action, v.action) {
		return false
	}
	if v.minScore > 0 {
		score := 0.0
		if risk != nil {
			score = risk.Score
		}
		if score < v.minScore {
			return false
		}
	}
	return true
}
