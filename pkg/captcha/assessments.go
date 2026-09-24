package captcha

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
)

const (
	assessmentsURLPrefix         = "https://recaptchaenterprise.googleapis.com/v1/projects/"
	assessmentsAPIKeyHeader      = "X-Goog-Api-Key" //nolint:gosec // header name, not a credential
	assessmentsResponseBodyLimit = 64 << 10
)

// assessmentsVerifier POSTs a solver token to Cloud reCAPTCHA Enterprise assessments.
type assessmentsVerifier struct {
	httpClient *http.Client
	projectID  string
	apiKey     string
	siteKey    string
	action     string
	minScore   float64
}

// newAssessmentsVerifier stores the Cloud assessments URL knobs and pass thresholds.
func newAssessmentsVerifier(httpClient *http.Client, projectID, apiKey, siteKey, action string, minScore float64) *assessmentsVerifier {
	return &assessmentsVerifier{
		httpClient: httpClient,
		projectID:  projectID,
		apiKey:     apiKey,
		siteKey:    siteKey,
		action:     action,
		minScore:   minScore,
	}
}

// assessmentEvent is the assessments request event object.
type assessmentEvent struct {
	Token          string `json:"token"`
	SiteKey        string `json:"siteKey"`
	UserIPAddress  string `json:"userIpAddress,omitempty"`
	ExpectedAction string `json:"expectedAction,omitempty"`
}

// assessmentRequest is the assessments POST body.
type assessmentRequest struct {
	Event assessmentEvent `json:"event"`
}

// assessmentTokenProperties is the Assessment tokenProperties object.
type assessmentTokenProperties struct {
	Valid  bool   `json:"valid"`
	Action string `json:"action"`
}

// assessmentRiskAnalysis is the Assessment riskAnalysis object.
type assessmentRiskAnalysis struct {
	Score float64 `json:"score"`
}

// assessmentResponse is a successful Assessment body.
type assessmentResponse struct {
	TokenProperties *assessmentTokenProperties `json:"tokenProperties"`
	RiskAnalysis    *assessmentRiskAnalysis    `json:"riskAnalysis"`
}

// assessmentsURL is the Cloud assessments create URL for this project.
func (v *assessmentsVerifier) assessmentsURL() string {
	return assessmentsURLPrefix + v.projectID + "/assessments"
}

// Pass POSTs token to assessments and applies valid, then action, then score.
func (v *assessmentsVerifier) Pass(token, remoteIP string) (bool, error) {
	event := assessmentEvent{Token: token, SiteKey: v.siteKey}
	if remoteIP != "" {
		event.UserIPAddress = remoteIP
	}
	if v.action != "" {
		event.ExpectedAction = v.action
	}
	payload, err := json.Marshal(assessmentRequest{Event: event})
	if err != nil {
		return false, err
	}
	req, err := http.NewRequest(http.MethodPost, v.assessmentsURL(), bytes.NewReader(payload))
	if err != nil {
		return false, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set(assessmentsAPIKeyHeader, v.apiKey)
	res, err := v.httpClient.Do(req)
	if err != nil {
		return false, err
	}
	defer func() {
		_ = res.Body.Close()
	}()
	if res.StatusCode < 200 || res.StatusCode > 299 {
		return false, fmt.Errorf("assessments: status %d", res.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(res.Body, assessmentsResponseBodyLimit+1))
	if err != nil {
		return false, err
	}
	if len(body) > assessmentsResponseBodyLimit {
		return false, errors.New("assessments: response body too large")
	}
	if len(bytes.TrimSpace(body)) == 0 {
		return false, errors.New("assessments: empty body")
	}
	var assessment assessmentResponse
	if err := json.Unmarshal(body, &assessment); err != nil {
		return false, err
	}
	if assessment.TokenProperties == nil {
		return false, errors.New("assessments: missing tokenProperties")
	}
	return v.passOrder(assessment.TokenProperties, assessment.RiskAnalysis), nil
}

// passOrder is valid, then action when configured, then score when a minimum is set.
func (v *assessmentsVerifier) passOrder(props *assessmentTokenProperties, risk *assessmentRiskAnalysis) bool {
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
