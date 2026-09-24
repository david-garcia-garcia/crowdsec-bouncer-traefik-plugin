package captcha

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
)

const (
	eucaptchaScriptURL         = "https://cdn.eu-captcha.eu/verify.js"
	eucaptchaClass             = "eu-captcha"
	eucaptchaResponseField     = "eu-captcha-response"
	eucaptchaVerifyURL         = "https://api.eu-captcha.eu/v1/verify"
	eucaptchaResponseBodyLimit = 64 << 10
)

// eucaptchaVerifier POSTs a solver token to EU CAPTCHA /v1/verify.
type eucaptchaVerifier struct {
	httpClient *http.Client
	siteKey    string
	secretKey  string
}

// newEucaptchaVerifier stores the site key, secret, and HTTP client for verify.
func newEucaptchaVerifier(httpClient *http.Client, siteKey, secretKey string) *eucaptchaVerifier {
	return &eucaptchaVerifier{
		httpClient: httpClient,
		siteKey:    siteKey,
		secretKey:  secretKey,
	}
}

// pairEucaptcha builds the official widget pairing and the verify verifier.
func pairEucaptcha(httpClient *http.Client, siteKey, secretKey string) (Widget, *eucaptchaVerifier) {
	return Widget{
		ScriptURL:        eucaptchaScriptURL,
		Class:            eucaptchaClass,
		TokenField:       eucaptchaResponseField,
		RetryAfterReject: true,
	}, newEucaptchaVerifier(httpClient, siteKey, secretKey)
}

// eucaptchaVerifyRequest is the official POST /v1/verify JSON body.
//
//nolint:tagliatelle // EU CAPTCHA names are client_ip, client_token, client_user_agent.
type eucaptchaVerifyRequest struct {
	SiteKey         string `json:"sitekey"`
	Secret          string `json:"secret"`
	ClientIP        string `json:"client_ip"`
	ClientToken     string `json:"client_token"`
	ClientUserAgent string `json:"client_user_agent"`
}

// eucaptchaVerifyResponse is an HTTP 200 verify JSON body.
// Train is a pointer so JSON null and an omitted key both decode as nil.
type eucaptchaVerifyResponse struct {
	Success bool  `json:"success"`
	Train   *bool `json:"train"`
}

// Pass POSTs token to EU CAPTCHA verify and classifies success and train.
// Empty remoteIP is Pass-false with no vendor POST. Empty userAgent is still sent.
func (v *eucaptchaVerifier) Pass(token, remoteIP, userAgent string) (bool, error) {
	if remoteIP == "" {
		return false, nil
	}
	payload, err := json.Marshal(eucaptchaVerifyRequest{
		SiteKey:         v.siteKey,
		Secret:          v.secretKey,
		ClientIP:        remoteIP,
		ClientToken:     token,
		ClientUserAgent: userAgent,
	})
	if err != nil {
		return false, err
	}
	req, err := http.NewRequest(http.MethodPost, eucaptchaVerifyURL, bytes.NewReader(payload))
	if err != nil {
		return false, err
	}
	req.Header.Set("Content-Type", "application/json")
	res, err := v.httpClient.Do(req)
	if err != nil {
		return false, err
	}
	defer func() {
		_ = res.Body.Close()
	}()
	if res.StatusCode < 200 || res.StatusCode > 299 {
		return false, fmt.Errorf("eucaptcha: status %d", res.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(res.Body, eucaptchaResponseBodyLimit+1))
	if err != nil {
		return false, err
	}
	if len(body) > eucaptchaResponseBodyLimit {
		return false, errors.New("eucaptcha: response body too large")
	}
	if len(bytes.TrimSpace(body)) == 0 {
		return false, errors.New("eucaptcha: empty body")
	}
	var verify eucaptchaVerifyResponse
	if err := json.Unmarshal(body, &verify); err != nil {
		return false, err
	}
	if !verify.Success {
		return false, nil
	}
	if verify.Train != nil && *verify.Train {
		return false, nil
	}
	return true, nil
}
