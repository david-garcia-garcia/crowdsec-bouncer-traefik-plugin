package captcha

import (
	"bytes"
	"encoding/json"
	"log/slog"
	"mime"
	"net/http"
	"net/url"

	"github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pkg/configuration"
	"github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pkg/logger"
)

// siteverifyVerifier posts secret+response to a siteverify URL and reads success.
type siteverifyVerifier struct {
	httpClient   *http.Client
	secretKey    string
	validateURL  string
	validateBody string
	log          *slog.Logger
}

// newSiteverifyVerifier stores the siteverify POST shape used by built-ins and custom.
func newSiteverifyVerifier(httpClient *http.Client, secretKey, validateURL, validateBody string, log *slog.Logger) *siteverifyVerifier {
	return &siteverifyVerifier{
		httpClient:   httpClient,
		secretKey:    secretKey,
		validateURL:  validateURL,
		validateBody: validateBody,
		log:          log,
	}
}

// responseProvider is the siteverify JSON success bit.
type responseProvider struct {
	Success bool `json:"success"`
}

// siteverifyRequest is the JSON body custom+json POSTs to the provider validate URL.
// RemoteIP is omitempty so an empty Pass address does not invent the field.
type siteverifyRequest struct {
	Secret   string `json:"secret"`
	Response string `json:"response"`
	RemoteIP string `json:"remoteip,omitempty"`
}

// postSiteverify POSTs secret and response to the provider validate URL.
// Custom+json sends application/json; form/omit and built-ins keep PostForm.
// remoteip is added on both encodings only when remoteIP is non-empty.
func (v *siteverifyVerifier) postSiteverify(response, remoteIP string) (*http.Response, error) {
	if v.validateBody == configuration.CaptchaCustomValidateBodyJSON {
		payload, err := json.Marshal(siteverifyRequest{Secret: v.secretKey, Response: response, RemoteIP: remoteIP})
		if err != nil {
			return nil, err
		}
		req, err := http.NewRequest(http.MethodPost, v.validateURL, bytes.NewReader(payload))
		if err != nil {
			return nil, err
		}
		req.Header.Set("Content-Type", "application/json")
		return v.httpClient.Do(req)
	}
	body := url.Values{}
	body.Add("secret", v.secretKey)
	body.Add("response", response)
	if remoteIP != "" {
		body.Add("remoteip", remoteIP)
	}
	return v.httpClient.PostForm(v.validateURL, body)
}

// Pass posts the token to siteverify and returns the decoded success bit.
// userAgent is unused; siteverify does not send it.
// A Content-Type miss is Pass-false with no error. Transport and JSON decode are the error return.
func (v *siteverifyVerifier) Pass(token, remoteIP, userAgent string) (bool, error) {
	_ = userAgent
	res, err := v.postSiteverify(token, remoteIP)
	if err != nil {
		return false, err
	}
	defer func() {
		_ = res.Body.Close()
	}()
	// Classify siteverify as JSON when the type token equals application/json.
	mediaType, _, err := mime.ParseMediaType(res.Header.Get("Content-Type"))
	if err != nil || mediaType != "application/json" {
		logger.Trace(v.log, "captcha:Validate responseType:noJson")
		return false, nil
	}
	var captchaResponse responseProvider
	err = json.NewDecoder(res.Body).Decode(&captchaResponse)
	if err != nil {
		return false, err
	}
	logger.Trace(v.log, "captcha:Validate", "success", captchaResponse.Success)
	return captchaResponse.Success, nil
}
