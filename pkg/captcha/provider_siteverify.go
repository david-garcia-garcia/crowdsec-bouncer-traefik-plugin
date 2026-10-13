package captcha

import (
	"bytes"
	"encoding/json"
	"log/slog"
	"mime"
	"net/http"
	"net/url"
	"strings"

	"github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pkg/configuration"
	"github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pkg/logger"
)

// siteverifyBuiltin is the widget and siteverify URL for one built-in provider.
type siteverifyBuiltin struct {
	widget      Widget
	validateURL string
}

// siteverifyBuiltins holds hCaptcha, classic reCAPTCHA, and Turnstile.
//
//nolint:gochecknoglobals
var siteverifyBuiltins = map[string]siteverifyBuiltin{
	configuration.HcaptchaProvider: {
		widget: Widget{
			ScriptURL:        "https://hcaptcha.com/1/api.js",
			Class:            "h-captcha",
			TokenField:       "h-captcha-response",
			RetryAfterReject: true,
		},
		validateURL: "https://api.hcaptcha.com/siteverify",
	},
	configuration.RecaptchaProvider: {
		widget: Widget{
			ScriptURL:        "https://www.google.com/recaptcha/api.js",
			Class:            "g-recaptcha",
			TokenField:       "g-recaptcha-response",
			RetryAfterReject: true,
		},
		validateURL: "https://www.google.com/recaptcha/api/siteverify",
	},
	configuration.TurnstileProvider: {
		widget: Widget{
			ScriptURL:        "https://challenges.cloudflare.com/turnstile/v0/api.js",
			Class:            "cf-turnstile",
			TokenField:       "cf-turnstile-response",
			RetryAfterReject: true,
		},
		validateURL: "https://challenges.cloudflare.com/turnstile/v0/siteverify",
	},
}

// pairSiteverify builds the built-in siteverify widget and form verifier.
// provider is hcaptcha, recaptcha, or turnstile. The validate body stays empty.
//
//nolint:ireturn // Yaegi v0.16.1 panics when New assigns a concrete verifier in one multi-value assignment.
func pairSiteverify(httpClient *http.Client, provider, secretKey string, log *slog.Logger) (Widget, Verifier) {
	builtin := siteverifyBuiltins[provider]
	return builtin.widget, newSiteverifyVerifier(httpClient, secretKey, builtin.validateURL, "", log)
}

// pairCustom builds the operator-supplied siteverify widget and verifier.
// validateBody may be form, json, or empty. Built-ins use pairSiteverify.
//
//nolint:ireturn // Yaegi v0.16.1 panics when New assigns a concrete verifier in one multi-value assignment.
func pairCustom(httpClient *http.Client, secretKey, scriptURL, className, tokenField, validateURL, validateBody string, log *slog.Logger) (Widget, Verifier) {
	return Widget{
		ScriptURL:        scriptURL,
		Class:            className,
		TokenField:       tokenField,
		RetryAfterReject: true,
	}, newSiteverifyVerifier(httpClient, secretKey, validateURL, strings.TrimSpace(validateBody), log)
}

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
