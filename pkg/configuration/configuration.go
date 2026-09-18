// Package configuration implements plugin Config, default Config values and validation param functions.
package configuration

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"strings"
	"text/template"
	"time"

	"github.com/david-garcia-garcia/traefik-middleware-utilities/backendbackoff"
	ip "github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pkg/ip"
)

// Enums for crowdsec mode.
const (
	AloneMode         = "alone"
	StreamMode        = "stream"
	LiveMode          = "live"
	NoneMode          = "none"
	AppsecMode        = "appsec"
	HTTPS             = "https"
	HTTP              = "http"
	LogDEBUG          = "DEBUG"
	LogINFO           = "INFO"
	LogWARN           = "WARN"
	LogERROR          = "ERROR"
	ReasonTECH        = "TECHNICAL_ISSUE"
	ReasonLAPI        = "LAPI"
	ReasonAPPSEC      = "APPSEC"
	HcaptchaProvider  = "hcaptcha"
	RecaptchaProvider = "recaptcha"
	TurnstileProvider = "turnstile"
	CustomProvider    = "custom"
	// CaptchaCustomValidateBodyForm is urlencoded siteverify secret+response (same as omit).
	CaptchaCustomValidateBodyForm = "form"
	// CaptchaCustomValidateBodyJSON is POST application/json secret+response (custom only).
	CaptchaCustomValidateBodyJSON = "json"
	// FailureActionPassthrough lets the request continue when LAPI or AppSec is down.
	FailureActionPassthrough = "passthrough"
	// FailureActionBan remediates as a ban when LAPI or AppSec is down.
	FailureActionBan = "ban"
	// FailureActionCaptcha remediates with pkg/captcha when LAPI or AppSec is down.
	FailureActionCaptcha = "captcha"
)

// Config the plugin configuration.
type Config struct {
	Enabled                                    bool              `json:"enabled,omitempty"`
	LogLevel                                   string            `json:"logLevel,omitempty"`
	LogFormat                                  string            `json:"logFormat,omitempty"`
	LogFilePath                                string            `json:"logFilePath,omitempty"`
	CrowdsecMode                               string            `json:"crowdsecMode,omitempty"`
	CrowdsecAppsecEnabled                      bool              `json:"crowdsecAppsecEnabled,omitempty"`
	CrowdsecAppsecScheme                       string            `json:"crowdsecAppsecScheme,omitempty"`
	CrowdsecAppsecHost                         string            `json:"crowdsecAppsecHost,omitempty"`
	CrowdsecAppsecPath                         string            `json:"crowdsecAppsecPath,omitempty"`
	CrowdsecAppsecKey                          string            `json:"crowdsecAppsecKey,omitempty"`
	CrowdsecAppsecKeyFile                      string            `json:"crowdsecAppsecKeyFile,omitempty"`
	CrowdsecAppsecTLSInsecureVerify            bool              `json:"crowdsecAppsecTlsInsecureVerify,omitempty"`
	CrowdsecAppsecTLSCertificateAuthority      string            `json:"crowdsecAppsecTlsCertificateAuthority,omitempty"`
	CrowdsecAppsecTLSCertificateAuthorityFile  string            `json:"crowdsecAppsecTlsCertificateAuthorityFile,omitempty"`
	CrowdsecAppsecTLSCertificateBouncer        string            `json:"crowdsecAppsecTlsCertificateBouncer,omitempty"`
	CrowdsecAppsecTLSCertificateBouncerFile    string            `json:"crowdsecAppsecTlsCertificateBouncerFile,omitempty"`
	CrowdsecAppsecTLSCertificateBouncerKey     string            `json:"crowdsecAppsecTlsCertificateBouncerKey,omitempty"`
	CrowdsecAppsecTLSCertificateBouncerKeyFile string            `json:"crowdsecAppsecTlsCertificateBouncerKeyFile,omitempty"`
	CrowdsecAppsecBodyLimit                    int64             `json:"crowdsecAppsecBodyLimit,omitempty"`
	CrowdsecAppsecFailureAction                string            `json:"crowdsecAppsecFailureAction,omitempty"`
	CrowdsecLapiScheme                         string            `json:"crowdsecLapiScheme,omitempty"`
	CrowdsecLapiHost                           string            `json:"crowdsecLapiHost,omitempty"`
	CrowdsecLapiPath                           string            `json:"crowdsecLapiPath,omitempty"`
	CrowdsecLapiKey                            string            `json:"crowdsecLapiKey,omitempty"`
	CrowdsecLapiKeyFile                        string            `json:"crowdsecLapiKeyFile,omitempty"`
	CrowdsecLapiTLSInsecureVerify              bool              `json:"crowdsecLapiTlsInsecureVerify,omitempty"`
	CrowdsecLapiTLSCertificateAuthority        string            `json:"crowdsecLapiTlsCertificateAuthority,omitempty"`
	CrowdsecLapiTLSCertificateAuthorityFile    string            `json:"crowdsecLapiTlsCertificateAuthorityFile,omitempty"`
	CrowdsecLapiTLSCertificateBouncer          string            `json:"crowdsecLapiTlsCertificateBouncer,omitempty"`
	CrowdsecLapiTLSCertificateBouncerFile      string            `json:"crowdsecLapiTlsCertificateBouncerFile,omitempty"`
	CrowdsecLapiTLSCertificateBouncerKey       string            `json:"crowdsecLapiTlsCertificateBouncerKey,omitempty"`
	CrowdsecLapiTLSCertificateBouncerKeyFile   string            `json:"crowdsecLapiTlsCertificateBouncerKeyFile,omitempty"`
	CrowdsecCapiMachineID                      string            `json:"crowdsecCapiMachineId,omitempty"`
	CrowdsecCapiMachineIDFile                  string            `json:"crowdsecCapiMachineIdFile,omitempty"`
	CrowdsecCapiPassword                       string            `json:"crowdsecCapiPassword,omitempty"`
	CrowdsecCapiPasswordFile                   string            `json:"crowdsecCapiPasswordFile,omitempty"`
	CrowdsecCapiScenarios                      []string          `json:"crowdsecCapiScenarios,omitempty"`
	UpdateIntervalSeconds                      int64             `json:"updateIntervalSeconds,omitempty"`
	MetricsUpdateIntervalSeconds               int64             `json:"metricsUpdateIntervalSeconds,omitempty"`
	UpdateMaxFailure                           int64             `json:"updateMaxFailure,omitempty"`
	CrowdsecLapiFailureAction                  string            `json:"crowdsecLapiFailureAction,omitempty"`
	StreamStartupBlock                         bool              `json:"streamStartupBlock,omitempty"`
	DefaultDecisionSeconds                     int64             `json:"defaultDecisionSeconds,omitempty"`
	RemediationStatusCode                      int               `json:"remediationStatusCode,omitempty"`
	HTTPTimeoutSeconds                         int64             `json:"httpTimeoutSeconds,omitempty"`
	BackendBackoffFailureRatio                 float64           `json:"backendBackoffFailureRatio,omitempty"`
	BackendBackoffTripFailures                 int64             `json:"backendBackoffTripFailures,omitempty"`
	BackendBackoffBaseCooldownSeconds          int64             `json:"backendBackoffBaseCooldownSeconds,omitempty"`
	BackendBackoffMaxCooldownSeconds           int64             `json:"backendBackoffMaxCooldownSeconds,omitempty"`
	BackendBackoffJitter                       float64           `json:"backendBackoffJitter,omitempty"`
	BackendBackoffTTLSeconds                   int64             `json:"backendBackoffTTLSeconds,omitempty"` //nolint:tagliatelle // spec key keeps TTL
	TraceHeadersCustomName                     string            `json:"traceHeadersCustomName,omitempty"`
	RemediationHeadersCustomName               string            `json:"remediationHeadersCustomName,omitempty"`
	ForwardedHeadersCustomName                 string            `json:"forwardedHeadersCustomName,omitempty"`
	ForwardedHeadersInsecure                   bool              `json:"forwardedHeadersInsecure,omitempty"`
	DecisionScopeHeaders                       map[string]string `json:"decisionScopeHeaders,omitempty"`
	ForwardedHeadersTrustedIPs                 []string          `json:"forwardedHeadersTrustedIps,omitempty"`
	ClientTrustedIPs                           []string          `json:"clientTrustedIps,omitempty"`
	RedisCacheEnabled                          bool              `json:"redisCacheEnabled,omitempty"`
	RedisCacheHost                             string            `json:"redisCacheHost,omitempty"`
	RedisCacheReadHosts                        []string          `json:"redisCacheReadHosts,omitempty"`
	RedisCachePassword                         string            `json:"redisCachePassword,omitempty"`
	RedisCachePasswordFile                     string            `json:"redisCachePasswordFile,omitempty"`
	RedisCacheDatabase                         string            `json:"redisCacheDatabase,omitempty"`
	RedisCacheUnreachableBlock                 bool              `json:"redisCacheUnreachableBlock,omitempty"`
	BanFilePath                                string            `json:"banFilePath,omitempty"`
	CaptchaFilePath                            string            `json:"captchaFilePath,omitempty"`
	CaptchaProvider                            string            `json:"captchaProvider,omitempty"`
	CaptchaCustomJsURL                         string            `json:"captchaCustomJsUrl,omitempty"`
	CaptchaCustomValidateURL                   string            `json:"captchaCustomValidateUrl,omitempty"`
	CaptchaCustomKey                           string            `json:"captchaCustomKey,omitempty"`
	CaptchaCustomResponse                      string            `json:"captchaCustomResponse,omitempty"`
	CaptchaCustomChallengeURL                  string            `json:"captchaCustomChallengeUrl,omitempty"`
	CaptchaCustomValidateBody                  string            `json:"captchaCustomValidateBody,omitempty"`
	CaptchaSiteKey                             string            `json:"captchaSiteKey,omitempty"`
	CaptchaSiteKeyFile                         string            `json:"captchaSiteKeyFile,omitempty"`
	CaptchaSecretKey                           string            `json:"captchaSecretKey,omitempty"`
	CaptchaSecretKeyFile                       string            `json:"captchaSecretKeyFile,omitempty"`
	CaptchaGateSecret                          string            `json:"captchaGateSecret,omitempty"`
	CaptchaGateSecretFile                      string            `json:"captchaGateSecretFile,omitempty"`
	CaptchaGateBindIP                          bool              `json:"captchaGateBindIp,omitempty"`
	CaptchaGracePeriodSeconds                  int64             `json:"captchaGracePeriodSeconds,omitempty"`
}

func contains(source []string, target string) bool {
	for _, item := range source {
		if item == target {
			return true
		}
	}
	return false
}

// validateFailureAction accepts empty (treated as ban at runtime), passthrough, ban, or captcha.
func validateFailureAction(name, action, captchaProvider string) error {
	if action == "" {
		return nil
	}
	if !contains([]string{FailureActionPassthrough, FailureActionBan, FailureActionCaptcha}, action) {
		return errors.New(name + ": must be one of 'passthrough', 'ban' or 'captcha'")
	}
	if action == FailureActionCaptcha && captchaProvider == "" {
		return errors.New(name + ": captcha requires CaptchaProvider")
	}
	return nil
}

// EffectiveFailureAction maps empty config to ban (plugin default).
func EffectiveFailureAction(action string) string {
	if action == "" {
		return FailureActionBan
	}
	return action
}

// New creates the default plugin configuration.
func New() *Config {
	return &Config{
		Enabled:                           false,
		LogLevel:                          LogINFO,
		LogFormat:                         "common",
		LogFilePath:                       "",
		CrowdsecMode:                      LiveMode,
		CrowdsecAppsecEnabled:             false,
		CrowdsecAppsecBodyLimit:           10485760,
		CrowdsecAppsecFailureAction:       FailureActionBan,
		CrowdsecAppsecScheme:              "",
		CrowdsecAppsecHost:                "crowdsec:7422",
		CrowdsecAppsecPath:                "/",
		CrowdsecAppsecKey:                 "",
		CrowdsecAppsecTLSInsecureVerify:   false,
		CrowdsecLapiScheme:                HTTP,
		CrowdsecLapiHost:                  "crowdsec:8080",
		CrowdsecLapiPath:                  "/",
		CrowdsecLapiKey:                   "",
		CrowdsecLapiTLSInsecureVerify:     false,
		UpdateIntervalSeconds:             60,
		MetricsUpdateIntervalSeconds:      600,
		UpdateMaxFailure:                  0,
		CrowdsecLapiFailureAction:         FailureActionBan,
		StreamStartupBlock:                true,
		DefaultDecisionSeconds:            60,
		RemediationStatusCode:             http.StatusForbidden,
		HTTPTimeoutSeconds:                10,
		BackendBackoffFailureRatio:        0.30,
		BackendBackoffTripFailures:        5,
		BackendBackoffBaseCooldownSeconds: 1,
		BackendBackoffMaxCooldownSeconds:  10,
		BackendBackoffJitter:              0.10,
		BackendBackoffTTLSeconds:          60,
		CaptchaProvider:                   "",
		CaptchaCustomJsURL:                "",
		CaptchaCustomValidateURL:          "",
		CaptchaCustomKey:                  "",
		CaptchaCustomResponse:             "",
		CaptchaCustomChallengeURL:         "",
		CaptchaCustomValidateBody:         "",
		CaptchaSiteKey:                    "",
		CaptchaSecretKey:                  "",
		CaptchaGateBindIP:                 true,
		CaptchaGracePeriodSeconds:         1800,
		CaptchaFilePath:                   "/captcha.html",
		BanFilePath:                       "",
		TraceHeadersCustomName:            "",
		RemediationHeadersCustomName:      "",
		ForwardedHeadersCustomName:        "X-Forwarded-For",
		ForwardedHeadersInsecure:          false,
		DecisionScopeHeaders:              map[string]string{},
		ForwardedHeadersTrustedIPs:        []string{},
		ClientTrustedIPs:                  []string{},
		RedisCacheEnabled:                 false,
		RedisCacheHost:                    "redis:6379",
		RedisCacheReadHosts:               []string{},
		RedisCachePassword:                "",
		RedisCacheDatabase:                "",
		RedisCacheUnreachableBlock:        true,
	}
}

// BackendBackoffConfig maps the shared plugin knobs onto the published gate Config.
func (c *Config) BackendBackoffConfig() backendbackoff.Config {
	return backendbackoff.Config{
		FailureRatio: c.BackendBackoffFailureRatio,
		TripFailures: int(c.BackendBackoffTripFailures),
		BaseCooldown: time.Duration(c.BackendBackoffBaseCooldownSeconds) * time.Second,
		MaxCooldown:  time.Duration(c.BackendBackoffMaxCooldownSeconds) * time.Second,
		Jitter:       c.BackendBackoffJitter,
		TTL:          time.Duration(c.BackendBackoffTTLSeconds) * time.Second,
	}
}

// GetVariable get variable from file and after in the variables gave by user.
func GetVariable(config *Config, key string) (string, error) {
	value := ""
	object := reflect.Indirect(reflect.ValueOf(config))
	field := object.FieldByName(key + "File")
	// Here linter say you should simplify this code, but lets not, performance is important not clarity and complexity
	fp := field.String()
	if fp != "" {
		file, err := os.Stat(fp)
		if err != nil {
			return value, fmt.Errorf("%s:%s invalid path %w", key, fp, err)
		}
		if file.IsDir() {
			return value, fmt.Errorf("%s:%s path must be a file", key, fp)
		}
		fileValue, err := os.ReadFile(filepath.Clean(fp))
		if err != nil {
			return value, fmt.Errorf("%s:%s read file path failed %w", key, fp, err)
		}
		value = string(fileValue)
		return strings.TrimSpace(value), nil
	}
	field = object.FieldByName(key)
	value = field.String()
	return strings.TrimSpace(value), nil
}

func getContentTypeFromPath(path string) string {
	if path == "" {
		return ""
	}
	ext := strings.ToLower(filepath.Ext(path))
	contentTypeMap := map[string]string{
		".html": "text/html; charset=utf-8",
		".htm":  "text/html; charset=utf-8",
		".json": "application/json",
		".txt":  "text/plain",
		".xml":  "application/xml",
		".js":   "application/javascript",
		".css":  "text/css",
	}
	if contentType, ok := contentTypeMap[ext]; ok {
		return contentType
	}
	// Default to HTML for backward compatibility
	return "text/html; charset=utf-8"
}

// GetTemplate get compiled template with {{ and }} delimiters.
// Uses text/template for all file types to avoid HTML escaping issues.
func GetTemplate(path string) (*template.Template, string, error) {
	if path == "" {
		return nil, "", errors.New("no template file provided")
	}
	contentType := getContentTypeFromPath(path)
	//nolint:gosec
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, "", err
	}
	content := string(b)
	compiledTemplate, err := template.New(filepath.Base(path)).Delims("{{", "}}").Parse(content)
	if err != nil {
		return nil, "", fmt.Errorf("impossible to compile template %s: %w", path, err)
	}
	return compiledTemplate, contentType, nil
}

// CustomCaptchaResourcePath returns the browser path a configured custom captcha
// resource URL is matched on, or "" when the value names no absolute path.
// Operators may configure either an absolute URL or a bare path; scheme, host, query
// and fragment never take part in the match.
func CustomCaptchaResourcePath(rawURL string) string {
	if rawURL == "" {
		return ""
	}
	parsed, err := url.Parse(rawURL)
	if err != nil {
		return ""
	}
	if !strings.HasPrefix(parsed.Path, "/") {
		return ""
	}
	return parsed.Path
}

// ValidateParams validate all the param gave by user.
func ValidateParams(config *Config, log *slog.Logger) error {
	if err := validateParamsRequired(config); err != nil {
		return err
	}

	if err := validateDecisionScopeHeaders(config); err != nil {
		return err
	}

	if err := validateCaptcha(config); err != nil {
		return err
	}

	if err := validateParamsIPs(log, config.ForwardedHeadersTrustedIPs, "ForwardedHeadersTrustedIPs"); err != nil {
		return err
	}
	if err := validateParamsIPs(log, config.ClientTrustedIPs, "ClientTrustedIPs"); err != nil {
		return err
	}

	// Redis password file is unused when Redis is off; skip Stat/read so leftovers do not fail startup.
	if config.RedisCacheEnabled {
		if _, err := GetVariable(config, "RedisCachePassword"); err != nil {
			return err
		}
	}

	if err := validateCaptchaCredentialsAndTemplates(config); err != nil {
		return err
	}

	if config.CrowdsecMode == AloneMode {
		if _, err := GetVariable(config, "CrowdsecCapiMachineID"); err != nil {
			return err
		}
		if _, err := GetVariable(config, "CrowdsecCapiPassword"); err != nil {
			return err
		}
	} else {
		if err := validateLapiURLAndKeys(config); err != nil {
			return err
		}
	}

	// AppSec URL, key file, and HTTPS CA only when this router will open AppSec.
	if config.CrowdsecAppsecEnabled {
		if err := validateAppsecURLKeyAndTLS(config); err != nil {
			return err
		}
	}

	warnUnenforcedAppsecMode(config, log)

	if err := validateBackendBackoff(config); err != nil {
		return err
	}

	return validateLogging(config)
}

// validateBackendBackoff rejects knobs the published Gate constructor would reject.
func validateBackendBackoff(config *Config) error {
	gate, err := backendbackoff.New(config.BackendBackoffConfig())
	if err != nil {
		return fmt.Errorf("backendBackoff: %w", err)
	}
	gate.Close()
	return nil
}

// warnUnenforcedAppsecMode reports the one accepted combination that enforces nothing. appsec mode
// selects no decision source, so with the AppSec leg off the middleware only calls next. This is a
// warning and not an error on purpose: the plugin doing nothing is not worth refusing to boot over,
// and implying crowdsecAppsecEnabled would point at the crowdsec:7422 default and, with the default
// ban failure action, ban every request on that router.
func warnUnenforcedAppsecMode(config *Config, log *slog.Logger) {
	if config.CrowdsecMode != AppsecMode || config.CrowdsecAppsecEnabled {
		return
	}
	log.Warn("crowdsecMode is 'appsec' while crowdsecAppsecEnabled is false: " +
		"this middleware checks nothing at all, no CrowdSec decisions and no AppSec inspection. " +
		"Set crowdsecAppsecEnabled to true, or pick a crowdsecMode that queries LAPI ('none', 'live', 'stream' or 'alone')")
}

func effectiveAppsecScheme(config *Config) string {
	if config.CrowdsecAppsecScheme != "" {
		return config.CrowdsecAppsecScheme
	}
	return config.CrowdsecLapiScheme
}

// validateCaptchaCredentialsAndTemplates checks captcha credentials and optional HTML templates.
func validateCaptchaCredentialsAndTemplates(config *Config) error {
	if err := validateEnabledCaptchaSettings(config); err != nil {
		return err
	}
	if config.BanFilePath != "" {
		if _, _, err := GetTemplate(config.BanFilePath); err != nil {
			return err
		}
	}
	return nil
}

// validateEnabledCaptchaSettings checks provider credentials, the optional custom
// challenge URL, and templates when a provider is set.
func validateEnabledCaptchaSettings(config *Config) error {
	if config.CaptchaProvider == "" {
		return nil
	}
	if err := validateCaptchaCredentials(config); err != nil {
		return err
	}
	// Empty is valid; it only leaves the challenge path out of the passthrough match set.
	// A value that names no path would silently never match, so reject it instead.
	if config.CaptchaProvider == CustomProvider && config.CaptchaCustomChallengeURL != "" &&
		CustomCaptchaResourcePath(config.CaptchaCustomChallengeURL) == "" {
		return errors.New("CaptchaCustomChallengeURL: " + config.CaptchaCustomChallengeURL +
			" has no absolute path, so no browser request could ever match it")
	}
	gateSecret, err := GetVariable(config, "CaptchaGateSecret")
	if err != nil {
		return err
	}
	if gateSecret == "" {
		return errors.New("CaptchaGateSecret: cannot be empty when CaptchaProvider is set")
	}
	if config.CaptchaFilePath == "" {
		return nil
	}
	if _, _, err := GetTemplate(config.CaptchaFilePath); err != nil {
		return err
	}
	return nil
}

// validateCaptchaCredentials resolves site and secret keys and rejects an empty
// trimmed value for each field independently, site first. Lookup errors stay.
func validateCaptchaCredentials(config *Config) error {
	siteKey, err := GetVariable(config, "CaptchaSiteKey")
	if err != nil {
		return err
	}
	if siteKey == "" {
		return errors.New("CaptchaSiteKey: cannot be empty when CaptchaProvider is set")
	}
	secretKey, err := GetVariable(config, "CaptchaSecretKey")
	if err != nil {
		return err
	}
	if secretKey == "" {
		return errors.New("CaptchaSecretKey: cannot be empty when CaptchaProvider is set")
	}
	return nil
}

func validateLapiURLAndKeys(config *Config) error {
	if err := validateURL("CrowdsecLapi", config.CrowdsecLapiScheme, config.CrowdsecLapiHost, config.CrowdsecLapiPath); err != nil {
		return err
	}

	lapiKey, err := GetVariable(config, "CrowdsecLapiKey")
	if err != nil {
		return err
	}
	certBouncer, err := GetVariable(config, "CrowdsecLapiTLSCertificateBouncer")
	if err != nil {
		return err
	}
	certBouncerKey, err := GetVariable(config, "CrowdsecLapiTLSCertificateBouncerKey")
	if err != nil {
		return err
	}

	if lapiKey == "" && (certBouncer == "" || certBouncerKey == "") && config.CrowdsecMode != AppsecMode {
		return errors.New("CrowdsecLapiKey || (CrowdsecLapiTLSCertificateBouncer && CrowdsecLapiTLSCertificateBouncerKey): cannot be all empty")
	}
	if lapiKey != "" && (certBouncer == "" || certBouncerKey == "") {
		lapiKey = strings.TrimSpace(lapiKey)
		if err = validateParamsAPIKey(lapiKey, "CrowdsecLapiKey"); err != nil {
			return err
		}
	}

	if config.CrowdsecLapiScheme == HTTPS && !config.CrowdsecLapiTLSInsecureVerify {
		if err = validateParamsTLS(config, "CrowdsecLapi"); err != nil {
			return err
		}
	}
	return nil
}

// validateAppsecURLKeyAndTLS checks the AppSec listener URL, optional key, and HTTPS CA.
func validateAppsecURLKeyAndTLS(config *Config) error {
	appsecScheme := effectiveAppsecScheme(config)
	if err := validateURL("CrowdsecAppsec", appsecScheme, config.CrowdsecAppsecHost, config.CrowdsecAppsecPath); err != nil {
		return err
	}

	// Enabled AppSec needs a listener host. validateURL only asks NewRequest to
	// accept scheme://host/path, so an empty host (http:///) still returns nil.
	if err := rejectMissingEnabledAppsecHost(config, appsecScheme); err != nil {
		return err
	}

	appsecKey, err := GetVariable(config, "CrowdsecAppsecKey")
	if err != nil {
		return err
	}
	if appsecKey != "" {
		appsecKey = strings.TrimSpace(appsecKey)
		if err = validateParamsAPIKey(appsecKey, "CrowdsecAppsecKey"); err != nil {
			return err
		}
	}

	if config.CrowdsecAppsecScheme == HTTPS && !config.CrowdsecAppsecTLSInsecureVerify {
		if err = validateParamsTLS(config, "CrowdsecAppsec"); err != nil {
			return err
		}
	}
	return nil
}

// rejectMissingEnabledAppsecHost fails when AppSec is on and the listener host is missing.
func rejectMissingEnabledAppsecHost(config *Config, appsecScheme string) error {
	if !config.CrowdsecAppsecEnabled {
		return nil
	}
	appsecURL := url.URL{Scheme: appsecScheme, Host: config.CrowdsecAppsecHost, Path: config.CrowdsecAppsecPath}
	appsecReq, err := http.NewRequest(http.MethodGet, appsecURL.String(), nil)
	if err != nil {
		return fmt.Errorf("CrowdsecLapiScheme://CrowdsecAppsecHost: '%v://%v%v' must be a valid URL", appsecScheme, config.CrowdsecAppsecHost, config.CrowdsecAppsecPath)
	}
	if config.CrowdsecAppsecHost == "" || appsecReq.URL.Host == "" {
		return errors.New("CrowdsecAppsecHost: cannot be empty when CrowdsecAppsecEnabled is true")
	}
	return nil
}

func validateLogging(config *Config) error {
	if !contains([]string{LogDEBUG, LogINFO, LogWARN, LogERROR}, strings.ToUpper(config.LogLevel)) {
		return fmt.Errorf("LogLevel should be one of (%s,%s,%s,%s)", LogDEBUG, LogINFO, LogWARN, LogERROR)
	}
	if config.LogFilePath != "" {
		_, err := os.OpenFile(filepath.Clean(config.LogFilePath), os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0600)
		if err != nil {
			return fmt.Errorf("LogFilePath is not writable %w", err)
		}
	}
	return nil
}

// validateDecisionScopeHeaders rejects empty names and Ip/Range keys.
func validateDecisionScopeHeaders(config *Config) error {
	for rawScope, rawHeader := range config.DecisionScopeHeaders {
		scope := strings.TrimSpace(rawScope)
		if scope == "" {
			return errors.New("decisionScopeHeaders: scope name cannot be empty")
		}
		switch strings.ToLower(scope) {
		case "ip", "range":
			return fmt.Errorf("decisionScopeHeaders: %q cannot be mapped to a header", scope)
		}
		if strings.TrimSpace(rawHeader) == "" {
			return fmt.Errorf("decisionScopeHeaders: header for %q cannot be empty", scope)
		}
	}
	return nil
}

func validateURL(variable, scheme, host, path string) error {
	// This only check that the format of the URL scheme://host/path is correct and do not make requests
	testURL := url.URL{Scheme: scheme, Host: host, Path: path}
	if _, err := http.NewRequest(http.MethodGet, testURL.String(), nil); err != nil {
		return fmt.Errorf("CrowdsecLapiScheme://%sHost: '%v://%v%v' must be a valid URL", variable, scheme, host, path)
	}
	return nil
}

// validHeaderFieldByte reports whether b is a valid byte in a header
// field name. RFC 7230 says:
// valid ! # $ % & ' * + - . ^ _ ` | ~ DIGIT ALPHA
// See https://httpwg.github.io/specs/rfc7230.html#rule.token.separators
func validateParamsAPIKey(key string, paramName string) error {
	reg := regexp.MustCompile("^[a-zA-Z0-9 !#$%&'*+-.^_`|~=/]*$")
	if !reg.MatchString(key) {
		return fmt.Errorf("%s doesn't validate this regexp: '/%s/'", paramName, reg.String())
	}
	return nil
}

func validateParamsTLS(config *Config, prefix string) error {
	certAuth, err := GetVariable(config, prefix+"TLSCertificateAuthority")
	if err != nil {
		return err
	}
	if certAuth == "" {
		// No custom CA — runtime will fall back to the system trust store.
		return nil
	}
	tlsConfig := new(tls.Config)
	tlsConfig.RootCAs = x509.NewCertPool()
	if !tlsConfig.RootCAs.AppendCertsFromPEM([]byte(certAuth)) {
		return errors.New("failed parsing pem file")
	}
	return nil
}

func validateParamsIPs(log *slog.Logger, listIP []string, key string) error {
	if len(listIP) > 0 {
		if _, err := ip.NewChecker(log, listIP); err != nil {
			return fmt.Errorf("%s must be a list of IP/CIDR :%w", key, err)
		}
	}
	return nil
}

func validateCaptcha(config *Config) error {
	if !contains([]string{"", HcaptchaProvider, RecaptchaProvider, TurnstileProvider, CustomProvider}, config.CaptchaProvider) {
		return fmt.Errorf("CaptchaProvider: must be one of '%s', '%s', '%s' or '%s'", HcaptchaProvider, RecaptchaProvider, TurnstileProvider, CustomProvider)
	}
	// Accept only empty, form, or json after trim; json is custom-only.
	validateBody := strings.TrimSpace(config.CaptchaCustomValidateBody)
	if validateBody != "" && validateBody != CaptchaCustomValidateBodyForm && validateBody != CaptchaCustomValidateBodyJSON {
		return errors.New("CaptchaCustomValidateBody: must be empty, form, or json")
	}
	if validateBody == CaptchaCustomValidateBodyJSON && config.CaptchaProvider != CustomProvider {
		return errors.New("CaptchaCustomValidateBody: json is only valid when CaptchaProvider is custom")
	}
	if config.CaptchaProvider == CustomProvider {
		if config.CaptchaCustomKey == "" || config.CaptchaCustomResponse == "" || config.CaptchaCustomValidateURL == "" || config.CaptchaCustomJsURL == "" {
			return fmt.Errorf(
				"CaptchaProvider: provider is custom, captchaCustom variables must be filled: CaptchaCustomKey:%s, CaptchaCustomResponse:%s, CaptchaCustomValidateURL:%s, CaptchaCustomJsURL:%s",
				config.CaptchaCustomKey,
				config.CaptchaCustomResponse,
				config.CaptchaCustomValidateURL,
				config.CaptchaCustomJsURL,
			)
		}
	}
	return nil
}

func validateParamsRequired(config *Config) error {
	requiredStrings := map[string]string{
		"CrowdsecLapiScheme": config.CrowdsecLapiScheme,
		"CrowdsecLapiHost":   config.CrowdsecLapiHost,
		"CrowdsecMode":       config.CrowdsecMode,
	}
	for key, val := range requiredStrings {
		if len(val) == 0 {
			return errors.New(key + ": cannot be empty")
		}
	}
	requiredInt0 := map[string]int64{
		"CrowdsecAppsecBodyLimit":      config.CrowdsecAppsecBodyLimit,
		"MetricsUpdateIntervalSeconds": config.MetricsUpdateIntervalSeconds,
	}
	for key, val := range requiredInt0 {
		if val < 0 {
			return errors.New(key + ": cannot be less than 0")
		}
	}
	requiredInt1 := map[string]int64{
		"UpdateIntervalSeconds":     config.UpdateIntervalSeconds,
		"DefaultDecisionSeconds":    config.DefaultDecisionSeconds,
		"HTTPTimeoutSeconds":        config.HTTPTimeoutSeconds,
		"CaptchaGracePeriodSeconds": config.CaptchaGracePeriodSeconds,
	}
	for key, val := range requiredInt1 {
		if val < 1 {
			return errors.New(key + ": cannot be less than 1")
		}
	}
	if config.UpdateMaxFailure < -1 {
		return errors.New("UpdateMaxFailure: cannot be less than -1")
	}
	if err := validateFailureAction("CrowdsecLapiFailureAction", config.CrowdsecLapiFailureAction, config.CaptchaProvider); err != nil {
		return err
	}
	if err := validateFailureAction("CrowdsecAppsecFailureAction", config.CrowdsecAppsecFailureAction, config.CaptchaProvider); err != nil {
		return err
	}
	if config.CrowdsecAppsecBodyLimit < 0 {
		return errors.New("CrowdsecAppsecBodyLimit: cannot be less than 0")
	}
	if config.RemediationStatusCode < 100 || config.RemediationStatusCode >= 600 {
		return errors.New("RemediationStatusCode: cannot be less than 100 and more than 600")
	}

	if !contains([]string{NoneMode, LiveMode, StreamMode, AloneMode, AppsecMode}, config.CrowdsecMode) {
		return errors.New("CrowdsecMode: must be one of 'none', 'live', 'stream', 'alone' or 'appsec'")
	}
	if !contains([]string{HTTP, HTTPS}, config.CrowdsecLapiScheme) {
		return errors.New("CrowdsecLapiScheme: must be one of 'http' or 'https'")
	}
	if !contains([]string{HTTP, HTTPS, ""}, config.CrowdsecAppsecScheme) {
		return errors.New("CrowdsecAppsecScheme: must be one of 'http' or 'https'")
	}
	return nil
}

func getTLSConfig(config *Config, log *slog.Logger, prefix, scheme string, insecureVerify bool) (*tls.Config, error) {
	tlsConfig := new(tls.Config)
	if scheme != HTTPS {
		log.Debug("getTLSConfig:" + prefix + "Scheme https:no")
		return tlsConfig, nil
	}
	// RootCAs is intentionally left nil unless a custom CA is provided:
	// crypto/tls then falls back to x509.SystemCertPool(), which is what we
	// want when the LAPI is exposed behind a reverse proxy with a publicly
	// trusted certificate (e.g. Let's Encrypt).
	//nolint:nestif
	if insecureVerify {
		tlsConfig.InsecureSkipVerify = true
		log.Debug("getTLSConfig:" + prefix + "TLSInsecureVerify tlsInsecure:true")
	} else {
		certAuthority, err := GetVariable(config, prefix+"TLSCertificateAuthority")
		if err != nil {
			return nil, err
		}
		if len(certAuthority) > 0 {
			tlsConfig.RootCAs = x509.NewCertPool()
			if !tlsConfig.RootCAs.AppendCertsFromPEM([]byte(certAuthority)) {
				return nil, errors.New("getTLSConfig:" + prefix + " cannot load CA and verify cert is enabled")
			}
			log.Debug("getTLSConfig:" + prefix + "TLSCertificateAuthority CA added successfully")
		} else {
			log.Debug("getTLSConfig:" + prefix + " no CA provided, using system trust store")
		}
	}
	certBouncer, err := GetVariable(config, prefix+"TLSCertificateBouncer")
	if err != nil {
		return nil, err
	}
	certBouncerKey, err := GetVariable(config, prefix+"TLSCertificateBouncerKey")
	if err != nil {
		return nil, err
	}
	if certBouncer == "" || certBouncerKey == "" {
		return tlsConfig, nil
	}
	clientCert, err := tls.X509KeyPair([]byte(certBouncer), []byte(certBouncerKey))
	if err != nil {
		return nil, fmt.Errorf("getTLSClientConfigCrowdsec impossible to generate ClientCert %w", err)
	}
	tlsConfig.Certificates = append(tlsConfig.Certificates, clientCert)

	return tlsConfig, nil
}

// GetTLSConfigCrowdsec get TLS config from Config.
func GetTLSConfigCrowdsec(config *Config, log *slog.Logger, isAppsec bool) (*tls.Config, error) {
	var prefix string
	if isAppsec && config.CrowdsecAppsecScheme != "" {
		prefix = "CrowdsecAppsec"
		return getTLSConfig(config, log, prefix, config.CrowdsecAppsecScheme, config.CrowdsecAppsecTLSInsecureVerify)
	}
	prefix = "CrowdsecLapi"
	return getTLSConfig(config, log, prefix, config.CrowdsecLapiScheme, config.CrowdsecLapiTLSInsecureVerify)
}
