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

	ip "github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pkg/ip"
)

// Enums for crowdsec mode.
const (
	AloneMode         = "alone"
	StreamMode        = "stream"
	LiveMode          = "live"
	NoneMode          = "none"
	HTTPS             = "https"
	HTTP              = "http"
	LogTRACE          = "TRACE"
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
	BouncerEnabled                             bool                         `json:"bouncerEnabled,omitempty"`
	LogLevel                                   string                       `json:"logLevel,omitempty"`
	LogFormat                                  string                       `json:"logFormat,omitempty"`
	LogFilePath                                string                       `json:"logFilePath,omitempty"`
	LapiMode                                   string                       `json:"lapiMode,omitempty"`
	LapiEnabled                                bool                         `json:"lapiEnabled,omitempty"`
	LapiInstanceName                           string                       `json:"lapiInstanceName,omitempty"`
	LapiStreamScopes                           []string                     `json:"lapiStreamScopes,omitempty"`
	AppsecEnabled                              bool                         `json:"appsecEnabled,omitempty"`
	AppsecInstanceName                         string                       `json:"appsecInstanceName,omitempty"`
	AppsecScheme                               string                       `json:"appsecScheme,omitempty"`
	AppsecHost                                 string                       `json:"appsecHost,omitempty"`
	AppsecPath                                 string                       `json:"appsecPath,omitempty"`
	AppsecKey                                  string                       `json:"appsecKey,omitempty"`
	AppsecKeyFile                              string                       `json:"appsecKeyFile,omitempty"`
	AppsecTLSInsecureVerify                    bool                         `json:"appsecTlsInsecureVerify,omitempty"`
	AppsecTLSCertificateAuthority              string                       `json:"appsecTlsCertificateAuthority,omitempty"`
	AppsecTLSCertificateAuthorityFile          string                       `json:"appsecTlsCertificateAuthorityFile,omitempty"`
	AppsecTLSClientCertificate                 string                       `json:"appsecTlsClientCertificate,omitempty"`
	AppsecTLSClientCertificateFile             string                       `json:"appsecTlsClientCertificateFile,omitempty"`
	AppsecTLSClientKey                         string                       `json:"appsecTlsClientKey,omitempty"`
	AppsecTLSClientKeyFile                     string                       `json:"appsecTlsClientKeyFile,omitempty"`
	AppsecBodyLimit                            int64                        `json:"appsecBodyLimit,omitempty"`
	BouncerAppsecFailureAction                 string                       `json:"bouncerAppsecFailureAction,omitempty"`
	LapiScheme                                 string                       `json:"lapiScheme,omitempty"`
	LapiHost                                   string                       `json:"lapiHost,omitempty"`
	LapiPath                                   string                       `json:"lapiPath,omitempty"`
	LapiKey                                    string                       `json:"lapiKey,omitempty"`
	LapiKeyFile                                string                       `json:"lapiKeyFile,omitempty"`
	LapiTLSInsecureVerify                      bool                         `json:"lapiTlsInsecureVerify,omitempty"`
	LapiTLSCertificateAuthority                string                       `json:"lapiTlsCertificateAuthority,omitempty"`
	LapiTLSCertificateAuthorityFile            string                       `json:"lapiTlsCertificateAuthorityFile,omitempty"`
	LapiTLSClientCertificate                   string                       `json:"lapiTlsClientCertificate,omitempty"`
	LapiTLSClientCertificateFile               string                       `json:"lapiTlsClientCertificateFile,omitempty"`
	LapiTLSClientKey                           string                       `json:"lapiTlsClientKey,omitempty"`
	LapiTLSClientKeyFile                       string                       `json:"lapiTlsClientKeyFile,omitempty"`
	LapiCapiMachineID                          string                       `json:"lapiCapiMachineId,omitempty"`
	LapiCapiMachineIDFile                      string                       `json:"lapiCapiMachineIdFile,omitempty"`
	LapiCapiPassword                           string                       `json:"lapiCapiPassword,omitempty"`
	LapiCapiPasswordFile                       string                       `json:"lapiCapiPasswordFile,omitempty"`
	LapiCapiScenarios                          []string                     `json:"lapiCapiScenarios,omitempty"`
	BouncerDecisionHeader                      string                       `json:"bouncerDecisionHeader,omitempty"` // incoming header name; empty = off; values b|c
	LapiUpdateIntervalSeconds                  int64                        `json:"lapiUpdateIntervalSeconds,omitempty"`
	LapiMetricsUpdateIntervalSeconds           int64                        `json:"lapiMetricsUpdateIntervalSeconds,omitempty"`
	LapiUpdateMaxFailure                       int64                        `json:"lapiUpdateMaxFailure,omitempty"`
	BouncerLapiFailureAction                   string                       `json:"bouncerLapiFailureAction,omitempty"`
	BouncerStartupBlock                        bool                         `json:"bouncerStartupBlock,omitempty"`
	LapiDefaultDecisionSeconds                 int64                        `json:"lapiDefaultDecisionSeconds,omitempty"`
	BouncerRemediationStatusCode               int                          `json:"bouncerRemediationStatusCode,omitempty"`
	LapiHTTPTimeoutSeconds                     int64                        `json:"lapiHttpTimeoutSeconds,omitempty"`
	AppsecHTTPTimeoutSeconds                   int64                        `json:"appsecHttpTimeoutSeconds,omitempty"`
	BouncerCaptchaSiteverifyHTTPTimeoutSeconds int64                        `json:"bouncerCaptchaSiteverifyHttpTimeoutSeconds,omitempty"`
	BouncerTraceHeadersCustomName              string                       `json:"bouncerTraceHeadersCustomName,omitempty"`
	BouncerRemediationHeadersCustomName        string                       `json:"bouncerRemediationHeadersCustomName,omitempty"`
	BouncerForwardedHeadersCustomName          string                       `json:"bouncerForwardedHeadersCustomName,omitempty"`
	BouncerForwardedHeadersInsecure            bool                         `json:"bouncerForwardedHeadersInsecure,omitempty"`
	BouncerDecisionScopeHeaders                map[string]string            `json:"bouncerDecisionScopeHeaders,omitempty"`
	BouncerForwardedHeadersTrustedIPs          []string                     `json:"bouncerForwardedHeadersTrustedIps,omitempty"`
	BouncerClientTrustedIPs                    []string                     `json:"bouncerClientTrustedIps,omitempty"`
	LapiRedisEnabled                           bool                         `json:"lapiRedisEnabled,omitempty"`
	LapiRedisHost                              string                       `json:"lapiRedisHost,omitempty"`
	LapiRedisReadHosts                         []string                     `json:"lapiRedisReadHosts,omitempty"`
	LapiRedisPassword                          string                       `json:"lapiRedisPassword,omitempty"`
	LapiRedisPasswordFile                      string                       `json:"lapiRedisPasswordFile,omitempty"`
	LapiRedisDatabase                          string                       `json:"lapiRedisDatabase,omitempty"`
	BouncerRedisUnreachableBlock               bool                         `json:"bouncerRedisUnreachableBlock,omitempty"`
	BouncerBanFilePath                         string                       `json:"bouncerBanFilePath,omitempty"`
	BouncerCaptchaFilePath                     string                       `json:"bouncerCaptchaFilePath,omitempty"`
	BouncerCaptchaProvider                     string                       `json:"bouncerCaptchaProvider,omitempty"`
	BouncerCaptchaCustomJsURL                  string                       `json:"bouncerCaptchaCustomJsUrl,omitempty"`
	BouncerCaptchaCustomValidateURL            string                       `json:"bouncerCaptchaCustomValidateUrl,omitempty"`
	BouncerCaptchaCustomKey                    string                       `json:"bouncerCaptchaCustomKey,omitempty"`
	BouncerCaptchaCustomResponse               string                       `json:"bouncerCaptchaCustomResponse,omitempty"`
	BouncerCaptchaCustomChallengeURL           string                       `json:"bouncerCaptchaCustomChallengeUrl,omitempty"`
	BouncerCaptchaCustomValidateBody           string                       `json:"bouncerCaptchaCustomValidateBody,omitempty"`
	BouncerCaptchaSiteKey                      string                       `json:"bouncerCaptchaSiteKey,omitempty"`
	BouncerCaptchaSiteKeyFile                  string                       `json:"bouncerCaptchaSiteKeyFile,omitempty"`
	BouncerCaptchaSecretKey                    string                       `json:"bouncerCaptchaSecretKey,omitempty"`
	BouncerCaptchaSecretKeyFile                string                       `json:"bouncerCaptchaSecretKeyFile,omitempty"`
	BouncerCaptchaGateSecret                   string                       `json:"bouncerCaptchaGateSecret,omitempty"`
	BouncerCaptchaGateSecretFile               string                       `json:"bouncerCaptchaGateSecretFile,omitempty"`
	BouncerCaptchaGateBindIP                   bool                         `json:"bouncerCaptchaGateBindIp,omitempty"`
	BouncerCaptchaGracePeriodSeconds           int64                        `json:"bouncerCaptchaGracePeriodSeconds,omitempty"`
	ReclaimGraceSeconds                        int64                        `json:"reclaimGraceSeconds,omitempty"`
	BouncerOriginBasedDecisionRemap            map[string]map[string]string `json:"bouncerOriginBasedDecisionRemap,omitempty"`
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
		return errors.New(name + ": captcha requires BouncerCaptchaProvider")
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
		BouncerEnabled:                   false,
		LogLevel:                         LogINFO,
		LogFormat:                        "common",
		LogFilePath:                      "",
		LapiMode:                         LiveMode,
		AppsecEnabled:                    false,
		AppsecBodyLimit:                  10485760,
		BouncerAppsecFailureAction:       FailureActionBan,
		AppsecScheme:                     "",
		AppsecHost:                       "crowdsec:7422",
		AppsecPath:                       "/",
		AppsecKey:                        "",
		AppsecTLSInsecureVerify:          false,
		LapiScheme:                       HTTP,
		LapiHost:                         "crowdsec:8080",
		LapiPath:                         "/",
		LapiKey:                          "",
		LapiTLSInsecureVerify:            false,
		LapiUpdateIntervalSeconds:        60,
		LapiMetricsUpdateIntervalSeconds: 600,
		LapiUpdateMaxFailure:             0,
		BouncerLapiFailureAction:         FailureActionBan,
		BouncerStartupBlock:              true,
		LapiDefaultDecisionSeconds:       60,
		BouncerRemediationStatusCode:     http.StatusForbidden,
		LapiHTTPTimeoutSeconds:           10,
		AppsecHTTPTimeoutSeconds:         10,
		BouncerCaptchaSiteverifyHTTPTimeoutSeconds: 10,
		BouncerCaptchaProvider:                     "",
		BouncerCaptchaCustomJsURL:                  "",
		BouncerCaptchaCustomValidateURL:            "",
		BouncerCaptchaCustomKey:                    "",
		BouncerCaptchaCustomResponse:               "",
		BouncerCaptchaCustomChallengeURL:           "",
		BouncerCaptchaCustomValidateBody:           "",
		BouncerCaptchaSiteKey:                      "",
		BouncerCaptchaSecretKey:                    "",
		BouncerCaptchaGateBindIP:                   true,
		BouncerCaptchaGracePeriodSeconds:           1800,
		ReclaimGraceSeconds:                        30,
		BouncerOriginBasedDecisionRemap:            map[string]map[string]string{},
		LapiStreamScopes:                           []string{},
		BouncerCaptchaFilePath:                     "/captcha.html",
		BouncerBanFilePath:                         "",
		BouncerDecisionHeader:                      "",
		BouncerTraceHeadersCustomName:              "",
		BouncerRemediationHeadersCustomName:        "",
		BouncerForwardedHeadersCustomName:          "X-Forwarded-For",
		BouncerForwardedHeadersInsecure:            false,
		BouncerDecisionScopeHeaders:                map[string]string{},
		BouncerForwardedHeadersTrustedIPs:          []string{},
		BouncerClientTrustedIPs:                    []string{},
		LapiRedisEnabled:                           false,
		LapiRedisHost:                              "redis:6379",
		LapiRedisReadHosts:                         []string{},
		LapiRedisPassword:                          "",
		LapiRedisDatabase:                          "",
		BouncerRedisUnreachableBlock:               true,
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

	if err := validateOriginBasedDecisionRemap(config); err != nil {
		return err
	}

	if err := validateCaptcha(config); err != nil {
		return err
	}

	if err := validateParamsIPs(log, config.BouncerForwardedHeadersTrustedIPs, "BouncerForwardedHeadersTrustedIPs"); err != nil {
		return err
	}
	if err := validateParamsIPs(log, config.BouncerClientTrustedIPs, "BouncerClientTrustedIPs"); err != nil {
		return err
	}

	// Redis password file is unused when Redis is off; skip Stat/read so leftovers do not fail startup.
	if config.LapiRedisEnabled {
		if _, err := GetVariable(config, "LapiRedisPassword"); err != nil {
			return err
		}
	}

	if err := validateCaptchaCredentialsAndTemplates(config); err != nil {
		return err
	}

	if err := validateLapiWhenEnabled(config); err != nil {
		return err
	}

	// AppSec URL, key file, and HTTPS CA only when this router will open AppSec.
	if config.AppsecEnabled {
		if err := validateAppsecURLKeyAndTLS(config); err != nil {
			return err
		}
	}

	if err := validateOpenVsSubscribe(config); err != nil {
		return err
	}

	return validateLogging(config)
}

// validateOpenVsSubscribe rejects leftover secrets or names when nothing owns or subscribes (E2).
func validateOpenVsSubscribe(config *Config) error {
	if err := validateLegOpenVsSubscribe("LAPI", config.BouncerEnabled, config.LapiEnabled, config.LapiInstanceName, lapiSecretPresent(config)); err != nil {
		return err
	}
	return validateLegOpenVsSubscribe("AppSec", config.BouncerEnabled, config.AppsecEnabled, config.AppsecInstanceName, appsecSecretPresent(config))
}

func validateLegOpenVsSubscribe(leg string, bounceEnabled, owned bool, instanceName string, secretPresent bool) error {
	if bounceEnabled || owned {
		return nil
	}
	if strings.TrimSpace(instanceName) == "" && !secretPresent {
		return nil
	}
	return fmt.Errorf("%s: leftover instance name, API key, or client certificate while BouncerEnabled is false and the leg is not owned", leg)
}

func lapiSecretPresent(config *Config) bool {
	key, err := GetVariable(config, "LapiKey")
	if err == nil && strings.TrimSpace(key) != "" {
		return true
	}
	cert, _ := GetVariable(config, "LapiTLSClientCertificate")
	certKey, _ := GetVariable(config, "LapiTLSClientKey")
	return strings.TrimSpace(cert) != "" && strings.TrimSpace(certKey) != ""
}

func appsecSecretPresent(config *Config) bool {
	key, err := GetVariable(config, "AppsecKey")
	if err == nil && strings.TrimSpace(key) != "" {
		return true
	}
	cert, _ := GetVariable(config, "AppsecTLSClientCertificate")
	certKey, _ := GetVariable(config, "AppsecTLSClientKey")
	return strings.TrimSpace(cert) != "" && strings.TrimSpace(certKey) != ""
}

func effectiveAppsecScheme(config *Config) string {
	if config.AppsecScheme != "" {
		return config.AppsecScheme
	}
	return config.LapiScheme
}

// validateCaptchaCredentialsAndTemplates checks captcha credentials and optional HTML templates.
func validateCaptchaCredentialsAndTemplates(config *Config) error {
	if err := validateEnabledCaptchaSettings(config); err != nil {
		return err
	}
	if config.BouncerBanFilePath != "" {
		if _, _, err := GetTemplate(config.BouncerBanFilePath); err != nil {
			return err
		}
	}
	return nil
}

// validateEnabledCaptchaSettings checks provider credentials, the optional custom
// challenge URL, and a loadable captcha template when a provider is set.
func validateEnabledCaptchaSettings(config *Config) error {
	if config.BouncerCaptchaProvider == "" {
		return nil
	}
	if err := validateCaptchaCredentials(config); err != nil {
		return err
	}
	// Empty is valid; it only leaves the challenge path out of the passthrough match set.
	// A value that names no path would silently never match, so reject it instead.
	if config.BouncerCaptchaProvider == CustomProvider && config.BouncerCaptchaCustomChallengeURL != "" &&
		CustomCaptchaResourcePath(config.BouncerCaptchaCustomChallengeURL) == "" {
		return errors.New("BouncerCaptchaCustomChallengeURL: " + config.BouncerCaptchaCustomChallengeURL +
			" has no absolute path, so no browser request could ever match it")
	}
	gateSecret, err := GetVariable(config, "BouncerCaptchaGateSecret")
	if err != nil {
		return err
	}
	if gateSecret == "" {
		return errors.New("BouncerCaptchaGateSecret: cannot be empty when BouncerCaptchaProvider is set")
	}
	if config.BouncerCaptchaFilePath == "" {
		return errors.New("BouncerCaptchaFilePath: cannot be empty when BouncerCaptchaProvider is set")
	}
	if _, _, err := GetTemplate(config.BouncerCaptchaFilePath); err != nil {
		return err
	}
	return nil
}

// validateCaptchaCredentials resolves site and secret keys and rejects an empty
// trimmed value for each field independently, site first. Lookup errors stay.
func validateCaptchaCredentials(config *Config) error {
	siteKey, err := GetVariable(config, "BouncerCaptchaSiteKey")
	if err != nil {
		return err
	}
	if siteKey == "" {
		return errors.New("BouncerCaptchaSiteKey: cannot be empty when BouncerCaptchaProvider is set")
	}
	secretKey, err := GetVariable(config, "BouncerCaptchaSecretKey")
	if err != nil {
		return err
	}
	if secretKey == "" {
		return errors.New("BouncerCaptchaSecretKey: cannot be empty when BouncerCaptchaProvider is set")
	}
	return nil
}

func validateLapiWhenEnabled(config *Config) error {
	if !config.LapiEnabled {
		return nil
	}
	if config.LapiMode == AloneMode {
		if _, err := GetVariable(config, "LapiCapiMachineID"); err != nil {
			return err
		}
		if _, err := GetVariable(config, "LapiCapiPassword"); err != nil {
			return err
		}
		return nil
	}
	return validateLapiURLAndKeys(config)
}

func validateLapiURLAndKeys(config *Config) error {
	if err := validateURL("Lapi", config.LapiScheme, config.LapiHost, config.LapiPath); err != nil {
		return err
	}

	lapiKey, err := GetVariable(config, "LapiKey")
	if err != nil {
		return err
	}
	clientCertificate, err := GetVariable(config, "LapiTLSClientCertificate")
	if err != nil {
		return err
	}
	clientKey, err := GetVariable(config, "LapiTLSClientKey")
	if err != nil {
		return err
	}

	if lapiKey == "" && (clientCertificate == "" || clientKey == "") {
		return errors.New("LapiKey || (LapiTLSClientCertificate && LapiTLSClientKey): cannot be all empty")
	}
	if lapiKey != "" && (clientCertificate == "" || clientKey == "") {
		lapiKey = strings.TrimSpace(lapiKey)
		if err = validateParamsAPIKey(lapiKey, "LapiKey"); err != nil {
			return err
		}
	}

	if config.LapiScheme == HTTPS && !config.LapiTLSInsecureVerify {
		if err = validateParamsTLS(config, "Lapi"); err != nil {
			return err
		}
	}
	return nil
}

// validateAppsecURLKeyAndTLS checks the AppSec listener URL, optional key, and HTTPS CA.
func validateAppsecURLKeyAndTLS(config *Config) error {
	appsecScheme := effectiveAppsecScheme(config)
	if err := validateURL("Appsec", appsecScheme, config.AppsecHost, config.AppsecPath); err != nil {
		return err
	}

	// AppsecEnabled AppSec needs a listener host. validateURL only asks NewRequest to
	// accept scheme://host/path, so an empty host (http:///) still returns nil.
	if err := rejectMissingEnabledAppsecHost(config, appsecScheme); err != nil {
		return err
	}

	appsecKey, err := GetVariable(config, "AppsecKey")
	if err != nil {
		return err
	}
	if appsecKey != "" {
		appsecKey = strings.TrimSpace(appsecKey)
		if err = validateParamsAPIKey(appsecKey, "AppsecKey"); err != nil {
			return err
		}
	}

	if config.AppsecScheme == HTTPS && !config.AppsecTLSInsecureVerify {
		if err = validateParamsTLS(config, "Appsec"); err != nil {
			return err
		}
	}
	return nil
}

// rejectMissingEnabledAppsecHost fails when AppSec is on and the listener host is missing.
func rejectMissingEnabledAppsecHost(config *Config, appsecScheme string) error {
	if !config.AppsecEnabled {
		return nil
	}
	appsecURL := url.URL{Scheme: appsecScheme, Host: config.AppsecHost, Path: config.AppsecPath}
	appsecReq, err := http.NewRequest(http.MethodGet, appsecURL.String(), nil)
	if err != nil {
		return fmt.Errorf("LapiScheme://AppsecHost: '%v://%v%v' must be a valid URL", appsecScheme, config.AppsecHost, config.AppsecPath)
	}
	if config.AppsecHost == "" || appsecReq.URL.Host == "" {
		return errors.New("AppsecHost: cannot be empty when AppsecEnabled is true")
	}
	return nil
}

// validateLogging rejects an unknown log level and an unwritable LogFilePath.
func validateLogging(config *Config) error {
	if !contains([]string{LogTRACE, LogDEBUG, LogINFO, LogWARN, LogERROR}, strings.ToUpper(config.LogLevel)) {
		return fmt.Errorf("LogLevel should be one of (%s,%s,%s,%s,%s)", LogTRACE, LogDEBUG, LogINFO, LogWARN, LogERROR)
	}
	if config.LogFilePath != "" {
		// Prove the path is writable, then close so ValidateParams does not keep the check descriptor.
		checkFile, err := os.OpenFile(filepath.Clean(config.LogFilePath), os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0600)
		if err != nil {
			return fmt.Errorf("LogFilePath is not writable %w", err)
		}
		_ = checkFile.Close()
	}
	return nil
}

// validateDecisionScopeHeaders rejects empty names and Ip/Range keys.
func validateDecisionScopeHeaders(config *Config) error {
	for rawScope, rawHeader := range config.BouncerDecisionScopeHeaders {
		scope := strings.TrimSpace(rawScope)
		if scope == "" {
			return errors.New("BouncerDecisionScopeHeaders: scope name cannot be empty")
		}
		switch strings.ToLower(scope) {
		case "ip", "range":
			return fmt.Errorf("BouncerDecisionScopeHeaders: %q cannot be mapped to a header", scope)
		}
		if strings.TrimSpace(rawHeader) == "" {
			return fmt.Errorf("BouncerDecisionScopeHeaders: header for %q cannot be empty", scope)
		}
	}
	return nil
}

func validateURL(variable, scheme, host, path string) error {
	// This only check that the format of the URL scheme://host/path is correct and do not make requests
	testURL := url.URL{Scheme: scheme, Host: host, Path: path}
	if _, err := http.NewRequest(http.MethodGet, testURL.String(), nil); err != nil {
		return fmt.Errorf("LapiScheme://%sHost: '%v://%v%v' must be a valid URL", variable, scheme, host, path)
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
	if !contains([]string{"", HcaptchaProvider, RecaptchaProvider, TurnstileProvider, CustomProvider}, config.BouncerCaptchaProvider) {
		return fmt.Errorf("BouncerCaptchaProvider: must be one of '%s', '%s', '%s' or '%s'", HcaptchaProvider, RecaptchaProvider, TurnstileProvider, CustomProvider)
	}
	// Accept only empty, form, or json after trim; json is custom-only.
	validateBody := strings.TrimSpace(config.BouncerCaptchaCustomValidateBody)
	if validateBody != "" && validateBody != CaptchaCustomValidateBodyForm && validateBody != CaptchaCustomValidateBodyJSON {
		return errors.New("BouncerCaptchaCustomValidateBody: must be empty, form, or json")
	}
	if validateBody == CaptchaCustomValidateBodyJSON && config.BouncerCaptchaProvider != CustomProvider {
		return errors.New("BouncerCaptchaCustomValidateBody: json is only valid when BouncerCaptchaProvider is custom")
	}
	if config.BouncerCaptchaProvider == CustomProvider {
		if config.BouncerCaptchaCustomKey == "" || config.BouncerCaptchaCustomResponse == "" || config.BouncerCaptchaCustomValidateURL == "" || config.BouncerCaptchaCustomJsURL == "" {
			return fmt.Errorf(
				"BouncerCaptchaProvider: provider is custom, captchaCustom variables must be filled: BouncerCaptchaCustomKey:%s, BouncerCaptchaCustomResponse:%s, BouncerCaptchaCustomValidateURL:%s, BouncerCaptchaCustomJsURL:%s",
				config.BouncerCaptchaCustomKey,
				config.BouncerCaptchaCustomResponse,
				config.BouncerCaptchaCustomValidateURL,
				config.BouncerCaptchaCustomJsURL,
			)
		}
	}
	return nil
}

func validateParamsRequired(config *Config) error {
	requiredStrings := map[string]string{
		"LapiScheme": config.LapiScheme,
		"LapiHost":   config.LapiHost,
		"LapiMode":   config.LapiMode,
	}
	for key, val := range requiredStrings {
		if len(val) == 0 {
			return errors.New(key + ": cannot be empty")
		}
	}
	requiredInt0 := map[string]int64{
		"AppsecBodyLimit":                  config.AppsecBodyLimit,
		"LapiMetricsUpdateIntervalSeconds": config.LapiMetricsUpdateIntervalSeconds,
		"ReclaimGraceSeconds":              config.ReclaimGraceSeconds,
	}
	for key, val := range requiredInt0 {
		if val < 0 {
			return errors.New(key + ": cannot be less than 0")
		}
	}
	requiredInt1 := map[string]int64{
		"LapiUpdateIntervalSeconds":                  config.LapiUpdateIntervalSeconds,
		"LapiDefaultDecisionSeconds":                 config.LapiDefaultDecisionSeconds,
		"LapiHTTPTimeoutSeconds":                     config.LapiHTTPTimeoutSeconds,
		"AppsecHTTPTimeoutSeconds":                   config.AppsecHTTPTimeoutSeconds,
		"BouncerCaptchaSiteverifyHTTPTimeoutSeconds": config.BouncerCaptchaSiteverifyHTTPTimeoutSeconds,
		"BouncerCaptchaGracePeriodSeconds":           config.BouncerCaptchaGracePeriodSeconds,
	}
	for key, val := range requiredInt1 {
		if val < 1 {
			return errors.New(key + ": cannot be less than 1")
		}
	}
	if config.LapiUpdateMaxFailure < -1 {
		return errors.New("LapiUpdateMaxFailure: cannot be less than -1")
	}
	if err := validateFailureAction("BouncerLapiFailureAction", config.BouncerLapiFailureAction, config.BouncerCaptchaProvider); err != nil {
		return err
	}
	if err := validateFailureAction("BouncerAppsecFailureAction", config.BouncerAppsecFailureAction, config.BouncerCaptchaProvider); err != nil {
		return err
	}
	if config.AppsecBodyLimit < 0 {
		return errors.New("AppsecBodyLimit: cannot be less than 0")
	}
	if config.BouncerRemediationStatusCode < 100 || config.BouncerRemediationStatusCode >= 600 {
		return errors.New("BouncerRemediationStatusCode: cannot be less than 100 and more than 600")
	}

	if !contains([]string{NoneMode, LiveMode, StreamMode, AloneMode}, config.LapiMode) {
		return errors.New("LapiMode: must be one of 'none', 'live', 'stream' or 'alone'")
	}
	if !contains([]string{HTTP, HTTPS}, config.LapiScheme) {
		return errors.New("LapiScheme: must be one of 'http' or 'https'")
	}
	if !contains([]string{HTTP, HTTPS, ""}, config.AppsecScheme) {
		return errors.New("AppsecScheme: must be one of 'http' or 'https'")
	}
	return nil
}

func getTLSConfig(config *Config, log *slog.Logger, prefix, scheme string, insecureVerify bool) (*tls.Config, error) {
	tlsConfig := new(tls.Config)
	if scheme != HTTPS {
		log.Debug("getTLSConfig:Scheme https:no", "prefix", prefix)
		return tlsConfig, nil
	}
	// RootCAs is intentionally left nil unless a custom CA is provided:
	// crypto/tls then falls back to x509.SystemCertPool(), which is what we
	// want when the LAPI is exposed behind a reverse proxy with a publicly
	// trusted certificate (e.g. Let's Encrypt).
	//nolint:nestif
	if insecureVerify {
		tlsConfig.InsecureSkipVerify = true
		log.Debug("getTLSConfig:TLSInsecureVerify", "prefix", prefix, "tlsInsecure", true)
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
			log.Debug("getTLSConfig:TLSCertificateAuthority CA added successfully", "prefix", prefix)
		} else {
			log.Debug("getTLSConfig: no CA provided, using system trust store", "prefix", prefix)
		}
	}
	clientCertificate, err := GetVariable(config, prefix+"TLSClientCertificate")
	if err != nil {
		return nil, err
	}
	clientKey, err := GetVariable(config, prefix+"TLSClientKey")
	if err != nil {
		return nil, err
	}
	if clientCertificate == "" || clientKey == "" {
		return tlsConfig, nil
	}
	clientCertificatePair, err := tls.X509KeyPair([]byte(clientCertificate), []byte(clientKey))
	if err != nil {
		return nil, fmt.Errorf("getTLSClientConfigCrowdsec impossible to generate ClientCert %w", err)
	}
	tlsConfig.Certificates = append(tlsConfig.Certificates, clientCertificatePair)

	return tlsConfig, nil
}

// GetTLSConfigCrowdsec get TLS config from Config.
func GetTLSConfigCrowdsec(config *Config, log *slog.Logger, isAppsec bool) (*tls.Config, error) {
	var prefix string
	if isAppsec && config.AppsecScheme != "" {
		prefix = "Appsec"
		return getTLSConfig(config, log, prefix, config.AppsecScheme, config.AppsecTLSInsecureVerify)
	}
	prefix = "Lapi"
	return getTLSConfig(config, log, prefix, config.LapiScheme, config.LapiTLSInsecureVerify)
}
