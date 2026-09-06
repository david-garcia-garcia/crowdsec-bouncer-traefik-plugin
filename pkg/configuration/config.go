// Package configuration implements plugin Config, default Config values and validation param functions.
package configuration

import (
	"net/http"
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
	TraceHeadersCustomName                     string            `json:"traceHeadersCustomName,omitempty"`
	RemediationHeadersCustomName               string            `json:"remediationHeadersCustomName,omitempty"`
	ForwardedHeadersCustomName                 string            `json:"forwardedHeadersCustomName,omitempty"`
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
	BanHTMLFilePath                            string            `json:"banHtmlFilePath,omitempty"` // Deprecated: Keep it for historical compatibility
	BanFilePath                                string            `json:"banFilePath,omitempty"`
	CaptchaHTMLFilePath                        string            `json:"captchaHtmlFilePath,omitempty"` // Deprecated: Keep it for historical compatibility
	CaptchaFilePath                            string            `json:"captchaFilePath,omitempty"`
	CaptchaProvider                            string            `json:"captchaProvider,omitempty"`
	CaptchaCustomJsURL                         string            `json:"captchaCustomJsUrl,omitempty"`
	CaptchaCustomValidateURL                   string            `json:"captchaCustomValidateUrl,omitempty"`
	CaptchaCustomKey                           string            `json:"captchaCustomKey,omitempty"`
	CaptchaCustomResponse                      string            `json:"captchaCustomResponse,omitempty"`
	CaptchaSiteKey                             string            `json:"captchaSiteKey,omitempty"`
	CaptchaSiteKeyFile                         string            `json:"captchaSiteKeyFile,omitempty"`
	CaptchaSecretKey                           string            `json:"captchaSecretKey,omitempty"`
	CaptchaSecretKeyFile                       string            `json:"captchaSecretKeyFile,omitempty"`
	CaptchaGracePeriodSeconds                  int64             `json:"captchaGracePeriodSeconds,omitempty"`
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
		Enabled:                         false,
		LogLevel:                        LogINFO,
		LogFormat:                       "common",
		LogFilePath:                     "",
		CrowdsecMode:                    LiveMode,
		CrowdsecAppsecEnabled:           false,
		CrowdsecAppsecBodyLimit:         10485760,
		CrowdsecAppsecFailureAction:     FailureActionBan,
		CrowdsecAppsecScheme:            "",
		CrowdsecAppsecHost:              "crowdsec:7422",
		CrowdsecAppsecPath:              "/",
		CrowdsecAppsecKey:               "",
		CrowdsecAppsecTLSInsecureVerify: false,
		CrowdsecLapiScheme:              HTTP,
		CrowdsecLapiHost:                "crowdsec:8080",
		CrowdsecLapiPath:                "/",
		CrowdsecLapiKey:                 "",
		CrowdsecLapiTLSInsecureVerify:   false,
		UpdateIntervalSeconds:           60,
		MetricsUpdateIntervalSeconds:    600,
		UpdateMaxFailure:                0,
		CrowdsecLapiFailureAction:       FailureActionBan,
		StreamStartupBlock:              true,
		DefaultDecisionSeconds:          60,
		RemediationStatusCode:           http.StatusForbidden,
		HTTPTimeoutSeconds:              10,
		CaptchaProvider:                 "",
		CaptchaCustomJsURL:              "",
		CaptchaCustomValidateURL:        "",
		CaptchaCustomKey:                "",
		CaptchaCustomResponse:           "",
		CaptchaSiteKey:                  "",
		CaptchaSecretKey:                "",
		CaptchaGracePeriodSeconds:       1800,
		CaptchaFilePath:                 "/captcha.html",
		BanFilePath:                     "",
		TraceHeadersCustomName:          "",
		RemediationHeadersCustomName:    "",
		ForwardedHeadersCustomName:      "X-Forwarded-For",
		DecisionScopeHeaders:            map[string]string{},
		ForwardedHeadersTrustedIPs:      []string{},
		ClientTrustedIPs:                []string{},
		RedisCacheEnabled:               false,
		RedisCacheHost:                  "redis:6379",
		RedisCacheReadHosts:             []string{},
		RedisCachePassword:              "",
		RedisCacheDatabase:              "",
		RedisCacheUnreachableBlock:      true,
	}
}
