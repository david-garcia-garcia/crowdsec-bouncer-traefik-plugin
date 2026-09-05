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
	"regexp"
	"strings"

	ip "github.com/maxlerebourg/crowdsec-bouncer-traefik-plugin/pkg/ip"
)

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

// ValidateParams validate all the param gave by user.
//
//nolint:gocyclo,gocognit,nestif,funlen
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

	if _, err := GetVariable(config, "RedisCachePassword"); err != nil {
		return err
	}

	if config.CrowdsecMode == AloneMode {
		if _, err := GetVariable(config, "CrowdsecCapiMachineID"); err != nil {
			return err
		}
		if _, err := GetVariable(config, "CrowdsecCapiPassword"); err != nil {
			return err
		}
		return nil
	}

	if config.CaptchaProvider != "" {
		if _, err := GetVariable(config, "CaptchaSiteKey"); err != nil {
			return err
		}
		if _, err := GetVariable(config, "CaptchaSecretKey"); err != nil {
			return err
		}
		if config.CaptchaFilePath != "" {
			if _, _, err := GetTemplate(config.CaptchaFilePath); err != nil {
				return err
			}
		}
	}
	if config.BanFilePath != "" {
		if _, _, err := GetTemplate(config.BanFilePath); err != nil {
			return err
		}
	}

	if err := validateURL("CrowdsecLapi", config.CrowdsecLapiScheme, config.CrowdsecLapiHost, config.CrowdsecLapiPath); err != nil {
		return err
	}

	if err := validateURL("CrowdsecAppsec", config.CrowdsecLapiScheme, config.CrowdsecAppsecHost, config.CrowdsecAppsecPath); err != nil {
		return err
	}

	lapiKey, err := GetVariable(config, "CrowdsecLapiKey")
	if err != nil {
		return err
	}
	appsecKey, err := GetVariable(config, "CrowdsecAppsecKey")
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

	// We need to either have crowdsecLapiKey defined or the BouncerCert and Bouncerkey
	if lapiKey == "" && (certBouncer == "" || certBouncerKey == "") && config.CrowdsecMode != AppsecMode {
		return errors.New("CrowdsecLapiKey || (CrowdsecLapiTLSCertificateBouncer && CrowdsecLapiTLSCertificateBouncerKey): cannot be all empty")
	} else if lapiKey != "" && (certBouncer == "" || certBouncerKey == "") {
		lapiKey = strings.TrimSpace(lapiKey)
		if err = validateParamsAPIKey(lapiKey, "CrowdsecLapiKey"); err != nil {
			return err
		}
	}

	// Validate CrowdsecAppsecKey if provided
	if appsecKey != "" {
		appsecKey = strings.TrimSpace(appsecKey)
		if err = validateParamsAPIKey(appsecKey, "CrowdsecAppsecKey"); err != nil {
			return err
		}
	}

	// Case https to contact Crowdsec LAPI and certificate must be provided
	if config.CrowdsecLapiScheme == HTTPS && !config.CrowdsecLapiTLSInsecureVerify {
		if err = validateParamsTLS(config); err != nil {
			return err
		}
	}

	// Check logging configuration
	// to upper allow of anycase of log level
	if !contains([]string{LogDEBUG, LogINFO, LogWARN, LogERROR}, strings.ToUpper(config.LogLevel)) {
		return fmt.Errorf("LogLevel should be one of (%s,%s,%s,%s)", LogDEBUG, LogINFO, LogWARN, LogERROR)
	}
	if config.LogFilePath != "" {
		_, err = os.OpenFile(filepath.Clean(config.LogFilePath), os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0600)
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

func validateParamsTLS(config *Config) error {
	certAuth, err := GetVariable(config, "CrowdsecLapiTLSCertificateAuthority")
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
