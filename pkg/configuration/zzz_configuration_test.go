package configuration

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	logger "github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pkg/logger"
)

// validPEM is a minimal self-signed certificate accepted by AppendCertsFromPEM,
// shared by the TLS tests below.
const validPEM = `-----BEGIN CERTIFICATE-----
MIIBhTCCASugAwIBAgIQIRi6zePL6mKjOipn+dNuaTAKBggqhkjOPQQDAjASMRAw
DgYDVQQKEwdBY21lIENvMB4XDTE3MTAyMDE5NDMwNloXDTE4MTAyMDE5NDMwNlow
EjEQMA4GA1UEChMHQWNtZSBDbzBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABD0d
7VNhbWvZLWPuj/RtHFjvtJBEwOkhbN/BnnE8rnZR8+sbwnc/KhCk3FhnpHZnQz7B
5aETbbIgmuvewdjvSBSjYzBhMA4GA1UdDwEB/wQEAwICpDATBgNVHSUEDDAKBggr
BgEFBQcDATAPBgNVHRMBAf8EBTADAQH/MCkGA1UdEQQiMCCCDmxvY2FsaG9zdDo1
NDUzgg4xMjcuMC4wLjE6NTQ1MzAKBggqhkjOPQQDAgNIADBFAiEA2zpJEPQyz6/l
Wf86aX6PepsntZv2GYlA5UpabfT2EZICICpJ5h/iI+i341gBmLiAFQOyTDT+/wQc
6MF9+Yw1Yy0t
-----END CERTIFICATE-----`

func getMinimalConfig() *Config {
	cfg := New()
	cfg.LapiKey = "test"
	return cfg
}

// writeCaptchaTemplateFixture writes a readable captcha.html so tests that used
// to blank BouncerCaptchaFile still skip only the key errors they assert.
func writeCaptchaTemplateFixture(t *testing.T) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "captcha.html")
	if err := os.WriteFile(path, []byte("CAPTCHA_FIXTURE"), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func Test_contains(t *testing.T) {
	type args struct {
		source []string
		target string
	}
	tests := []struct {
		name string
		args args
		want bool
	}{
		{name: "Contain in the list", args: args{source: []string{"a", "b"}, target: "a"}, want: true},
		{name: "Contain not in the list", args: args{source: []string{"a", "b"}, target: "c"}, want: false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := contains(tt.args.source, tt.args.target); got != tt.want {
				t.Errorf("contains() = %v, want %v", got, tt.want)
			}
		})
	}
}

func Test_GetVariable(t *testing.T) {
	cfg1 := New()
	cfg1.LapiKey = "test"
	cfg2 := New()
	cfg2.LapiKeyFile = "../../tests/.keytest"
	cfg3 := New()
	cfg3.LapiKeyFile = "../../tests/.bad"
	type args struct {
		config *Config
		key    string
	}
	tests := []struct {
		name    string
		args    args
		want    string
		wantErr bool
	}{
		{name: "Validate a key string", args: args{config: cfg1, key: "LapiKey"}, want: "test", wantErr: false},
		{name: "Validate a key file", args: args{config: cfg2, key: "LapiKey"}, want: "test", wantErr: false},
		{name: "Not validate an invalid file", args: args{config: cfg3, key: "LapiKey"}, want: "", wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := GetVariable(tt.args.config, tt.args.key)
			if (err != nil) != tt.wantErr {
				t.Errorf("getVariable() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if got != tt.want {
				t.Errorf("getVariable() = %v, want %v", got, tt.want)
			}
		})
	}
}

func Test_ValidateParams(t *testing.T) {
	log := logger.New("INFO", "")
	cfg1 := New()
	cfg1.LapiKey = "test\n\n"
	cfg2 := New()
	cfg2.LapiKey = "test@"
	cfg3 := getMinimalConfig()
	cfg3.LapiMode = "bad"
	cfg4 := getMinimalConfig()
	cfg4.LapiUpdateIntervalSeconds = 0
	cfg5 := getMinimalConfig()
	cfg5.BouncerClientTrustedIPs = []string{0: "bad"}
	cfg6 := getMinimalConfig()
	cfg6.LapiScheme = HTTPS
	cfg6.LapiTLSInsecureVerify = true
	cfg7 := getMinimalConfig()
	cfg7.LapiScheme = HTTPS
	cfg8 := getMinimalConfig()
	cfg8.LogLevel = LogINFO
	cfg9 := getMinimalConfig()
	cfg9.LogLevel = "info"
	cfgTrace := getMinimalConfig()
	cfgTrace.LogLevel = "trace"
	cfg10 := getMinimalConfig()
	cfg10.LogLevel = "Warning"
	captchaTemplate := writeCaptchaTemplateFixture(t)
	cfgCaptchaNoProvider := getMinimalConfig()
	cfgCaptchaNoProvider.BouncerLapiFailureAction = FailureActionCaptcha
	cfgCaptchaWithProvider := getMinimalConfig()
	cfgCaptchaWithProvider.BouncerLapiFailureAction = FailureActionCaptcha
	cfgCaptchaWithProvider.BouncerCaptchaProvider = HbouncerCaptchaProvider
	cfgCaptchaWithProvider.BouncerCaptchaSiteKey = "site"
	cfgCaptchaWithProvider.BouncerCaptchaSecretKey = "secret"
	cfgCaptchaWithProvider.BouncerCaptchaGateSecret = "gate-secret"
	cfgCaptchaWithProvider.BouncerCaptchaFile = captchaTemplate
	cfgEmptyKeysDefaultBan := getMinimalConfig()
	cfgEmptyKeysDefaultBan.BouncerCaptchaProvider = HbouncerCaptchaProvider
	cfgEmptyKeysDefaultBan.BouncerCaptchaGateSecret = "gate-secret"
	cfgEmptyKeysDefaultBan.BouncerCaptchaFile = captchaTemplate
	cfgOnlySiteEmpty := getMinimalConfig()
	cfgOnlySiteEmpty.BouncerCaptchaProvider = HbouncerCaptchaProvider
	cfgOnlySiteEmpty.BouncerCaptchaSecretKey = "secret"
	cfgOnlySiteEmpty.BouncerCaptchaGateSecret = "gate-secret"
	cfgOnlySiteEmpty.BouncerCaptchaFile = captchaTemplate
	cfgOnlySecretEmpty := getMinimalConfig()
	cfgOnlySecretEmpty.BouncerCaptchaProvider = HbouncerCaptchaProvider
	cfgOnlySecretEmpty.BouncerCaptchaSiteKey = "site"
	cfgOnlySecretEmpty.BouncerCaptchaGateSecret = "gate-secret"
	cfgOnlySecretEmpty.BouncerCaptchaFile = captchaTemplate
	cfgWhitespaceSite := getMinimalConfig()
	cfgWhitespaceSite.BouncerCaptchaProvider = HbouncerCaptchaProvider
	cfgWhitespaceSite.BouncerCaptchaSiteKey = "   "
	cfgWhitespaceSite.BouncerCaptchaSecretKey = "secret"
	cfgWhitespaceSite.BouncerCaptchaGateSecret = "gate-secret"
	cfgWhitespaceSite.BouncerCaptchaFile = captchaTemplate
	cfgUnknownAction := getMinimalConfig()
	cfgUnknownAction.BouncerAppsecFailureAction = "block"
	cfgEmptyAction := getMinimalConfig()
	cfgEmptyAction.BouncerLapiFailureAction = ""
	cfgEmptyAction.BouncerAppsecFailureAction = ""
	cfgAppsecHTTPS := getMinimalConfig()
	cfgAppsecHTTPS.LapiScheme = HTTP
	cfgAppsecHTTPS.AppsecScheme = HTTPS
	cfgAppsecHTTPS.AppsecTLSCa = "not a pem"
	cfgAppsecDistinctScheme := getMinimalConfig()
	cfgAppsecDistinctScheme.AppsecEnabled = true
	cfgAppsecDistinctScheme.LapiScheme = HTTP
	cfgAppsecDistinctScheme.AppsecScheme = HTTPS
	missingAppsecKeyFile := "../../tests/.missing-appsec-key"
	cfgAloneAppsecOnInvalidCA := getMinimalConfig()
	cfgAloneAppsecOnInvalidCA.LapiMode = AloneMode
	cfgAloneAppsecOnInvalidCA.LapiCapiMachineID = "machine"
	cfgAloneAppsecOnInvalidCA.LapiCapiPassword = "password"
	cfgAloneAppsecOnInvalidCA.AppsecEnabled = true
	cfgAloneAppsecOnInvalidCA.AppsecScheme = HTTPS
	cfgAloneAppsecOnInvalidCA.AppsecTLSCa = "not a pem"
	cfgAloneAppsecOnMissingKey := getMinimalConfig()
	cfgAloneAppsecOnMissingKey.LapiMode = AloneMode
	cfgAloneAppsecOnMissingKey.LapiCapiMachineID = "machine"
	cfgAloneAppsecOnMissingKey.LapiCapiPassword = "password"
	cfgAloneAppsecOnMissingKey.AppsecEnabled = true
	cfgAloneAppsecOnMissingKey.AppsecKeyFile = missingAppsecKeyFile
	cfgAloneAppsecOffLeftover := getMinimalConfig()
	cfgAloneAppsecOffLeftover.LapiMode = AloneMode
	cfgAloneAppsecOffLeftover.LapiCapiMachineID = "machine"
	cfgAloneAppsecOffLeftover.LapiCapiPassword = "password"
	cfgAloneAppsecOffLeftover.AppsecEnabled = false
	cfgAloneAppsecOffLeftover.AppsecScheme = HTTPS
	cfgAloneAppsecOffLeftover.AppsecTLSCa = "not a pem"
	cfgAloneAppsecOffLeftover.AppsecKeyFile = missingAppsecKeyFile
	cfgLiveAppsecOnInvalidCA := getMinimalConfig()
	cfgLiveAppsecOnInvalidCA.AppsecEnabled = true
	cfgLiveAppsecOnInvalidCA.LapiScheme = HTTP
	cfgLiveAppsecOnInvalidCA.AppsecScheme = HTTPS
	cfgLiveAppsecOnInvalidCA.AppsecTLSCa = "not a pem"
	cfgLiveAppsecOnMissingKey := getMinimalConfig()
	cfgLiveAppsecOnMissingKey.AppsecEnabled = true
	cfgLiveAppsecOnMissingKey.AppsecKeyFile = missingAppsecKeyFile
	cfgLiveAppsecOffLeftover := getMinimalConfig()
	cfgLiveAppsecOffLeftover.AppsecEnabled = false
	cfgLiveAppsecOffLeftover.AppsecScheme = HTTPS
	cfgLiveAppsecOffLeftover.AppsecTLSCa = "not a pem"
	cfgLiveAppsecOffLeftover.AppsecKeyFile = missingAppsecKeyFile
	cfgAppsecModeOffLeftover := getMinimalConfig()
	cfgAppsecModeOffLeftover.LapiEnabled = false
	cfgAppsecModeOffLeftover.LapiKey = ""
	cfgAppsecModeOffLeftover.AppsecEnabled = false
	cfgAppsecModeOffLeftover.AppsecScheme = HTTPS
	cfgAppsecModeOffLeftover.AppsecTLSCa = "not a pem"
	cfgAppsecModeNoLapiKey := getMinimalConfig()
	cfgAppsecModeNoLapiKey.LapiEnabled = false
	cfgAppsecModeNoLapiKey.LapiKey = ""
	cfgAppsecModeNoLapiKey.AppsecEnabled = true
	cfgAppsecModeNoLapiKey.AppsecKey = "appsec-test"
	cfgNoneMode := getMinimalConfig()
	cfgNoneMode.LapiMode = NoneMode
	cfgAloneValid := getMinimalConfig()
	cfgAloneValid.LapiMode = AloneMode
	cfgAloneValid.LapiCapiMachineID = "machine"
	cfgAloneValid.LapiCapiPassword = "password"
	cfgAloneMissingCaptchaKeys := getMinimalConfig()
	cfgAloneMissingCaptchaKeys.LapiMode = AloneMode
	cfgAloneMissingCaptchaKeys.LapiCapiMachineID = "machine"
	cfgAloneMissingCaptchaKeys.LapiCapiPassword = "password"
	cfgAloneMissingCaptchaKeys.BouncerLapiFailureAction = FailureActionCaptcha
	cfgAloneMissingCaptchaKeys.BouncerCaptchaProvider = HbouncerCaptchaProvider
	cfgAloneMissingCaptchaKeys.BouncerCaptchaGateSecret = "gate-secret"
	cfgAloneMissingCaptchaKeys.BouncerCaptchaFile = captchaTemplate
	cfgAloneBadLog := getMinimalConfig()
	cfgAloneBadLog.LapiMode = AloneMode
	cfgAloneBadLog.LapiCapiMachineID = "machine"
	cfgAloneBadLog.LapiCapiPassword = "password"
	cfgAloneBadLog.LogLevel = "Warning"
	cfgAppsecCaptchaNoProvider := getMinimalConfig()
	cfgAppsecCaptchaNoProvider.BouncerAppsecFailureAction = FailureActionCaptcha
	cfgRemediationLow := getMinimalConfig()
	cfgRemediationLow.BouncerRemediationStatusCode = 99
	cfgRemediationHigh := getMinimalConfig()
	cfgRemediationHigh.BouncerRemediationStatusCode = 600
	cfgLapiUpdateMaxFailureNegOne := getMinimalConfig()
	cfgLapiUpdateMaxFailureNegOne.LapiUpdateMaxFailure = -1
	type args struct {
		config *Config
	}
	tests := []struct {
		name            string
		args            args
		wantErr         bool
		wantErrContains string
	}{
		{name: "Validate minimal config", args: args{config: getMinimalConfig()}, wantErr: false},
		{name: "Validate a non trimed crowdsec lapi key", args: args{config: cfg1}, wantErr: false},
		{name: "Not validate unauthorized character in crowdsec lapi key", args: args{config: cfg2}, wantErr: true},
		{name: "Not validate an absent crowdsec lapi key", args: args{config: New()}, wantErr: true},
		{name: "Not validate a not listed item", args: args{config: cfg3}, wantErr: true},
		{name: "Not validate a bad number", args: args{config: cfg4}, wantErr: true},
		{name: "Not validate a bad clients ips", args: args{config: cfg5}, wantErr: true},
		// HTTPS enabled
		{name: "Validate https config with insecure verify", args: args{config: cfg6}, wantErr: false},
		{name: "Validate https without cert authority (falls back to system trust store)", args: args{config: cfg7}, wantErr: false},
		{name: "Valid log level uppercase INFO", args: args{config: cfg8}, wantErr: false},
		{name: "Valid log level lowercase info", args: args{config: cfg9}, wantErr: false},
		{name: "Valid log level lowercase trace", args: args{config: cfgTrace}, wantErr: false},
		{name: "Invalid log level Warning", args: args{config: cfg10}, wantErr: true},
		{name: "Captcha LAPI action without provider", args: args{config: cfgCaptchaNoProvider}, wantErr: true},
		{name: "Captcha LAPI action with provider", args: args{config: cfgCaptchaWithProvider}, wantErr: false},
		{name: "Provider set with empty site and secret", args: args{config: cfgEmptyKeysDefaultBan}, wantErr: true, wantErrContains: "BouncerCaptchaSiteKey: cannot be empty when BouncerCaptchaProvider is set"},
		{name: "Provider set with only site empty", args: args{config: cfgOnlySiteEmpty}, wantErr: true, wantErrContains: "BouncerCaptchaSiteKey: cannot be empty when BouncerCaptchaProvider is set"},
		{name: "Provider set with only secret empty", args: args{config: cfgOnlySecretEmpty}, wantErr: true, wantErrContains: "BouncerCaptchaSecretKey: cannot be empty when BouncerCaptchaProvider is set"},
		{name: "Provider set with whitespace-only site", args: args{config: cfgWhitespaceSite}, wantErr: true, wantErrContains: "BouncerCaptchaSiteKey: cannot be empty when BouncerCaptchaProvider is set"},
		{name: "Unknown AppSec failure action", args: args{config: cfgUnknownAction}, wantErr: true},
		{name: "Empty failure actions use default ban", args: args{config: cfgEmptyAction}, wantErr: false},
		{name: "AppSec HTTPS with invalid CA while LAPI HTTP", args: args{config: cfgAppsecHTTPS}, wantErr: false},
		{name: "AppSec distinct HTTPS scheme validates URL", args: args{config: cfgAppsecDistinctScheme}, wantErr: false},
		{name: "Alone AppSec on with invalid CA", args: args{config: cfgAloneAppsecOnInvalidCA}, wantErr: true},
		{name: "Alone AppSec on with missing key file", args: args{config: cfgAloneAppsecOnMissingKey}, wantErr: true, wantErrContains: "AppsecKey"},
		{name: "Alone AppSec off leftover CA and key file", args: args{config: cfgAloneAppsecOffLeftover}, wantErr: false},
		{name: "Live AppSec on with invalid CA", args: args{config: cfgLiveAppsecOnInvalidCA}, wantErr: true},
		{name: "Live AppSec on with missing key file", args: args{config: cfgLiveAppsecOnMissingKey}, wantErr: true, wantErrContains: "AppsecKey"},
		{name: "Live AppSec off leftover CA and key file", args: args{config: cfgLiveAppsecOffLeftover}, wantErr: false},
		{name: "LAPI disabled leftover invalid AppSec CA", args: args{config: cfgAppsecModeOffLeftover}, wantErr: false},
		{name: "AppSec-only without LAPI key", args: args{config: cfgAppsecModeNoLapiKey}, wantErr: false},
		{name: "None mode minimal config", args: args{config: cfgNoneMode}, wantErr: false},
		{name: "Alone mode with CAPI credentials", args: args{config: cfgAloneValid}, wantErr: false},
		{name: "Alone mode captcha without site/secret keys", args: args{config: cfgAloneMissingCaptchaKeys}, wantErr: true, wantErrContains: "BouncerCaptchaSiteKey: cannot be empty when BouncerCaptchaProvider is set"},
		{name: "Alone mode invalid log level", args: args{config: cfgAloneBadLog}, wantErr: true},
		{name: "AppSec captcha action without provider", args: args{config: cfgAppsecCaptchaNoProvider}, wantErr: true},
		{name: "BouncerRemediationStatusCode below 100", args: args{config: cfgRemediationLow}, wantErr: true},
		{name: "BouncerRemediationStatusCode 600 or above", args: args{config: cfgRemediationHigh}, wantErr: true},
		{name: "LapiUpdateMaxFailure -1 accepted", args: args{config: cfgLapiUpdateMaxFailureNegOne}, wantErr: false},
		{name: "Custom json validate body accepted", args: args{config: newCustomValidateBodyConfig(t, "json")}, wantErr: false},
		{name: "Custom form validate body accepted", args: args{config: newCustomValidateBodyConfig(t, "form")}, wantErr: false},
		{name: "Custom omit validate body accepted", args: args{config: newCustomValidateBodyConfig(t, "")}, wantErr: false},
		{name: "Custom whitespace-padded json accepted", args: args{config: newCustomValidateBodyConfig(t, " json ")}, wantErr: false},
		{name: "Built-in json validate body rejected", args: args{config: newBuiltinValidateBodyConfig(t, HbouncerCaptchaProvider, "json")}, wantErr: true, wantErrContains: "BouncerCaptchaCustomValidateBody: json is only valid when BouncerCaptchaProvider is custom"},
		{name: "Recaptcha json validate body rejected", args: args{config: newBuiltinValidateBodyConfig(t, RebouncerCaptchaProvider, "json")}, wantErr: true, wantErrContains: "BouncerCaptchaCustomValidateBody: json is only valid when BouncerCaptchaProvider is custom"},
		{name: "Turnstile json validate body rejected", args: args{config: newBuiltinValidateBodyConfig(t, TurnstileProvider, "json")}, wantErr: true, wantErrContains: "BouncerCaptchaCustomValidateBody: json is only valid when BouncerCaptchaProvider is custom"},
		{name: "Unknown JSON token rejected", args: args{config: newCustomValidateBodyConfig(t, "JSON")}, wantErr: true, wantErrContains: "BouncerCaptchaCustomValidateBody: must be empty, form, or json"},
		{name: "Unknown Form token rejected", args: args{config: newCustomValidateBodyConfig(t, "Form")}, wantErr: true, wantErrContains: "BouncerCaptchaCustomValidateBody: must be empty, form, or json"},
		{name: "Unknown xml token rejected", args: args{config: newCustomValidateBodyConfig(t, "xml")}, wantErr: true, wantErrContains: "BouncerCaptchaCustomValidateBody: must be empty, form, or json"},
		{name: "Built-in form validate body accepted", args: args{config: newBuiltinValidateBodyConfig(t, HbouncerCaptchaProvider, "form")}, wantErr: false},
		{name: "Built-in omit validate body accepted", args: args{config: newBuiltinValidateBodyConfig(t, HbouncerCaptchaProvider, "")}, wantErr: false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateParams(tt.args.config, log)
			if (err != nil) != tt.wantErr {
				t.Errorf("validateParams() error = %v, wantErr %v", err, tt.wantErr)
			}
			if tt.wantErrContains != "" && (err == nil || !strings.Contains(err.Error(), tt.wantErrContains)) {
				t.Errorf("validateParams() error = %v, want containing %q", err, tt.wantErrContains)
			}
		})
	}
}

// Test_ValidateParams_captchaTemplateRequired fails empty or missing captcha
// templates when a provider is set, and keeps ban template optional.
func Test_ValidateParams_captchaTemplateRequired(t *testing.T) {
	log := logger.New("INFO", "")
	captchaTemplate := writeCaptchaTemplateFixture(t)

	cfgEmptyCaptchaPath := getMinimalConfig()
	cfgEmptyCaptchaPath.BouncerCaptchaProvider = HbouncerCaptchaProvider
	cfgEmptyCaptchaPath.BouncerCaptchaSiteKey = "site"
	cfgEmptyCaptchaPath.BouncerCaptchaSecretKey = "secret"
	cfgEmptyCaptchaPath.BouncerCaptchaGateSecret = "gate-secret"
	cfgEmptyCaptchaPath.BouncerCaptchaFile = ""

	cfgMissingCaptchaFile := getMinimalConfig()
	cfgMissingCaptchaFile.BouncerCaptchaProvider = HbouncerCaptchaProvider
	cfgMissingCaptchaFile.BouncerCaptchaSiteKey = "site"
	cfgMissingCaptchaFile.BouncerCaptchaSecretKey = "secret"
	cfgMissingCaptchaFile.BouncerCaptchaGateSecret = "gate-secret"
	cfgMissingCaptchaFile.BouncerCaptchaFile = filepath.Join(t.TempDir(), "missing-captcha.html")

	cfgEmptyBanPath := getMinimalConfig()
	cfgEmptyBanPath.BouncerCaptchaProvider = HbouncerCaptchaProvider
	cfgEmptyBanPath.BouncerCaptchaSiteKey = "site"
	cfgEmptyBanPath.BouncerCaptchaSecretKey = "secret"
	cfgEmptyBanPath.BouncerCaptchaGateSecret = "gate-secret"
	cfgEmptyBanPath.BouncerCaptchaFile = captchaTemplate
	cfgEmptyBanPath.BouncerBanFile = ""

	cfgAloneEmptyCaptchaPath := getMinimalConfig()
	cfgAloneEmptyCaptchaPath.LapiMode = AloneMode
	cfgAloneEmptyCaptchaPath.LapiCapiMachineID = "machine"
	cfgAloneEmptyCaptchaPath.LapiCapiPassword = "password"
	cfgAloneEmptyCaptchaPath.BouncerCaptchaProvider = HbouncerCaptchaProvider
	cfgAloneEmptyCaptchaPath.BouncerCaptchaSiteKey = "site"
	cfgAloneEmptyCaptchaPath.BouncerCaptchaSecretKey = "secret"
	cfgAloneEmptyCaptchaPath.BouncerCaptchaGateSecret = "gate-secret"
	cfgAloneEmptyCaptchaPath.BouncerCaptchaFile = ""

	tests := []struct {
		name            string
		config          *Config
		wantErr         bool
		wantErrContains string
	}{
		{name: "Provider set with empty captcha path", config: cfgEmptyCaptchaPath, wantErr: true, wantErrContains: "BouncerCaptchaFile: cannot be empty when BouncerCaptchaProvider is set"},
		{name: "Provider set with missing captcha file", config: cfgMissingCaptchaFile, wantErr: true},
		{name: "Provider set with empty ban path still accepted", config: cfgEmptyBanPath, wantErr: false},
		{name: "Alone mode empty captcha path", config: cfgAloneEmptyCaptchaPath, wantErr: true, wantErrContains: "BouncerCaptchaFile: cannot be empty when BouncerCaptchaProvider is set"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateParams(tt.config, log)
			if (err != nil) != tt.wantErr {
				t.Errorf("ValidateParams() error = %v, wantErr %v", err, tt.wantErr)
			}
			if tt.wantErrContains != "" && (err == nil || !strings.Contains(err.Error(), tt.wantErrContains)) {
				t.Errorf("ValidateParams() error = %v, want containing %q", err, tt.wantErrContains)
			}
		})
	}
}

// Test_ValidateParams_skipsRedisPasswordFileWhenRedisDisabled pins that
// LapiRedisPasswordFile is Stat/read only when lapiRedisEnabled is true.
func Test_ValidateParams_skipsRedisPasswordFileWhenRedisDisabled(t *testing.T) {
	log := logger.New("INFO", "")
	missingFile := filepath.Join(t.TempDir(), "missing-redis-password")
	staleDir := t.TempDir()

	disabledMissing := getMinimalConfig()
	disabledMissing.LapiRedisEnabled = false
	disabledMissing.LapiRedisPasswordFile = missingFile

	disabledStale := getMinimalConfig()
	disabledStale.LapiRedisEnabled = false
	disabledStale.LapiRedisPasswordFile = staleDir

	enabledMissing := getMinimalConfig()
	enabledMissing.LapiRedisEnabled = true
	enabledMissing.LapiRedisPasswordFile = missingFile

	enabledEmpty := getMinimalConfig()
	enabledEmpty.LapiRedisEnabled = true
	enabledEmpty.LapiRedisPassword = ""
	enabledEmpty.LapiRedisPasswordFile = ""

	tests := []struct {
		name    string
		config  *Config
		wantErr bool
	}{
		{name: "disabled Redis ignores a missing password file", config: disabledMissing, wantErr: false},
		{name: "disabled Redis ignores a directory password file", config: disabledStale, wantErr: false},
		{name: "enabled Redis rejects a missing password file", config: enabledMissing, wantErr: true},
		{name: "enabled Redis accepts an empty password with no file", config: enabledEmpty, wantErr: false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateParams(tt.config, log)
			if (err != nil) != tt.wantErr {
				t.Errorf("ValidateParams() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func Test_validateParamsTLS(t *testing.T) {
	cfgEmpty := getMinimalConfig()
	cfgValid := getMinimalConfig()
	cfgValid.LapiTLSCa = validPEM
	cfgInvalidCA := getMinimalConfig()
	cfgInvalidCA.LapiTLSCa = "not a pem"

	tests := []struct {
		name    string
		config  *Config
		wantErr bool
	}{
		{name: "Empty CA is accepted (system trust store used at runtime)", config: cfgEmpty, wantErr: false},
		{name: "Valid PEM CA is accepted", config: cfgValid, wantErr: false},
		{name: "Invalid CA is rejected", config: cfgInvalidCA, wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := validateParamsTLS(tt.config, "Lapi"); (err != nil) != tt.wantErr {
				t.Errorf("validateParamsTLS() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func Test_validateParamsIPs(t *testing.T) {
	log := logger.New("INFO", "")
	type args struct {
		listIP []string
		key    string
	}
	tests := []struct {
		name    string
		args    args
		wantErr bool
	}{
		{name: "Not validate a non ip", args: args{listIP: []string{0: "bad"}}, wantErr: true},
		{name: "Not validate localhost", args: args{listIP: []string{0: "localhost"}}, wantErr: true},
		{name: "Not validate a weird ip", args: args{listIP: []string{0: "0.0.0.0/89"}}, wantErr: true},
		{name: "Not validate a weird ip 2", args: args{listIP: []string{0: "0.0.0.256/12"}}, wantErr: true},
		{name: "Validate an ip not trimmed", args: args{listIP: []string{0: " 0.0.0.0/0"}}, wantErr: false},
		{name: "Validate an ip", args: args{listIP: []string{0: "0.0.0.0/12"}}, wantErr: false},
		{name: "Validate an ip list", args: args{listIP: []string{0: "0.0.0.0/0", 1: "1.1.1.1/1"}}, wantErr: false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := validateParamsIPs(log, tt.args.listIP, tt.args.key); (err != nil) != tt.wantErr {
				t.Errorf("validateParamsIPs() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func Test_validateParamsRequired(t *testing.T) {
	cfg2 := getMinimalConfig()
	cfg2.LapiScheme = "bad"
	cfg3 := getMinimalConfig()
	cfg3.LapiMode = "bad"
	cfg4 := getMinimalConfig()
	cfg4.LapiUpdateIntervalSeconds = 0
	cfg5 := getMinimalConfig()
	cfg5.BouncerLiveTTLSeconds = 0
	type args struct {
		config *Config
	}
	tests := []struct {
		name    string
		args    args
		wantErr bool
	}{
		{name: "Validate minimal config", args: args{config: getMinimalConfig()}, wantErr: false},
		{name: "Not validate a bad crowdsec scheme", args: args{config: cfg2}, wantErr: true},
		{name: "Not validate a bad crowdsec mode", args: args{config: cfg3}, wantErr: true},
		{name: "Not validate a bad update interval seconds", args: args{config: cfg4}, wantErr: true},
		{name: "Not validate a bad default decision seconds", args: args{config: cfg5}, wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := validateParamsRequired(tt.args.config); (err != nil) != tt.wantErr {
				t.Errorf("validateParamsRequired() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func Test_validateParamsAPIKey(t *testing.T) {
	type args struct {
		lapiKey   string
		paramName string
	}
	tests := []struct {
		name    string
		args    args
		wantErr bool
	}{
		{name: "Validate all the valid characters", args: args{lapiKey: "test!#$%&'*+-.^_`|~", paramName: "CrowdsecParamName"}, wantErr: false},
		{name: "Not validate a @", args: args{lapiKey: "test@", paramName: "CrowdsecParamName"}, wantErr: true},
		{name: "Not validate a (", args: args{lapiKey: "test(", paramName: "CrowdsecParamName"}, wantErr: true},
		{name: "Not validate a [", args: args{lapiKey: "test[", paramName: "CrowdsecParamName"}, wantErr: true},
		{name: "Not validate a ?", args: args{lapiKey: "test?", paramName: "CrowdsecParamName"}, wantErr: true},
		{name: "Not validate a \\n, (must be trimed before)", args: args{lapiKey: "test\n", paramName: "CrowdsecParamName"}, wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := validateParamsAPIKey(tt.args.lapiKey, tt.args.paramName); (err != nil) != tt.wantErr {
				t.Errorf("validateParamsAPIKey() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func Test_GetTLSConfigCrowdsec(t *testing.T) {
	log := logger.New("INFO", "")

	httpCfg := getMinimalConfig()
	httpCfg.LapiScheme = HTTP

	httpsSystemCA := getMinimalConfig()
	httpsSystemCA.LapiScheme = HTTPS

	httpsCustomCA := getMinimalConfig()
	httpsCustomCA.LapiScheme = HTTPS
	httpsCustomCA.LapiTLSCa = validPEM

	httpsInsecure := getMinimalConfig()
	httpsInsecure.LapiScheme = HTTPS
	httpsInsecure.LapiTLSInsecureVerify = true

	httpsBadCA := getMinimalConfig()
	httpsBadCA.LapiScheme = HTTPS
	httpsBadCA.LapiTLSCa = "not a pem"

	tests := []struct {
		name             string
		config           *Config
		wantErr          bool
		wantRootCAsNil   bool
		wantInsecureSkip bool
	}{
		{name: "HTTP scheme returns empty tls.Config", config: httpCfg, wantRootCAsNil: true},
		{name: "HTTPS without CA leaves RootCAs nil (system trust store)", config: httpsSystemCA, wantRootCAsNil: true},
		{name: "HTTPS with custom CA populates RootCAs", config: httpsCustomCA, wantRootCAsNil: false},
		{name: "HTTPS with insecure verify sets InsecureSkipVerify", config: httpsInsecure, wantRootCAsNil: true, wantInsecureSkip: true},
		{name: "HTTPS with garbage CA is rejected", config: httpsBadCA, wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := GetTLSConfigCrowdsec(tt.config, log, false)
			if (err != nil) != tt.wantErr {
				t.Errorf("GetTLSConfigCrowdsec() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if tt.wantErr {
				return
			}
			if (got.RootCAs == nil) != tt.wantRootCAsNil {
				t.Errorf("GetTLSConfigCrowdsec() RootCAs nil = %v, want nil = %v", got.RootCAs == nil, tt.wantRootCAsNil)
			}
			if got.InsecureSkipVerify != tt.wantInsecureSkip {
				t.Errorf("GetTLSConfigCrowdsec() InsecureSkipVerify = %v, want %v", got.InsecureSkipVerify, tt.wantInsecureSkip)
			}
		})
	}
}

func Test_getContentTypeFromPath(t *testing.T) {
	tests := []struct {
		name     string
		path     string
		expected string
	}{
		{name: "HTML file with .html extension", path: "/ban.html", expected: "text/html; charset=utf-8"},
		{name: "JSON file", path: "/ban.json", expected: "application/json"},
		{name: "Text file", path: "/ban.txt", expected: "text/plain"},
		{name: "File with mixed case extension", path: "/ban.HtMl", expected: "text/html; charset=utf-8"},
		{name: "Unknown extension defaults to HTML", path: "/ban.xyz", expected: "text/html; charset=utf-8"},
		{name: "File without extension", path: "/ban", expected: "text/html; charset=utf-8"},
		{name: "Empty path", path: "", expected: ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := getContentTypeFromPath(tt.path)
			if got != tt.expected {
				t.Errorf("GetContentTypeFromPath(%q) = %q, want %q", tt.path, got, tt.expected)
			}
		})
	}
}

func Test_validateLapiScopeHeaders(t *testing.T) {
	cfg := getMinimalConfig()
	cfg.LapiScopeHeaders = map[string]string{"Country": "CF-IPCountry"}
	if err := validateLapiScopeHeaders(cfg); err != nil {
		t.Fatalf("valid Country map: %v", err)
	}
	cfg.LapiScopeHeaders = map[string]string{"Ip": "X-Real-IP"}
	if err := validateLapiScopeHeaders(cfg); err == nil {
		t.Fatal("Ip key must be rejected")
	}
	cfg.LapiScopeHeaders = map[string]string{"RANGE": "X-Range"}
	if err := validateLapiScopeHeaders(cfg); err == nil {
		t.Fatal("Range key must be rejected")
	}
	cfg.LapiScopeHeaders = map[string]string{"": "X-Empty"}
	if err := validateLapiScopeHeaders(cfg); err == nil {
		t.Fatal("empty scope must be rejected")
	}
	cfg.LapiScopeHeaders = map[string]string{"username": "  "}
	if err := validateLapiScopeHeaders(cfg); err == nil {
		t.Fatal("empty header must be rejected")
	}
}

func newCustomValidateBodyConfig(t *testing.T, validateBody string) *Config {
	t.Helper()
	cfg := getMinimalConfig()
	cfg.BouncerCaptchaProvider = CustomProvider
	cfg.BouncerCaptchaCustomKey = "wicketkeeper"
	cfg.BouncerCaptchaCustomResponse = "wicketkeeper_solution"
	cfg.BouncerCaptchaCustomValidateURL = "http://wicketkeeper:8080/v0/siteverify"
	cfg.BouncerCaptchaCustomJsURL = "http://wicketkeeper:8080/fast.js"
	cfg.BouncerCaptchaCustomValidateBody = validateBody
	cfg.BouncerCaptchaSiteKey = "site"
	cfg.BouncerCaptchaSecretKey = "secret"
	cfg.BouncerCaptchaGateSecret = "gate-secret"
	cfg.BouncerCaptchaFile = writeCaptchaTemplateFixture(t)
	return cfg
}

func newBuiltinValidateBodyConfig(t *testing.T, provider, validateBody string) *Config {
	t.Helper()
	cfg := getMinimalConfig()
	cfg.BouncerCaptchaProvider = provider
	cfg.BouncerCaptchaCustomValidateBody = validateBody
	cfg.BouncerCaptchaSiteKey = "site"
	cfg.BouncerCaptchaSecretKey = "secret"
	cfg.BouncerCaptchaGateSecret = "gate-secret"
	cfg.BouncerCaptchaFile = writeCaptchaTemplateFixture(t)
	return cfg
}

func Test_validateCaptcha(t *testing.T) {
	cfgCustomMissing := getMinimalConfig()
	cfgCustomMissing.BouncerCaptchaProvider = CustomProvider
	cfgCustomFourFields := getMinimalConfig()
	cfgCustomFourFields.BouncerCaptchaProvider = CustomProvider
	cfgCustomFourFields.BouncerCaptchaCustomKey = "wicketkeeper"
	cfgCustomFourFields.BouncerCaptchaCustomResponse = "wicketkeeper_solution"
	cfgCustomFourFields.BouncerCaptchaCustomValidateURL = "http://wicketkeeper:8080/v0/siteverify"
	cfgCustomFourFields.BouncerCaptchaCustomJsURL = "http://wicketkeeper:8080/fast.js"
	cfgCustomFourFields.BouncerCaptchaCustomChallengeURL = ""
	tests := []struct {
		name    string
		config  *Config
		wantErr bool
	}{
		{name: "Valid hcaptcha provider", config: getMinimalConfig(), wantErr: false},
		{name: "Custom provider missing fields", config: cfgCustomMissing, wantErr: true},
		{name: "Custom provider four fields empty challenge URL", config: cfgCustomFourFields, wantErr: false},
		{name: "Custom json", config: newCustomValidateBodyConfig(t, "json"), wantErr: false},
		{name: "Custom form", config: newCustomValidateBodyConfig(t, "form"), wantErr: false},
		{name: "Custom omit", config: newCustomValidateBodyConfig(t, ""), wantErr: false},
		{name: "Custom whitespace-padded json", config: newCustomValidateBodyConfig(t, " json "), wantErr: false},
		{name: "Built-in json rejected", config: newBuiltinValidateBodyConfig(t, HbouncerCaptchaProvider, "json"), wantErr: true},
		{name: "Unknown JSON token rejected", config: newCustomValidateBodyConfig(t, "JSON"), wantErr: true},
		{name: "Unknown Form token rejected", config: newCustomValidateBodyConfig(t, "Form"), wantErr: true},
		{name: "Built-in form ignored", config: newBuiltinValidateBodyConfig(t, HbouncerCaptchaProvider, "form"), wantErr: false},
		{name: "Built-in omit ignored", config: newBuiltinValidateBodyConfig(t, HbouncerCaptchaProvider, ""), wantErr: false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := validateCaptcha(tt.config); (err != nil) != tt.wantErr {
				t.Errorf("validateCaptcha() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func Test_CustomCaptchaResourcePath(t *testing.T) {
	tests := []struct {
		name   string
		rawURL string
		want   string
	}{
		{name: "Absolute URL keeps its path", rawURL: "http://captcha.localhost:8000/v0/challenge", want: "/v0/challenge"},
		{name: "Bare path is kept", rawURL: "/v0/challenge", want: "/v0/challenge"},
		{name: "Query is dropped", rawURL: "/v0/challenge?difficulty=4", want: "/v0/challenge"},
		{name: "Empty value has no path", rawURL: "", want: ""},
		{name: "Relative value has no path", rawURL: "fast.js", want: ""},
		{name: "Host without a path has no path", rawURL: "http://captcha.localhost:8000", want: ""},
		{name: "Missing scheme is not a path", rawURL: "captcha.localhost:8000/v0/challenge", want: ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := CustomCaptchaResourcePath(tt.rawURL); got != tt.want {
				t.Errorf("CustomCaptchaResourcePath(%q) = %q, want %q", tt.rawURL, got, tt.want)
			}
		})
	}
}

func Test_validateEnabledCaptchaSettings_customChallengeURL(t *testing.T) {
	captchaTemplate := writeCaptchaTemplateFixture(t)
	newCustomConfig := func(challengeURL string) *Config {
		cfg := getMinimalConfig()
		cfg.BouncerCaptchaProvider = CustomProvider
		cfg.BouncerCaptchaSiteKey = "site"
		cfg.BouncerCaptchaSecretKey = "secret"
		cfg.BouncerCaptchaGateSecret = "gate-secret"
		cfg.BouncerCaptchaFile = captchaTemplate
		cfg.BouncerCaptchaCustomChallengeURL = challengeURL
		return cfg
	}
	tests := []struct {
		name         string
		challengeURL string
		wantErr      bool
	}{
		{name: "Empty challenge URL is valid", challengeURL: "", wantErr: false},
		{name: "Absolute challenge URL is valid", challengeURL: "http://captcha.localhost:8000/v0/challenge", wantErr: false},
		{name: "Bare challenge path is valid", challengeURL: "/v0/challenge", wantErr: false},
		{name: "Challenge URL without a path is rejected", challengeURL: "http://captcha.localhost:8000", wantErr: true},
		{name: "Relative challenge URL is rejected", challengeURL: "v0/challenge", wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateEnabledCaptchaSettings(newCustomConfig(tt.challengeURL))
			if (err != nil) != tt.wantErr {
				t.Errorf("validateEnabledCaptchaSettings() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}

	// A built-in provider ignores the key, so a stale value must not block startup.
	builtin := getMinimalConfig()
	builtin.BouncerCaptchaProvider = HbouncerCaptchaProvider
	builtin.BouncerCaptchaSiteKey = "site"
	builtin.BouncerCaptchaSecretKey = "secret"
	builtin.BouncerCaptchaGateSecret = "gate-secret"
	builtin.BouncerCaptchaFile = captchaTemplate
	builtin.BouncerCaptchaCustomChallengeURL = "v0/challenge"
	if err := validateEnabledCaptchaSettings(builtin); err != nil {
		t.Errorf("built-in provider must ignore BouncerCaptchaCustomChallengeURL, got %v", err)
	}
}

func Test_validateURL(t *testing.T) {
	tests := []struct {
		name    string
		scheme  string
		host    string
		path    string
		wantErr bool
	}{
		{name: "Valid URL", scheme: HTTP, host: "crowdsec:8080", path: "/", wantErr: false},
		{name: "Invalid host with spaces", scheme: HTTP, host: "bad host", path: "/", wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := validateURL("Test", tt.scheme, tt.host, tt.path); (err != nil) != tt.wantErr {
				t.Errorf("validateURL() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func Test_GetTemplate(t *testing.T) {
	t.Run("Empty path", func(t *testing.T) {
		_, _, err := GetTemplate("")
		if err == nil {
			t.Fatal("expected error for empty path")
		}
	})
	t.Run("Missing file", func(t *testing.T) {
		_, _, err := GetTemplate(filepath.Join(t.TempDir(), "missing.html"))
		if err == nil {
			t.Fatal("expected error for missing file")
		}
	})
	t.Run("Invalid template syntax", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "bad.html")
		if err := os.WriteFile(path, []byte("{{"), 0600); err != nil {
			t.Fatal(err)
		}
		_, _, err := GetTemplate(path)
		if err == nil {
			t.Fatal("expected compile error")
		}
	})
	t.Run("Valid template", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "ok.html")
		if err := os.WriteFile(path, []byte("hello {{ .Name }}"), 0600); err != nil {
			t.Fatal(err)
		}
		tmpl, ct, err := GetTemplate(path)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if tmpl == nil || ct == "" {
			t.Fatal("expected template and content type")
		}
	})
}

func Test_validateParamsTLS_appsec(t *testing.T) {
	cfgValid := getMinimalConfig()
	cfgValid.AppsecTLSCa = validPEM
	cfgInvalid := getMinimalConfig()
	cfgInvalid.AppsecTLSCa = "not a pem"

	tests := []struct {
		name    string
		config  *Config
		wantErr bool
	}{
		{name: "Valid AppSec CA PEM", config: cfgValid, wantErr: false},
		{name: "Invalid AppSec CA PEM", config: cfgInvalid, wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := validateParamsTLS(tt.config, "Appsec"); (err != nil) != tt.wantErr {
				t.Errorf("validateParamsTLS() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

// TestHunt_ValidateParams_closesLogFileAfterWritabilityCheck proves a successful
// writable-path check does not keep the check descriptor, and an unwritable path still fails.
func TestHunt_ValidateParams_closesLogFileAfterWritabilityCheck(t *testing.T) {
	log := logger.New("INFO", "")

	t.Run("successful writable path leaves no check descriptor", func(t *testing.T) {
		cfg := getMinimalConfig()
		logPath := filepath.Join(t.TempDir(), "plugin.log")
		cfg.LogFilePath = logPath
		if err := ValidateParams(cfg, log); err != nil {
			t.Fatalf("ValidateParams = %v want nil", err)
		}
		assertWritabilityCheckHandleClosed(t, logPath)
	})

	t.Run("unwritable path still fails", func(t *testing.T) {
		cfg := getMinimalConfig()
		cfg.LogFilePath = filepath.Join(t.TempDir(), "missing-dir", "plugin.log")
		if err := ValidateParams(cfg, log); err == nil {
			t.Fatal("ValidateParams = nil want error")
		}
	})
}

// assertWritabilityCheckHandleClosed fails when the process still holds a descriptor for path.
func assertWritabilityCheckHandleClosed(t *testing.T, path string) {
	t.Helper()
	cleaned := filepath.Clean(path)
	if runtime.GOOS == "windows" {
		if err := os.Remove(cleaned); err != nil {
			t.Fatalf("os.Remove(%s) = %v; writability-check handle still open", cleaned, err)
		}
		return
	}
	entries, err := os.ReadDir("/proc/self/fd")
	if err != nil {
		t.Logf("skip leak assertion: neither Windows nor /proc/self/fd (%v)", err)
		return
	}
	for _, entry := range entries {
		target, err := os.Readlink(filepath.Join("/proc/self/fd", entry.Name()))
		if err != nil {
			continue
		}
		if target == cleaned || filepath.Clean(target) == cleaned {
			t.Fatalf("/proc/self/fd/%s still names %s", entry.Name(), cleaned)
		}
	}
}

// TestValidateParams_EmptyAppsecHost pins enabled AppSec rejecting a missing
// listener host while disabled AppSec still accepts an empty host.
func TestValidateParams_EmptyAppsecHost(t *testing.T) {
	log := logger.New("INFO", "")
	t.Run("enabled rejects empty host", func(t *testing.T) {
		cfg := getMinimalConfig()
		cfg.AppsecEnabled = true
		cfg.AppsecHost = ""
		if err := ValidateParams(cfg, log); err == nil {
			t.Fatal("ValidateParams = nil want error")
		}
	})
	t.Run("disabled accepts empty host", func(t *testing.T) {
		cfg := getMinimalConfig()
		cfg.AppsecEnabled = false
		cfg.AppsecHost = ""
		if err := ValidateParams(cfg, log); err != nil {
			t.Fatalf("ValidateParams = %v want nil", err)
		}
	})
}

func TestBouncerForwardedInsecure(t *testing.T) {
	log := logger.New("INFO", "")
	t.Run("defaults to false", func(t *testing.T) {
		if New().BouncerForwardedInsecure {
			t.Fatal("BouncerForwardedInsecure default = true want false")
		}
	})
	t.Run("flag plus populated trusted list is accepted", func(t *testing.T) {
		cfg := getMinimalConfig()
		cfg.BouncerForwardedInsecure = true
		cfg.BouncerForwardedTrustedIPs = []string{"10.0.0.0/8"}
		if err := ValidateParams(cfg, log); err != nil {
			t.Fatalf("ValidateParams = %v want nil", err)
		}
	})
	t.Run("flag plus invalid CIDR still fails", func(t *testing.T) {
		cfg := getMinimalConfig()
		cfg.BouncerForwardedInsecure = true
		cfg.BouncerForwardedTrustedIPs = []string{"not-a-cidr"}
		if err := ValidateParams(cfg, log); err == nil {
			t.Fatal("ValidateParams = nil want error")
		}
	})
}
