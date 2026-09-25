package captcha

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pkg/configuration"
	"github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pkg/yaegitest"
)

// yaegiProviderCase is one Open call for a captcha provider the bouncer builds.
type yaegiProviderCase struct {
	name         string
	provider     string
	js           string
	challengeURL string
	key          string
	response     string
	validate     string
	validateBody string
	action       string
	apiKey       string
	keyType      string
	minScore     string
	projectID    string
}

// TestYaegi_Open_eachProvider opens every captcha provider under Yaegi v0.16.1.
// The bouncer calls Open, and Open calls Client.New, inside that interpreter.
// A compiled test never assigns the verifier to the Verifier interface there,
// so a panic on that assignment stays hidden.
func TestYaegi_Open_eachProvider(t *testing.T) {
	goPath := yaegitest.GoPath(t)
	templatePath := filepath.Join(t.TempDir(), "captcha.html")
	if err := os.WriteFile(templatePath, []byte("captcha"), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, providerCase := range yaegiProviderCases() {
		t.Run(providerCase.name, func(t *testing.T) {
			yaegitest.Run(t, goPath, providerCase.source(templatePath))
		})
	}
}

// yaegiProviderCases is every provider branch of Client.New, including both enterprise key types.
func yaegiProviderCases() []yaegiProviderCase {
	return []yaegiProviderCase{
		{
			name:         configuration.CustomProvider,
			provider:     configuration.CustomProvider,
			js:           "https://captcha.example/fast.js",
			challengeURL: "https://captcha.example/challenge",
			key:          "custom-key",
			response:     "custom-response",
			validate:     "https://captcha.example/siteverify",
			validateBody: "form",
		},
		{
			name:      configuration.RecaptchaEnterpriseProvider + "/checkbox",
			provider:  configuration.RecaptchaEnterpriseProvider,
			apiKey:    "api-key",
			keyType:   configuration.CaptchaEnterpriseKeyTypeCheckbox,
			projectID: "project",
		},
		{
			name:      configuration.RecaptchaEnterpriseProvider + "/score",
			provider:  configuration.RecaptchaEnterpriseProvider,
			action:    "login",
			apiKey:    "api-key",
			keyType:   configuration.CaptchaEnterpriseKeyTypeScore,
			minScore:  "0.5",
			projectID: "project",
		},
		{name: configuration.EucaptchaProvider, provider: configuration.EucaptchaProvider},
		{name: configuration.HcaptchaProvider, provider: configuration.HcaptchaProvider},
		{name: configuration.RecaptchaProvider, provider: configuration.RecaptchaProvider},
		{name: configuration.TurnstileProvider, provider: configuration.TurnstileProvider},
	}
}

// source is the interpreted program that calls Open for this provider.
// Open builds the HTTP client and logger inside the captcha package, as the bouncer does.
func (c yaegiProviderCase) source(templatePath string) string {
	return fmt.Sprintf(`package main

import (
	"context"
	"fmt"
	"os"

	captcha %q
	configuration %q
	logger %q
)

func main() {
	cfg := configuration.New()
	cfg.CaptchaEnabled = true
	cfg.CaptchaProvider = %q
	cfg.CaptchaSiteKey = "site-key"
	cfg.CaptchaSecretKey = "secret-key"
	cfg.CaptchaGateSecret = "gate-secret"
	cfg.CaptchaFilePath = %q
	cfg.CaptchaCustomJsURL = %q
	cfg.CaptchaCustomChallengeURL = %q
	cfg.CaptchaCustomKey = %q
	cfg.CaptchaCustomResponse = %q
	cfg.CaptchaCustomValidateURL = %q
	cfg.CaptchaCustomValidateBody = %q
	cfg.CaptchaEnterpriseAction = %q
	cfg.CaptchaEnterpriseAPIKey = %q
	cfg.CaptchaEnterpriseKeyType = %q
	cfg.CaptchaEnterpriseMinScore = %q
	cfg.CaptchaEnterpriseProjectID = %q
	_, err := captcha.Open(context.Background(), cfg, logger.New("ERROR", ""), "crowdsec", "test")
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
`, yaegitest.ModulePath+"/pkg/captcha",
		yaegitest.ModulePath+"/pkg/configuration",
		yaegitest.ModulePath+"/pkg/logger",
		c.provider, templatePath,
		c.js, c.challengeURL, c.key, c.response, c.validate, c.validateBody,
		c.action, c.apiKey, c.keyType, c.minScore, c.projectID)
}
