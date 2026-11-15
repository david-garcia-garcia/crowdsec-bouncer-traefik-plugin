package captcha

import (
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// newMarkerTestClient runs New with the given challenge template and returns the client and its WARN log.
func newMarkerTestClient(t *testing.T, templatePath string) (*Client, string) {
	t.Helper()
	log, sink := newTestLogSink(slog.LevelWarn)
	client := &Client{}
	err := client.New(
		log,
		http.DefaultClient,
		"hcaptcha",
		"",
		"",
		"",
		"",
		"",
		"",
		"site",
		"secret",
		"gate-secret",
		true,
		templatePath,
		3600,
		Enterprise{},
	)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	return client, sink.String()
}

func writeMarkerTestTemplate(t *testing.T, content string) string {
	t.Helper()
	templatePath := filepath.Join(t.TempDir(), "captcha.html")
	if err := os.WriteFile(templatePath, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	return templatePath
}

// Test_New_warnsWhenCaptchaTemplateLacksChallengeMarker keeps the captcha usable and warns once.
func Test_New_warnsWhenCaptchaTemplateLacksChallengeMarker(t *testing.T) {
	templatePath := writeMarkerTestTemplate(t, `<form method="POST"><div class="h-captcha"></div></form>`)
	client, logged := newMarkerTestClient(t, templatePath)
	if !client.Valid {
		t.Fatal("a template without the challenge marker must still load")
	}
	if strings.Count(logged, msgCaptchaTemplateMarkerMissing) != 1 {
		t.Fatalf("want one marker WARN, got %s", logged)
	}
	if !strings.Contains(logged, `"marker":"crowdsec_captcha_challenge=v1"`) {
		t.Fatalf("want marker field, got %s", logged)
	}
}

// Test_New_silentWhenCaptchaTemplateHasChallengeMarker covers a custom template and the stock page.
func Test_New_silentWhenCaptchaTemplateHasChallengeMarker(t *testing.T) {
	cases := map[string]string{
		"custom template": writeMarkerTestTemplate(t, `<form method="POST"><input type="hidden" name="crowdsec_captcha_challenge" value="v1"></form>`),
		"stock template":  filepath.Join("..", "..", "captcha.html"),
	}
	for name, templatePath := range cases {
		t.Run(name, func(t *testing.T) {
			client, logged := newMarkerTestClient(t, templatePath)
			if !client.Valid {
				t.Fatalf("template %s must load, log: %s", templatePath, logged)
			}
			if strings.Contains(logged, msgCaptchaTemplateMarkerMissing) {
				t.Fatalf("unexpected marker WARN: %s", logged)
			}
		})
	}
}
