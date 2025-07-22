package captcha

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/maxlerebourg/crowdsec-bouncer-traefik-plugin/pkg/cache"
	"github.com/maxlerebourg/crowdsec-bouncer-traefik-plugin/pkg/configuration"
	"github.com/maxlerebourg/crowdsec-bouncer-traefik-plugin/pkg/logger"
)

// mockTransport implements http.RoundTripper for mocking HTTP requests
type mockTransport struct {
	response *http.Response
	err      error
}

func (m *mockTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	return m.response, m.err
}

// createMockResponse creates a mock HTTP response with the given status code and body
func createMockResponse(statusCode int, body string, contentType string) *http.Response {
	return &http.Response{
		StatusCode: statusCode,
		Header:     http.Header{"Content-Type": []string{contentType}},
		Body:       io.NopCloser(strings.NewReader(body)),
	}
}

func TestGetCacheKey(t *testing.T) {
	tests := []struct {
		name     string
		remoteIP string
		hostname string
		expected string
	}{
		{
			name:     "Standard case",
			remoteIP: "192.168.1.1",
			hostname: "example.com",
			expected: "192.168.1.1_example.com_captcha",
		},
		{
			name:     "With port",
			remoteIP: "127.0.0.1",
			hostname: "localhost:8080",
			expected: "127.0.0.1_localhost:8080_captcha",
		},
		{
			name:     "IPv6",
			remoteIP: "2001:db8::1",
			hostname: "example.org",
			expected: "2001:db8::1_example.org_captcha",
		},
		{
			name:     "Empty hostname",
			remoteIP: "10.0.0.1",
			hostname: "",
			expected: "10.0.0.1__captcha",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			client := &Client{}
			result := client.getCacheKey(tt.remoteIP, tt.hostname)
			if result != tt.expected {
				t.Errorf("getCacheKey(%q, %q) = %q, want %q", tt.remoteIP, tt.hostname, result, tt.expected)
			}
		})
	}
}

func TestCaptchaValidation(t *testing.T) {
	tests := []struct {
		name          string
		provider      string
		mockResponse  *http.Response
		method        string
		formData      map[string]string
		requestHost   string
		expectedValid bool
		description   string
	}{
		{
			name:          "Valid hCaptcha response with matching hostname",
			provider:      configuration.HcaptchaProvider,
			mockResponse:  createMockResponse(200, `{"success": true, "hostname": "example.com"}`, "application/json"),
			method:        "POST",
			formData:      map[string]string{"h-captcha-response": "valid-token"},
			requestHost:   "example.com",
			expectedValid: true,
			description:   "Should validate successful hCaptcha with matching hostname",
		},
		{
			name:          "Hostname mismatch should fail",
			provider:      configuration.HcaptchaProvider,
			mockResponse:  createMockResponse(200, `{"success": true, "hostname": "attacker.com"}`, "application/json"),
			method:        "POST",
			formData:      map[string]string{"h-captcha-response": "valid-token"},
			requestHost:   "example.com",
			expectedValid: false,
			description:   "Should reject when captcha hostname doesn't match request hostname",
		},
		{
			name:          "Failed captcha validation",
			provider:      configuration.HcaptchaProvider,
			mockResponse:  createMockResponse(200, `{"success": false, "hostname": "example.com"}`, "application/json"),
			method:        "POST",
			formData:      map[string]string{"h-captcha-response": "invalid-token"},
			requestHost:   "example.com",
			expectedValid: false,
			description:   "Should reject failed captcha validation",
		},
		{
			name:          "GET method should not validate",
			provider:      configuration.HcaptchaProvider,
			method:        "GET",
			requestHost:   "example.com",
			expectedValid: false,
			description:   "Should not validate captcha for GET requests",
		},
		{
			name:          "Missing captcha response",
			provider:      configuration.HcaptchaProvider,
			method:        "POST",
			formData:      map[string]string{}, // No captcha response
			requestHost:   "example.com",
			expectedValid: false,
			description:   "Should reject when no captcha response provided",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create logger and cache
			log := logger.New("DEBUG", "")
			cacheClient := &cache.Client{}
			cacheClient.New(log, false, "", "", "")

			// Create mock HTTP client
			var mockClient *http.Client
			if tt.mockResponse != nil {
				mockClient = &http.Client{
					Transport: &mockTransport{response: tt.mockResponse},
				}
			} else {
				mockClient = &http.Client{}
			}

			// Create captcha client
			client := &Client{}
			err := client.New(log, cacheClient, mockClient, tt.provider, "test-site-key", "test-secret-key", "", "", 300)
			if err != nil {
				t.Fatalf("Failed to create captcha client: %v", err)
			}

			// Create test request
			req := httptest.NewRequest(tt.method, "http://"+tt.requestHost+"/test", nil)

			// Add form data if provided
			if len(tt.formData) > 0 {
				req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
				req.ParseForm()
				for key, value := range tt.formData {
					req.Form.Set(key, value)
				}
			}

			// Test validation
			valid, err := client.Validate(req)
			if err != nil && tt.expectedValid {
				t.Errorf("Unexpected error: %v", err)
			}

			if valid != tt.expectedValid {
				t.Errorf("Validate() = %v, want %v - %s", valid, tt.expectedValid, tt.description)
			}
		})
	}
}

func TestCaptchaCheckAndSet(t *testing.T) {
	// Create logger and cache
	log := logger.New("DEBUG", "")
	cacheClient := &cache.Client{}
	cacheClient.New(log, false, "", "", "")

	// Create captcha client
	client := &Client{}
	err := client.New(log, cacheClient, &http.Client{}, configuration.HcaptchaProvider, "test-site-key", "test-secret-key", "", "", 300)
	if err != nil {
		t.Fatalf("Failed to create captcha client: %v", err)
	}

	testIP := "192.168.1.1"
	testHostname := "example.com"

	// Initially should not be checked
	if client.Check(testIP, testHostname) {
		t.Error("Expected Check to return false for uncached IP+hostname")
	}

	// Simulate successful validation by setting cache directly
	cacheKey := client.getCacheKey(testIP, testHostname)
	client.cacheClient.Set(cacheKey, cache.CaptchaDoneValue, 300)

	// Now should be checked
	if !client.Check(testIP, testHostname) {
		t.Error("Expected Check to return true for cached IP+hostname")
	}

	// Different hostname should not be checked
	if client.Check(testIP, "different.com") {
		t.Error("Expected Check to return false for different hostname")
	}

	// Different IP should not be checked
	if client.Check("10.0.0.1", testHostname) {
		t.Error("Expected Check to return false for different IP")
	}
}

// Note: ServeHTTP testing with templates is complex due to template setup requirements
// The main logic is tested through other test functions and integration tests

func TestCaptchaNew(t *testing.T) {
	log := logger.New("DEBUG", "")
	cacheClient := &cache.Client{}
	cacheClient.New(log, false, "", "", "")

	tests := []struct {
		name        string
		provider    string
		expectValid bool
	}{
		{
			name:        "hCaptcha provider",
			provider:    configuration.HcaptchaProvider,
			expectValid: true,
		},
		{
			name:        "reCAPTCHA provider",
			provider:    configuration.RecaptchaProvider,
			expectValid: true,
		},
		{
			name:        "Turnstile provider",
			provider:    configuration.TurnstileProvider,
			expectValid: true,
		},
		{
			name:        "Empty provider",
			provider:    "",
			expectValid: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			client := &Client{}
			err := client.New(log, cacheClient, &http.Client{}, tt.provider, "site-key", "secret-key", "", "", 300)

			if err != nil {
				t.Errorf("New() returned error: %v", err)
			}

			if client.Valid != tt.expectValid {
				t.Errorf("Expected Valid=%v, got Valid=%v", tt.expectValid, client.Valid)
			}

			if tt.expectValid && client.provider != tt.provider {
				t.Errorf("Expected provider=%q, got provider=%q", tt.provider, client.provider)
			}
		})
	}
}
