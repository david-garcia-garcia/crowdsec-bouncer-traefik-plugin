package clientrequest

import (
	"crypto/tls"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestNew_schemeMatrix(t *testing.T) {
	tlsState := &tls.ConnectionState{}
	cases := []struct {
		name   string
		proto  *string // nil means header absent
		tlsOn  bool
		urlSch string
		want   string
	}{
		{name: "forwarded https", proto: optionalProto("https"), want: schemeHTTPS},
		{name: "forwarded HTTPS", proto: optionalProto("HTTPS"), want: schemeHTTPS},
		{name: "forwarded https trimmed", proto: optionalProto(" https "), want: schemeHTTPS},
		{name: "forwarded http", proto: optionalProto("http"), want: schemeHTTP},
		{name: "forwarded HTTP", proto: optionalProto("HTTP"), want: schemeHTTP},
		{name: "forwarded http trimmed", proto: optionalProto(" http "), want: schemeHTTP},
		{name: "proto http plus TLS", proto: optionalProto("http"), tlsOn: true, want: schemeHTTP},
		{name: "TLS fallback wss", proto: optionalProto("wss"), tlsOn: true, want: schemeHTTPS},
		{name: "TLS fallback empty", proto: optionalProto(""), tlsOn: true, want: schemeHTTPS},
		{name: "TLS fallback absent", tlsOn: true, want: schemeHTTPS},
		{name: "TLS fallback comma list", proto: optionalProto("https,http"), tlsOn: true, want: schemeHTTPS},
		{name: "HTTP fallback wss", proto: optionalProto("wss"), want: schemeHTTP},
		{name: "HTTP fallback empty", proto: optionalProto(""), want: schemeHTTP},
		{name: "HTTP fallback absent", want: schemeHTTP},
		{name: "HTTP fallback comma list", proto: optionalProto("https,http"), want: schemeHTTP},
		{name: "URL.Scheme ignored", urlSch: schemeHTTPS, want: schemeHTTP},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			httpReq := httptest.NewRequest(http.MethodGet, "/", nil)
			if testCase.proto != nil {
				httpReq.Header.Set("X-Forwarded-Proto", *testCase.proto)
			}
			if testCase.tlsOn {
				httpReq.TLS = tlsState
			}
			if testCase.urlSch != "" {
				httpReq.URL.Scheme = testCase.urlSch
			}
			got := New(httpReq, "192.0.2.1", nil, "")
			if got.Scheme() != testCase.want {
				t.Fatalf("scheme=%q want %q", got.Scheme(), testCase.want)
			}
		})
	}
}

func TestNew_doesNotWriteURLScheme(t *testing.T) {
	httpReq := httptest.NewRequest(http.MethodGet, "/", nil)
	httpReq.URL.Scheme = ""
	httpReq.Header.Set("X-Forwarded-Proto", "https")
	_ = New(httpReq, "192.0.2.1", nil, "")
	if httpReq.URL.Scheme != "" {
		t.Fatalf("URL.Scheme=%q want empty", httpReq.URL.Scheme)
	}
}

func TestAbsoluteURL_originFormUsesRequestHost(t *testing.T) {
	httpReq := httptest.NewRequest(http.MethodGet, "/foo?q=1", nil)
	httpReq.Host = "app.example"
	httpReq.URL.Scheme = ""
	httpReq.URL.Host = ""
	httpReq.Header.Set("X-Forwarded-Proto", "https")
	got := New(httpReq, "192.0.2.1", nil, "").AbsoluteURL()
	if got != "https://app.example/foo?q=1" {
		t.Fatalf("AbsoluteURL=%q", got)
	}
}

func TestAbsoluteURL_URLHostWins(t *testing.T) {
	httpReq := httptest.NewRequest(http.MethodGet, "http://url.example/path", nil)
	httpReq.Host = "req.example"
	if got := New(httpReq, "192.0.2.1", nil, "").AbsoluteURL(); got != "http://url.example/path" {
		t.Fatalf("AbsoluteURL=%q", got)
	}
}

// optionalProto is a set X-Forwarded-Proto value; nil on the case means the header is absent.
func optionalProto(value string) *string {
	return &value
}
