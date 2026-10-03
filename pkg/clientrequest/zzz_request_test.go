package clientrequest

import (
	"crypto/tls"
	"io"
	"net"
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
			got := New(httpReq, "192.0.2.1", nil)
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
	_ = New(httpReq, "192.0.2.1", nil)
	if httpReq.URL.Scheme != "" {
		t.Fatalf("URL.Scheme=%q want empty", httpReq.URL.Scheme)
	}
}

func TestNew_addressIsSnapshot(t *testing.T) {
	httpReq := httptest.NewRequest(http.MethodGet, "/", nil)
	raw := net.ParseIP("2001:0db8:0000:0000:0000:0000:0000:0001")
	got := New(httpReq, "2001:0db8:0000:0000:0000:0000:0000:0001", raw)
	raw[0] = 0
	if got.RemoteIP() != "2001:db8::1" {
		t.Fatalf("remoteIP=%q", got.RemoteIP())
	}
	if got.IPType() != "ipv6" {
		t.Fatalf("ipType=%q", got.IPType())
	}
	if !got.IPAddr().Equal(net.ParseIP("2001:db8::1")) {
		t.Fatalf("ipAddr=%v", got.IPAddr())
	}
	got.IPAddr()[0] = 9
	if !got.IPAddr().Equal(net.ParseIP("2001:db8::1")) {
		t.Fatalf("IPAddr getter returned the stored slice")
	}

	unparsed := New(httpReq, "not-an-ip", nil)
	if unparsed.RemoteIP() != "not-an-ip" || unparsed.IPAddr() != nil || unparsed.IPType() != "" {
		t.Fatalf("remoteIP=%q ipAddr=%v ipType=%q", unparsed.RemoteIP(), unparsed.IPAddr(), unparsed.IPType())
	}
}

func TestAbsoluteURL_originFormUsesRequestHost(t *testing.T) {
	httpReq := httptest.NewRequest(http.MethodGet, "/foo?q=1", nil)
	httpReq.Host = "app.example"
	httpReq.URL.Scheme = ""
	httpReq.URL.Host = ""
	httpReq.Header.Set("X-Forwarded-Proto", "https")
	got := New(httpReq, "192.0.2.1", nil).AbsoluteURL()
	if got != "https://app.example/foo?q=1" {
		t.Fatalf("AbsoluteURL=%q", got)
	}
}

func TestAbsoluteURL_frozenAtNew(t *testing.T) {
	httpReq := httptest.NewRequest(http.MethodGet, "/foo?q=1", nil)
	httpReq.Host = "app.example"
	httpReq.URL.Scheme = ""
	httpReq.URL.Host = ""
	httpReq.Header.Set("X-Forwarded-Proto", "https")
	req := New(httpReq, "192.0.2.1", nil)
	httpReq.Host = "other.example"
	httpReq.URL.Path = "/changed"
	httpReq.URL.RawQuery = "q=2"
	if got := req.AbsoluteURL(); got != "https://app.example/foo?q=1" {
		t.Fatalf("AbsoluteURL=%q", got)
	}
}

func TestAbsoluteURL_URLHostWins(t *testing.T) {
	httpReq := httptest.NewRequest(http.MethodGet, "http://url.example/path", nil)
	httpReq.Host = "req.example"
	if got := New(httpReq, "192.0.2.1", nil).AbsoluteURL(); got != "http://url.example/path" {
		t.Fatalf("AbsoluteURL=%q", got)
	}
}

func TestEstimatedSize_namedFields(t *testing.T) {
	httpReq := originFormRequest()
	httpReq.Header.Set("X-A", "b")
	httpReq.ContentLength = 10
	got := New(httpReq, "192.0.2.1", nil).EstimatedSize()
	want := int64(len("/a") + len("h") + len("X-A") + len("b") + 10)
	if got != want {
		t.Fatalf("EstimatedSize=%d want %d", got, want)
	}
}

func TestEstimatedSize_headerNameOncePerKey(t *testing.T) {
	httpReq := originFormRequest()
	httpReq.Header.Add("X-A", "b")
	httpReq.Header.Add("X-A", "c")
	httpReq.ContentLength = 0
	got := New(httpReq, "192.0.2.1", nil).EstimatedSize()
	want := int64(len("/a") + len("h") + len("X-A") + len("b") + len("c"))
	if got != want {
		t.Fatalf("EstimatedSize=%d want %d", got, want)
	}
}

func TestEstimatedSize_contentLengthCap(t *testing.T) {
	httpReq := originFormRequest()
	httpReq.ContentLength = maxContentLengthContribution + 1
	got := New(httpReq, "192.0.2.1", nil).EstimatedSize()
	want := int64(len("/a")+len("h")) + maxContentLengthContribution
	if got != want {
		t.Fatalf("EstimatedSize=%d want %d", got, want)
	}
}

func TestEstimatedSize_unknownBodyLengthAddsNothing(t *testing.T) {
	spy := &readSpy{}
	httpReq := originFormRequest()
	httpReq.Body = spy
	httpReq.ContentLength = -1
	got := New(httpReq, "192.0.2.1", nil).EstimatedSize()
	want := int64(len("/a") + len("h"))
	if got != want {
		t.Fatalf("EstimatedSize=%d want %d", got, want)
	}
	if spy.read {
		t.Fatal("EstimatedSize must not read Body")
	}
}

// originFormRequest is RequestURI /a and Host h with an empty Header map (Traefik origin-form).
func originFormRequest() *http.Request {
	httpReq := httptest.NewRequest(http.MethodGet, "/a", nil)
	httpReq.Host = "h"
	httpReq.Header = make(http.Header)
	return httpReq
}

func TestEstimatedSize_nilEmbed(t *testing.T) {
	got := Request{}.EstimatedSize()
	if got != 0 {
		t.Fatalf("EstimatedSize=%d want 0", got)
	}
}

// readSpy records whether Read was called. EstimatedSize must not touch Body.
type readSpy struct {
	read bool
}

func (s *readSpy) Read([]byte) (int, error) {
	s.read = true
	return 0, io.EOF
}

func (s *readSpy) Close() error { return nil }

// optionalProto is a set X-Forwarded-Proto value; nil on the case means the header is absent.
func optionalProto(value string) *string {
	return &value
}
