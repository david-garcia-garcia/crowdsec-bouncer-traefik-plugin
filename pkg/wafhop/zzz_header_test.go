package wafhop

import (
	"net/http"
	"testing"
)

// TestIsHopByHopHeader checks the RFC 9110 section 7.6.1 set and that end-to-end headers pass.
func TestIsHopByHopHeader(t *testing.T) {
	tests := []struct {
		name string
		want bool
	}{
		{name: "Connection", want: true},
		{name: "keep-alive", want: true},
		{name: "Proxy-Authenticate", want: true},
		{name: "Proxy-Authorization", want: true},
		{name: "Proxy-Connection", want: true},
		{name: "TE", want: true},
		{name: "Trailer", want: true},
		{name: "Trailers", want: true},
		{name: "Transfer-Encoding", want: true},
		{name: "Upgrade", want: true},
		{name: "Content-Type", want: false},
		{name: "Cookie", want: false},
		{name: "Content-Length", want: false},
		{name: "Proxy-Payload", want: false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := IsHopByHopHeader(tt.name); got != tt.want {
				t.Errorf("IsHopByHopHeader(%q) = %v, want %v", tt.name, got, tt.want)
			}
		})
	}
}

func TestCopyEndToEndHeaders(t *testing.T) {
	src := http.Header{}
	src.Set("Connection", "Upgrade, Cookie")
	src.Set("Upgrade", "websocket")
	src.Set("Cookie", "session=1")
	src.Set("Content-Length", "10")
	src.Set("Server", "sidecar")
	src.Add("Accept", "a")
	src.Add("Accept", "b")
	dst := http.Header{}
	CopyEndToEndHeaders(dst, src, "content-length")
	for _, name := range []string{"Connection", "Upgrade", "Content-Length"} {
		if dst.Get(name) != "" {
			t.Errorf("%s must not be copied", name)
		}
	}
	if got := dst.Values("Accept"); len(got) != 2 || got[0] != "a" || got[1] != "b" {
		t.Fatalf("Accept=%v", got)
	}
	if dst.Get("Cookie") != "session=1" {
		t.Fatal("a name the client lists in Connection must still reach the WAF")
	}
	if dst.Get("Server") != "sidecar" {
		t.Fatal("Server is end-to-end unless omitted")
	}
	dst["Accept"][0] = "changed"
	if src.Values("Accept")[0] != "a" {
		t.Fatal("dst must not alias src values")
	}
}
