package modsecurity

import (
	"context"
	"crypto/tls"
	"net"
	"net/http"
	"time"
)

// newHTTPClient builds the sidecar HTTP client. CheckRedirect keeps a 3xx as a copied block.
func newHTTPClient(timeoutSeconds int64) *http.Client {
	timeout := 10 * time.Second
	if timeoutSeconds > 0 {
		timeout = time.Duration(timeoutSeconds) * time.Second
	}
	dialer := &net.Dialer{
		Timeout:   30 * time.Second,
		KeepAlive: 30 * time.Second,
	}
	transport := &http.Transport{
		MaxIdleConns:          100,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
		MaxConnsPerHost:       100,
		MaxIdleConnsPerHost:   10,
		TLSClientConfig: &tls.Config{
			MinVersion: tls.VersionTLS12,
		},
		ForceAttemptHTTP2: true,
		// Closure, not dialer.DialContext: Yaegi v0.16 types the method value with a receiver.
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			return dialer.DialContext(ctx, network, addr)
		},
	}
	return &http.Client{
		Timeout:   timeout,
		Transport: transport,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
}
