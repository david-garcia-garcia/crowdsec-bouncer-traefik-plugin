// Package clientrequest holds one inbound HTTP request together with the
// client address GetRemoteIP already chose and the constructor-owned scheme token.
package clientrequest

import (
	"net"
	"net/http"
	"net/url"
	"strings"
)

const (
	schemeHTTP  = "http"
	schemeHTTPS = "https"
)

// Request is one inbound request plus the GetRemoteIP address plus the scheme token.
// Callers keep the name req. Scopes, remediation origin, and captcha state stay off this type.
type Request struct {
	*http.Request
	IPAddr   net.IP // same address as net.IP; nil when unparseable
	IPType   string // FamilyOfIP(IPAddr): ipv4, ipv6, or empty
	RemoteIP string // after parse: IPAddr.String(); before: raw extract for fail logs
	scheme   string // constructor token: http or https
}

// New builds Request from the live request and the address GetRemoteIP already chose.
// Callers MUST NOT assign Scheme afterwards. New does not write onto the live *http.Request.
func New(httpReq *http.Request, remoteIP string, ipAddr net.IP, ipType string) Request {
	return Request{
		Request:  httpReq,
		IPAddr:   ipAddr,
		IPType:   ipType,
		RemoteIP: remoteIP,
		scheme:   schemeOf(httpReq),
	}
}

// Scheme is the constructor-owned client-facing scheme token (http or https).
func (r Request) Scheme() string {
	return r.scheme
}

// AbsoluteURL is the client-facing URL: constructor scheme, URL.Host else Request.Host, path and query preserved.
func (r Request) AbsoluteURL() string {
	if r.Request == nil || r.URL == nil {
		return r.scheme + "://"
	}
	host := r.URL.Host
	if host == "" {
		host = r.Host
	}
	abs := url.URL{
		Scheme:   r.scheme,
		Host:     host,
		Path:     r.URL.Path,
		RawPath:  r.URL.RawPath,
		RawQuery: r.URL.RawQuery,
	}
	return abs.String()
}

// schemeOf derives the scheme token from proto-then-TLS. It does not re-check hop trust.
func schemeOf(httpReq *http.Request) string {
	proto := strings.TrimSpace(httpReq.Header.Get("X-Forwarded-Proto"))
	if strings.EqualFold(proto, schemeHTTPS) {
		return schemeHTTPS
	}
	if strings.EqualFold(proto, schemeHTTP) {
		return schemeHTTP
	}
	if httpReq.TLS != nil {
		return schemeHTTPS
	}
	return schemeHTTP
}
