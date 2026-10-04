// Package clientrequest holds one inbound HTTP request together with the
// client address GetRemoteIP already chose and the constructor-owned scheme token.
package clientrequest

import (
	"net"
	"net/http"
	"net/url"
	"strings"

	"github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pkg/ip"
)

const (
	schemeHTTP  = "http"
	schemeHTTPS = "https"
	// maxContentLengthContribution caps the ContentLength part of EstimatedSize at 50 MiB.
	maxContentLengthContribution = 50 * 1024 * 1024
)

// Request is one inbound request plus the GetRemoteIP address plus the scheme token.
// Callers keep the name req. Scopes, remediation origin, and captcha state stay off this type.
// Address, scheme, and absolute URL are fixed by New.
type Request struct {
	*http.Request
	ipAddr       net.IP // copy of the parsed address; nil when unparseable
	ipType       string // ip.FamilyOfIP(ipAddr): ipv4, ipv6, or empty
	ipAddrString string // ipAddr.String() when parsed; otherwise the raw extract for fail logs
	scheme       string // constructor token: http or https
	absoluteURL  string // constructor snapshot of the client-facing URL
}

// New builds Request from the live request and the address GetRemoteIP already chose.
// When ipAddr is non-nil, IPAddrString is stored as ipAddr.String(). The family is ip.FamilyOfIP(ipAddr).
// Scheme and AbsoluteURL are fixed here. Later edits to Host, URL, or the passed net.IP do not change them.
// New does not write onto the live *http.Request.
func New(httpReq *http.Request, remoteIP string, ipAddr net.IP) Request {
	if ipAddr != nil {
		ipAddr = append(net.IP(nil), ipAddr...)
		remoteIP = ipAddr.String()
	}
	scheme := schemeOf(httpReq)
	return Request{
		Request:      httpReq,
		ipAddr:       ipAddr,
		ipType:       ip.FamilyOfIP(ipAddr),
		ipAddrString: remoteIP,
		scheme:       scheme,
		absoluteURL:  absoluteURL(httpReq, scheme),
	}
}

// IPAddr is the parsed client address captured by New. Nil when that address was unparseable.
// The returned slice is a copy.
func (r Request) IPAddr() net.IP {
	if r.ipAddr == nil {
		return nil
	}
	return append(net.IP(nil), r.ipAddr...)
}

// IPType is the address family captured by New: ip.FamilyOfIP of the parsed address (ipv4, ipv6, or empty).
func (r Request) IPType() string {
	return r.ipType
}

// IPAddrString is the client address string captured by New, the same address as IPAddr.
// A parsed address is ipAddr.String(); an unparsed extract stays as GetRemoteIP returned it.
func (r Request) IPAddrString() string {
	return r.ipAddrString
}

// Scheme is the constructor-owned client-facing scheme token (http or https).
func (r Request) Scheme() string {
	return r.scheme
}

// AbsoluteURL is the client-facing URL captured by New: constructor scheme, URL.Host else Request.Host, path and query preserved.
func (r Request) AbsoluteURL() string {
	return r.absoluteURL
}

// EstimatedSize is the inbound request size for dropped / byte usage-metrics.
// It sums RequestURI, Host, each Header map key once plus each header value, and capped ContentLength.
// It does not read Body and does not reconstruct a wire image.
func (r Request) EstimatedSize() int64 {
	if r.Request == nil {
		return 0
	}
	// Sum the live request-target and the server-lifted Host field.
	n := int64(len(r.RequestURI) + len(r.Host))
	// Add each Header map key once and each header value. Host is not reconstructed from Header.
	for name, values := range r.Header {
		n += int64(len(name))
		for _, value := range values {
			n += int64(len(value))
		}
	}
	// Count declared ContentLength when known; cap that part at 50 MiB. Do not read Body.
	if r.ContentLength >= 0 {
		contentLength := r.ContentLength
		if contentLength > maxContentLengthContribution {
			contentLength = maxContentLengthContribution
		}
		n += contentLength
	}
	return n
}

// absoluteURL snapshots the client-facing URL. It does not read URL.Scheme.
func absoluteURL(httpReq *http.Request, scheme string) string {
	if httpReq == nil || httpReq.URL == nil {
		return scheme + "://"
	}
	host := httpReq.URL.Host
	if host == "" {
		host = httpReq.Host
	}
	abs := url.URL{
		Scheme:   scheme,
		Host:     host,
		Path:     httpReq.URL.Path,
		RawPath:  httpReq.URL.RawPath,
		RawQuery: httpReq.URL.RawQuery,
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
