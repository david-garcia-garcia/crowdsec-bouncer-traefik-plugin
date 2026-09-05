// Package ip implements utility routines to manipulate IP and CIDR.
// It allows searching an IP on a list, and find if an IP is part of a list of CIDR.
package ip

import (
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"strings"

	"github.com/maxlerebourg/crowdsec-bouncer-traefik-plugin/pkg/iplookup"
)

// Checker allows to check that addresses are in a trusted IPs.
type Checker struct {
	trustedCIDRs *iplookup.Helper
}

// NewChecker builds a new Checker given a list of CIDR-Strings to trusted IPs.
func NewChecker(log *slog.Logger, trustedIPs []string) (*Checker, error) {
	trustedCIDRs := iplookup.NewEmptyHelper()

	for _, ipMaskRaw := range trustedIPs {
		ipMask := strings.TrimSpace(ipMaskRaw)
		// Bare addresses enter the tree as a host prefix.
		if ipAddr := net.ParseIP(ipMask); ipAddr != nil {
			if err := trustedCIDRs.AddCIDR(hostCIDR(ipAddr)); err != nil {
				return nil, fmt.Errorf("parsing CIDR trusted IPs %s: %w", ipMask, err)
			}
			log.Debug(fmt.Sprintf("IP %v is trusted", ipAddr))
			continue
		}

		// CIDR strings are inserted as given (not rewritten to a host prefix).
		if err := trustedCIDRs.AddCIDR(ipMask); err != nil {
			return nil, fmt.Errorf("parsing CIDR trusted IPs %s: %w", ipMask, err)
		}
		log.Debug(fmt.Sprintf("IP network %v is trusted", ipMask))
	}

	return &Checker{trustedCIDRs: trustedCIDRs}, nil
}

// Contains checks if provided address is in the trusted IPs.
func (ip *Checker) Contains(addr string) (bool, error) {
	if len(addr) == 0 {
		return false, errors.New("Contains:noAddress")
	}

	ipAddr, err := parseIP(addr)
	if err != nil {
		return false, fmt.Errorf("Contains:parseAddress addr:%s %w", addr, err)
	}

	return ip.ContainsIP(ipAddr), nil
}

// ContainsIP checks if provided address is in the trusted IPs.
func (ip *Checker) ContainsIP(addr net.IP) bool {
	// An uninitialized Checker trusts nothing.
	if ip.trustedCIDRs == nil {
		return false
	}
	// Boolean any-match: ignore longest-prefix length.
	found, _, err := ip.trustedCIDRs.IsContained(addr)
	// Nil IP is an error from the helper and is not trusted.
	if err != nil {
		return false
	}
	return found
}

// hostCIDR formats a bare address as a host prefix for the lookup helper.
func hostCIDR(addr net.IP) string {
	if v4 := addr.To4(); v4 != nil {
		return v4.String() + "/32"
	}
	return addr.String() + "/128"
}

// parseIP parses a dotted or compact address string into net.IP.
func parseIP(addr string) (net.IP, error) {
	userIP := net.ParseIP(addr)
	if userIP == nil {
		return nil, fmt.Errorf("parseIP:parseAddress %s", addr)
	}

	return userIP, nil
}

// PoolStrategy is a strategy based on an IP Checker.
// It allows to check whether addresses are in a given pool of IPs.
type PoolStrategy struct {
	Checker *Checker
}

// GetIP checks the list of Forwarded IPs (most recent first) against the
// Checker pool of IPs. It returns the first IP that is not in the pool, or the
// empty string otherwise.
func (s *PoolStrategy) getIP(req *http.Request, customHeader string) string {
	if s.Checker == nil {
		return ""
	}

	xff := req.Header.Get(customHeader)

	xffs := strings.Split(xff, ",")

	// Walk most-recent hop first (right to left).
	for i := len(xffs) - 1; i >= 0; i-- {
		xffTrimmed := strings.TrimSpace(xffs[i])
		if len(xffTrimmed) == 0 {
			continue
		}
		if contain, _ := s.Checker.Contains(xffTrimmed); !contain {
			return xffTrimmed
		}
	}

	return ""
}

// GetRemoteIP returns the client address for a request.
// It walks the custom forwarded header most-recent-first against the trusted-hop pool,
// then falls back to the host of req.RemoteAddr.
func GetRemoteIP(req *http.Request, strategy *PoolStrategy, customHeader string) (string, error) {
	remoteIP := strategy.getIP(req, customHeader)
	if len(remoteIP) != 0 {
		return remoteIP, nil
	}
	// Header walk found no untrusted hop; use the socket peer.
	remoteIP, _, err := net.SplitHostPort(req.RemoteAddr)
	if err != nil {
		return "", fmt.Errorf("GetRemoteIP:extractIP: %w", err)
	}
	return remoteIP, nil
}
