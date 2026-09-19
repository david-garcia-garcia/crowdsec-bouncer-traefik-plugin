package decisionscope

import (
	"net"
	"strings"

	"github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pkg/cache"
	"github.com/david-garcia-garcia/traefik-middleware-utilities/iplookup"
)

// RangeMembership is in-process ban-then-captcha CIDR membership rebuilt from range-index.
type RangeMembership struct {
	ban          *iplookup.Helper  // CIDRs whose remediation is ban
	captcha      *iplookup.Helper  // CIDRs whose remediation is captcha
	storedByCIDR map[string]string // cidr -> stored letter or letter plus origin suffix
}

// MembershipFromIndex builds RangeMembership from a cidr=remediation blob. Invalid CIDR lines are skipped.
func MembershipFromIndex(index string) *RangeMembership {
	ban := iplookup.New()
	captcha := iplookup.New()
	storedByCIDR := make(map[string]string)
	if index == "" {
		return &RangeMembership{ban: ban, captcha: captcha, storedByCIDR: storedByCIDR}
	}
	for _, line := range strings.Split(index, "\n") {
		network, remediation := parseIndexLine(line)
		if network == "" || !IsActiveRemediation(remediation) {
			continue
		}
		if cache.RemediationKind(remediation) == BannedValue {
			if err := ban.AddCIDR(network, ""); err != nil {
				continue
			}
		} else {
			if err := captcha.AddCIDR(network, ""); err != nil {
				continue
			}
		}
		storedByCIDR[network] = remediation
	}
	return &RangeMembership{ban: ban, captcha: captcha, storedByCIDR: storedByCIDR}
}

// Remediation returns the stored string of the winning CIDR (ban over captcha), or empty.
func (membership *RangeMembership) Remediation(ipAddr net.IP) string {
	if membership == nil || ipAddr == nil {
		return ""
	}
	if membership.ban != nil {
		found, prefixLen, _, err := membership.ban.Contains(ipAddr)
		if err == nil && found {
			return membership.storedMatchingPrefix(ipAddr, prefixLen, BannedValue)
		}
	}
	if membership.captcha != nil {
		found, prefixLen, _, err := membership.captcha.Contains(ipAddr)
		if err == nil && found {
			return membership.storedMatchingPrefix(ipAddr, prefixLen, CaptchaValue)
		}
	}
	return ""
}

// storedMatchingPrefix returns the stored remediation of the CIDR that matches prefixLen, else any containing CIDR of that kind.
func (membership *RangeMembership) storedMatchingPrefix(ipAddr net.IP, prefixLen int, kind string) string {
	fallback := ""
	for cidr, stored := range membership.storedByCIDR {
		if cache.RemediationKind(stored) != kind {
			continue
		}
		_, network, err := net.ParseCIDR(cidr)
		if err != nil || network == nil || !network.Contains(ipAddr) {
			continue
		}
		ones, _ := network.Mask.Size()
		if ones == prefixLen {
			return stored
		}
		if fallback == "" {
			fallback = stored
		}
	}
	if fallback != "" {
		return fallback
	}
	return kind
}
