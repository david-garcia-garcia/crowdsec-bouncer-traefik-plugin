package decisionstore

import (
	"net"

	"github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pkg/decisionscope"
	"github.com/david-garcia-garcia/traefik-middleware-utilities/iplookup"
)

// RangeMembership is in-process ban-then-captcha CIDR membership rebuilt from range-index.
type RangeMembership struct {
	ban     *iplookup.Helper // CIDRs whose remediation is ban
	captcha *iplookup.Helper // CIDRs whose remediation is captcha
}

// MembershipFromIndex builds RangeMembership from a cidr=kind blob. Origin is the following line.
func MembershipFromIndex(index string) *RangeMembership {
	ban := iplookup.New()
	captcha := iplookup.New()
	if index == "" {
		return &RangeMembership{ban: ban, captcha: captcha}
	}
	for _, rec := range parseRangeRecords(index) {
		if rec.cidr == "" || !decisionscope.IsActiveRemediation(rec.kind) {
			continue
		}
		helper := captcha
		if decisionscope.RemediationKind(rec.kind) == decisionscope.BannedValue {
			helper = ban
		}
		if err := helper.AddCIDR(rec.cidr, KindOriginString(rec.kind, rec.origin)); err != nil {
			continue
		}
	}
	return &RangeMembership{ban: ban, captcha: captcha}
}

// Remediation returns the stored string of the winning CIDR (ban over captcha), or empty.
func (membership *RangeMembership) Remediation(ipAddr net.IP) string {
	if membership == nil || ipAddr == nil {
		return ""
	}
	if membership.ban != nil {
		found, _, stored, err := membership.ban.Contains(ipAddr)
		if err == nil && found {
			return stored
		}
	}
	if membership.captcha != nil {
		found, _, stored, err := membership.captcha.Contains(ipAddr)
		if err == nil && found {
			return stored
		}
	}
	return ""
}
