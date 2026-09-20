package lapi

import (
	"github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pkg/configuration"
)

// sessionResidue is the create-time snapshot of session-owned knobs.
// Joiners that differ WARNs those YAML field names (never secret values).
type sessionResidue struct {
	RedisCacheEnabled            bool
	RedisCacheHost               string
	RedisCachePassword           string
	RedisCacheDatabase           string
	RedisCacheReadHosts          []string
	UpdateIntervalSeconds        int64
	MetricsUpdateIntervalSeconds int64
	UpdateMaxFailure             int64
	CrowdsecCapiScenarios        []string
}

// residueFrom copies session-owned YAML off cfg. Call after Prepare.
func residueFrom(cfg *configuration.Config) sessionResidue {
	return sessionResidue{
		RedisCacheEnabled:            cfg.RedisCacheEnabled,
		RedisCacheHost:               cfg.RedisCacheHost,
		RedisCachePassword:           cfg.RedisCachePassword,
		RedisCacheDatabase:           cfg.RedisCacheDatabase,
		RedisCacheReadHosts:          copyStrings(cfg.RedisCacheReadHosts),
		UpdateIntervalSeconds:        cfg.UpdateIntervalSeconds,
		MetricsUpdateIntervalSeconds: cfg.MetricsUpdateIntervalSeconds,
		UpdateMaxFailure:             cfg.UpdateMaxFailure,
		CrowdsecCapiScenarios:        copyStrings(cfg.CrowdsecCapiScenarios),
	}
}

// ignoredFields is the YAML names that differ from create-time residue.
// redisCachePassword is listed as a field name only.
func (r sessionResidue) ignoredFields(cfg *configuration.Config) []string {
	var ignored []string
	if r.RedisCacheEnabled != cfg.RedisCacheEnabled {
		ignored = append(ignored, "redisCacheEnabled")
	}
	if r.RedisCacheHost != cfg.RedisCacheHost {
		ignored = append(ignored, "redisCacheHost")
	}
	if r.RedisCachePassword != cfg.RedisCachePassword {
		ignored = append(ignored, "redisCachePassword")
	}
	if r.RedisCacheDatabase != cfg.RedisCacheDatabase {
		ignored = append(ignored, "redisCacheDatabase")
	}
	if !stringSlicesEqual(r.RedisCacheReadHosts, cfg.RedisCacheReadHosts) {
		ignored = append(ignored, "redisCacheReadHosts")
	}
	if r.UpdateIntervalSeconds != cfg.UpdateIntervalSeconds {
		ignored = append(ignored, "updateIntervalSeconds")
	}
	if r.MetricsUpdateIntervalSeconds != cfg.MetricsUpdateIntervalSeconds {
		ignored = append(ignored, "metricsUpdateIntervalSeconds")
	}
	if r.UpdateMaxFailure != cfg.UpdateMaxFailure {
		ignored = append(ignored, "updateMaxFailure")
	}
	if !stringSlicesEqual(r.CrowdsecCapiScenarios, cfg.CrowdsecCapiScenarios) {
		ignored = append(ignored, "crowdsecCapiScenarios")
	}
	return ignored
}

// copyStrings is a new backing array so create-time residue does not alias cfg.
func copyStrings(in []string) []string {
	if in == nil {
		return nil
	}
	out := make([]string, len(in))
	copy(out, in)
	return out
}

// stringSlicesEqual is element-wise equality (Yaegi: do not import slices).
func stringSlicesEqual(residue, joiner []string) bool {
	if len(residue) != len(joiner) {
		return false
	}
	for i := range residue {
		if residue[i] != joiner[i] {
			return false
		}
	}
	return true
}
