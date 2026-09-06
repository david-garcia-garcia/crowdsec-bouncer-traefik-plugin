package lapi

import (
	"testing"

	"github.com/maxlerebourg/crowdsec-bouncer-traefik-plugin/pkg/configuration"
	logger "github.com/maxlerebourg/crowdsec-bouncer-traefik-plugin/pkg/logger"
)

// validPEM is a minimal self-signed certificate accepted by AppendCertsFromPEM,
// shared by the TLS tests below.
const validPEM = `-----BEGIN CERTIFICATE-----
MIIBhTCCASugAwIBAgIQIRi6zePL6mKjOipn+dNuaTAKBggqhkjOPQQDAjASMRAw
DgYDVQQKEwdBY21lIENvMB4XDTE3MTAyMDE5NDMwNloXDTE4MTAyMDE5NDMwNlow
EjEQMA4GA1UEChMHQWNtZSBDbzBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABD0d
7VNhbWvZLWPuj/RtHFjvtJBEwOkhbN/BnnE8rnZR8+sbwnc/KhCk3FhnpHZnQz7B
5aETbbIgmuvewdjvSBSjYzBhMA4GA1UdDwEB/wQEAwICpDATBgNVHSUEDDAKBggr
BgEFBQcDATAPBgNVHRMBAf8EBTADAQH/MCkGA1UdEQQiMCCCDmxvY2FsaG9zdDo1
NDUzgg4xMjcuMC4wLjE6NTQ1MzAKBggqhkjOPQQDAgNIADBFAiEA2zpJEPQyz6/l
Wf86aX6PepsntZv2GYlA5UpabfT2EZICICpJ5h/iI+i341gBmLiAFQOyTDT+/wQc
6MF9+Yw1Yy0t
-----END CERTIFICATE-----`

func newTestMinimalConfig() *configuration.Config {
	cfg := configuration.New()
	cfg.CrowdsecLapiKey = "test"
	return cfg
}

func Test_getTLSConfigCrowdsec(t *testing.T) {
	log := logger.New("INFO", "")

	httpCfg := newTestMinimalConfig()
	httpCfg.CrowdsecLapiScheme = configuration.HTTP

	httpsSystemCA := newTestMinimalConfig()
	httpsSystemCA.CrowdsecLapiScheme = configuration.HTTPS

	httpsCustomCA := newTestMinimalConfig()
	httpsCustomCA.CrowdsecLapiScheme = configuration.HTTPS
	httpsCustomCA.CrowdsecLapiTLSCertificateAuthority = validPEM

	httpsInsecure := newTestMinimalConfig()
	httpsInsecure.CrowdsecLapiScheme = configuration.HTTPS
	httpsInsecure.CrowdsecLapiTLSInsecureVerify = true

	httpsBadCA := newTestMinimalConfig()
	httpsBadCA.CrowdsecLapiScheme = configuration.HTTPS
	httpsBadCA.CrowdsecLapiTLSCertificateAuthority = "not a pem"

	tests := []struct {
		name             string
		config           *configuration.Config
		wantErr          bool
		wantRootCAsNil   bool
		wantInsecureSkip bool
	}{
		{name: "HTTP scheme returns empty tls.Config", config: httpCfg, wantRootCAsNil: true},
		{name: "HTTPS without CA leaves RootCAs nil (system trust store)", config: httpsSystemCA, wantRootCAsNil: true},
		{name: "HTTPS with custom CA populates RootCAs", config: httpsCustomCA, wantRootCAsNil: false},
		{name: "HTTPS with insecure verify sets InsecureSkipVerify", config: httpsInsecure, wantRootCAsNil: true, wantInsecureSkip: true},
		{name: "HTTPS with garbage CA is rejected", config: httpsBadCA, wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := getTLSConfigCrowdsec(tt.config, log, false)
			if (err != nil) != tt.wantErr {
				t.Errorf("getTLSConfigCrowdsec() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if tt.wantErr {
				return
			}
			if (got.RootCAs == nil) != tt.wantRootCAsNil {
				t.Errorf("getTLSConfigCrowdsec() RootCAs nil = %v, want nil = %v", got.RootCAs == nil, tt.wantRootCAsNil)
			}
			if got.InsecureSkipVerify != tt.wantInsecureSkip {
				t.Errorf("getTLSConfigCrowdsec() InsecureSkipVerify = %v, want %v", got.InsecureSkipVerify, tt.wantInsecureSkip)
			}
		})
	}
}
