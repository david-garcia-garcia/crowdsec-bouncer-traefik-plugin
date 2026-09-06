package appsec

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"log/slog"

	"github.com/maxlerebourg/crowdsec-bouncer-traefik-plugin/pkg/configuration"
)

// getTLSConfig builds a tls.Config from Config fields named prefix+TLS* and scheme.
func getTLSConfig(config *configuration.Config, log *slog.Logger, prefix, scheme string, insecureVerify bool) (*tls.Config, error) {
	tlsConfig := new(tls.Config)
	if scheme != configuration.HTTPS {
		log.Debug("getTLSConfig:" + prefix + "Scheme https:no")
		return tlsConfig, nil
	}
	// RootCAs is intentionally left nil unless a custom CA is provided:
	// crypto/tls then falls back to x509.SystemCertPool(), which is what we
	// want when the listener is exposed behind a reverse proxy with a publicly
	// trusted certificate (e.g. Let's Encrypt).
	//nolint:nestif
	if insecureVerify {
		tlsConfig.InsecureSkipVerify = true
		log.Debug("getTLSConfig:" + prefix + "TLSInsecureVerify tlsInsecure:true")
	} else {
		certAuthority, err := configuration.GetVariable(config, prefix+"TLSCertificateAuthority")
		if err != nil {
			return nil, err
		}
		if len(certAuthority) > 0 {
			tlsConfig.RootCAs = x509.NewCertPool()
			if !tlsConfig.RootCAs.AppendCertsFromPEM([]byte(certAuthority)) {
				return nil, errors.New("getTLSConfig:" + prefix + " cannot load CA and verify cert is enabled")
			}
			log.Debug("getTLSConfig:" + prefix + "TLSCertificateAuthority CA added successfully")
		} else {
			log.Debug("getTLSConfig:" + prefix + " no CA provided, using system trust store")
		}
	}
	certBouncer, err := configuration.GetVariable(config, prefix+"TLSCertificateBouncer")
	if err != nil {
		return nil, err
	}
	certBouncerKey, err := configuration.GetVariable(config, prefix+"TLSCertificateBouncerKey")
	if err != nil {
		return nil, err
	}
	if certBouncer == "" || certBouncerKey == "" {
		return tlsConfig, nil
	}
	clientCert, err := tls.X509KeyPair([]byte(certBouncer), []byte(certBouncerKey))
	if err != nil {
		return nil, fmt.Errorf("getTLSClientConfigCrowdsec impossible to generate ClientCert %w", err)
	}
	tlsConfig.Certificates = append(tlsConfig.Certificates, clientCert)

	return tlsConfig, nil
}

// getTLSConfigAppsec builds AppSec tls.Config from Config TLS fields.
func getTLSConfigAppsec(config *configuration.Config, log *slog.Logger) (*tls.Config, error) {
	return getTLSConfig(config, log, "CrowdsecAppsec", config.CrowdsecAppsecScheme, config.CrowdsecAppsecTLSInsecureVerify)
}
