package configuration

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"math/big"
	"testing"
	"time"

	logger "github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pkg/logger"
)

// testClientCertPEM is a throwaway cert and key GetTLSConfigCrowdsec can load.
func testClientCertPEM(t *testing.T) (certPEM, keyPEM string) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	certPEM = string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
	keyPEM = string(pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}))
	return certPEM, keyPEM
}

func TestGetTLSConfigCrowdsec_ClientCertificate(t *testing.T) {
	log := logger.New("ERROR", "")
	certPEM, keyPEM := testClientCertPEM(t)
	cfg := getMinimalConfig()
	cfg.LapiScheme = HTTPS
	cfg.LapiTLSClientCertificate = certPEM
	cfg.LapiTLSClientKey = keyPEM

	got, err := GetTLSConfigCrowdsec(cfg, log, false)
	if err != nil {
		t.Fatal(err)
	}
	if len(got.Certificates) != 1 {
		t.Fatalf("certificates = %d, want 1", len(got.Certificates))
	}

	cfg.LapiTLSClientKey = "not-a-key"
	if _, err := GetTLSConfigCrowdsec(cfg, log, false); err == nil {
		t.Fatal("mismatched client key must fail")
	}
}
