package captcha

import (
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func Test_validateGateValue_bindIP(t *testing.T) {
	secret := []byte("test-secret")
	now := time.Unix(1_700_000_000, 0)
	value := mintGateValue(secret, true, "203.0.113.5", now)
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.AddCookie(&http.Cookie{Name: gateCookieName, Value: value})
	if !validateGateValue(secret, true, "203.0.113.5", value, now.Add(time.Minute), 3600) {
		t.Fatal("expected valid gate within grace")
	}
	if validateGateValue(secret, true, "203.0.113.6", value, now.Add(time.Minute), 3600) {
		t.Fatal("expected IP mismatch to fail")
	}
}

func Test_validateGateValue_cookieOnly(t *testing.T) {
	secret := []byte("cookie-only")
	now := time.Unix(1_700_000_000, 0)
	value := mintGateValue(secret, false, "203.0.113.5", now)
	if !validateGateValue(secret, false, "198.51.100.1", value, now.Add(time.Minute), 3600) {
		t.Fatal("cookie-only should ignore client IP")
	}
}

func Test_validateGateValue_expired(t *testing.T) {
	secret := []byte("exp")
	issued := time.Unix(1_700_000_000, 0)
	value := mintGateValue(secret, true, "10.0.0.1", issued)
	afterGrace := issued.Add(2 * time.Hour)
	if validateGateValue(secret, true, "10.0.0.1", value, afterGrace, 60) {
		t.Fatal("expected expiry failure")
	}
}

func Test_validateGateValue_tamper(t *testing.T) {
	secret := []byte("tamper")
	now := time.Unix(1_700_000_000, 0)
	value := mintGateValue(secret, true, "10.0.0.1", now) + "x"
	if validateGateValue(secret, true, "10.0.0.1", value, now, 3600) {
		t.Fatal("tampered value should fail")
	}
}

func Test_Check_readsCookie(t *testing.T) {
	secret := []byte("check")
	now := time.Now()
	client := &Client{
		Valid:              true,
		gateSecret:         secret,
		gateBindIP:         true,
		gracePeriodSeconds: 3600,
		log:                slog.Default(),
	}
	value := mintGateValue(secret, true, "10.0.0.2", now)
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.AddCookie(&http.Cookie{Name: gateCookieName, Value: value})
	if !client.Check(req, "10.0.0.2") {
		t.Fatal("Check should accept valid cookie")
	}
}
