package captcha

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"
)

const (
	gateCookieName     = "crowdsec_captcha_gate"
	clockSkewSeconds   = 30
	gatePayloadVersion = "v1"
)

func mintGateValue(secret []byte, bindIP bool, remoteIP string, issued time.Time) string {
	bindFlag := "0"
	ip := ""
	if bindIP {
		bindFlag = "1"
		ip = remoteIP
	}
	prefix := fmt.Sprintf("%s.%d.%s.%s", gatePayloadVersion, issued.Unix(), bindFlag, ip)
	mac := hmac.New(sha256.New, secret)
	_, _ = mac.Write([]byte(prefix))
	sig := base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
	return prefix + "." + sig
}

func validateGateValue(secret []byte, bindIPConfig bool, remoteIP, value string, now time.Time, gracePeriodSeconds int64) bool {
	if value == "" {
		return false
	}
	lastDot := strings.LastIndex(value, ".")
	if lastDot <= 0 || lastDot >= len(value)-1 {
		return false
	}
	prefix := value[:lastDot]
	sig := value[lastDot+1:]
	expectedMac := hmac.New(sha256.New, secret)
	_, _ = expectedMac.Write([]byte(prefix))
	expectedSig := base64.RawURLEncoding.EncodeToString(expectedMac.Sum(nil))
	if !hmac.Equal([]byte(sig), []byte(expectedSig)) {
		return false
	}
	parts := strings.SplitN(prefix, ".", 4)
	if len(parts) != 4 || parts[0] != gatePayloadVersion {
		return false
	}
	issuedUnix, err := strconv.ParseInt(parts[1], 10, 64)
	if err != nil {
		return false
	}
	issued := time.Unix(issuedUnix, 0)
	expires := issued.Add(time.Duration(gracePeriodSeconds) * time.Second)
	if now.Before(issued.Add(-clockSkewSeconds * time.Second)) {
		return false
	}
	if now.After(expires) {
		return false
	}
	if bindIPConfig {
		if parts[2] != "1" || parts[3] != remoteIP {
			return false
		}
	}
	return true
}

func setGateCookie(rw http.ResponseWriter, r *http.Request, value string, maxAge int64) {
	cookie := &http.Cookie{
		Name:     gateCookieName,
		Value:    value,
		Path:     "/",
		MaxAge:   int(maxAge),
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
	}
	if r.TLS != nil {
		cookie.Secure = true
	}
	http.SetCookie(rw, cookie)
}

func gateCookieValue(r *http.Request) string {
	c, err := r.Cookie(gateCookieName)
	if err != nil {
		return ""
	}
	return c.Value
}
