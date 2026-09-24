package captcha

// Verifier classifies a posted solver token with the provider.
type Verifier interface {
	// Pass reports whether the provider accepted token for remoteIP.
	// remoteIP is the address already chosen for this request; empty omits it
	// on siteverify and assessments, and is a local reject on eucaptcha.
	// userAgent is r.UserAgent() on the challenge request; siteverify and
	// assessments ignore it.
	Pass(token, remoteIP, userAgent string) (bool, error)
}
