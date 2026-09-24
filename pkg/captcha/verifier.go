package captcha

// Verifier classifies a posted solver token with the provider.
type Verifier interface {
	// Pass reports whether the provider accepted token for remoteIP.
	// remoteIP is the address already chosen for this request; empty omits it.
	Pass(token, remoteIP string) (bool, error)
}
