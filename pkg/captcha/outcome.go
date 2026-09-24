package captcha

// Outcome is how Validate classifies a challenge request.
type Outcome int

const (
	// None means the request is not a POST or the token field is empty.
	None Outcome = iota
	// Pass means the verifier accepted the posted token.
	Pass
	// Reject means a token was posted and the verifier returned false with no error.
	Reject
)
