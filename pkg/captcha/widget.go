package captcha

// Widget is the challenge-page pairing stored at construction.
type Widget struct {
	ScriptURL        string
	Class            string
	TokenField       string
	Action           string
	BootScript       string
	RetryAfterReject bool
}

// drawCheckbox is non-empty when the checkbox div should render.
func (w Widget) drawCheckbox() string {
	if w.Class == "" {
		return ""
	}
	return "1"
}
