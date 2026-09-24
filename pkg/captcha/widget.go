package captcha

import "encoding/json"

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

const (
	enterpriseScriptURL     = "https://www.google.com/recaptcha/enterprise.js"
	enterpriseCheckboxClass = "g-recaptcha"
	recaptchaResponseField  = "g-recaptcha-response"
)

// enterpriseCheckboxWidget loads enterprise.js with a g-recaptcha checkbox and retry.
func enterpriseCheckboxWidget(action string) Widget {
	return Widget{
		ScriptURL:        enterpriseScriptURL,
		Class:            enterpriseCheckboxClass,
		TokenField:       recaptchaResponseField,
		Action:           action,
		RetryAfterReject: true,
	}
}

// enterpriseScoreWidget loads enterprise.js?render=siteKey with a fixed execute boot and no retry.
func enterpriseScoreWidget(siteKey, action string) Widget {
	return Widget{
		ScriptURL:        enterpriseScriptURL + "?render=" + siteKey,
		TokenField:       recaptchaResponseField,
		Action:           action,
		BootScript:       scoreBootScript(siteKey, action),
		RetryAfterReject: false,
	}
}

// scoreBootScript is the fixed score-key boot: ready, execute, write the token, submit.
func scoreBootScript(siteKey, action string) string {
	quotedSiteKey := quoteJSString(siteKey)
	quotedAction := quoteJSString(action)
	return "grecaptcha.enterprise.ready(function(){grecaptcha.enterprise.execute(" +
		quotedSiteKey + ",{action:" + quotedAction +
		"}).then(function(token){document.getElementById(\"g-recaptcha-response\").value=token;document.getElementById(\"captcha-form\").submit();});});"
}

// quoteJSString JSON-quotes value so it is safe inside the fixed boot script.
func quoteJSString(value string) string {
	quoted, err := json.Marshal(value)
	if err != nil {
		return `""`
	}
	return string(quoted)
}
