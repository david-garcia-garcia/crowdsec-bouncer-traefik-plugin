package captcha

import (
	"bytes"
	"io"
	"mime"
	"mime/multipart"
	"net/http"
	"net/url"
)

// captchaFormMaxBytes is the largest POST body inspected for a provider token.
// Provider tokens are small, so a bigger body is origin traffic and is left alone.
const captchaFormMaxBytes = 64 << 10

// peekCaptchaFormBody reads up to captchaFormMaxBytes and always leaves r.Body readable.
// It reports the buffered body, and false when the body exceeds the cap or could not be
// read — which also covers a request whose Content-Length is unknown and whose body turns
// out to be large.
func peekCaptchaFormBody(r *http.Request) ([]byte, bool) {
	if r.Body == nil {
		return nil, false
	}
	peeked, err := io.ReadAll(io.LimitReader(r.Body, captchaFormMaxBytes+1))
	if err != nil || len(peeked) > captchaFormMaxBytes {
		r.Body = io.NopCloser(io.MultiReader(bytes.NewReader(peeked), r.Body))
		return nil, false
	}
	_ = r.Body.Close()
	r.Body = io.NopCloser(bytes.NewReader(peeked))
	r.ContentLength = int64(len(peeked))
	return peeked, true
}

// formFieldValue returns one field of an already-buffered urlencoded or multipart body.
// A body with no usable Content-Type is read as urlencoded, which is what the bundled
// captcha form sends.
func formFieldValue(contentType string, body []byte, field string) string {
	mediaType, params, err := mime.ParseMediaType(contentType)
	if err != nil {
		mediaType = "application/x-www-form-urlencoded"
	}
	switch mediaType {
	case "application/x-www-form-urlencoded":
		values, parseErr := url.ParseQuery(string(body))
		if parseErr != nil {
			return ""
		}
		return values.Get(field)
	case "multipart/form-data":
		return multipartFieldValue(params["boundary"], body, field)
	default:
		return ""
	}
}

// multipartFieldValue reads one form value out of a buffered multipart body.
func multipartFieldValue(boundary string, body []byte, field string) string {
	if boundary == "" {
		return ""
	}
	// The body is already capped, so this parse never spills to a temporary file.
	form, err := multipart.NewReader(bytes.NewReader(body), boundary).ReadForm(captchaFormMaxBytes)
	if err != nil {
		return ""
	}
	defer func() { _ = form.RemoveAll() }()
	values := form.Value[field]
	if len(values) == 0 {
		return ""
	}
	return values[0]
}

// readFieldFromRequest returns one named field from the query, the POST form, or the raw urlencoded body.
// Traefik's Yaegi request wrapper often leaves Form empty after FormValue, so the body is parsed directly when ParseForm yields nothing.
// It parses the form and truncates a body over 1MiB. Validate uses it on a request the plugin answers itself, so that request is never forwarded.
func readFieldFromRequest(r *http.Request, field string) string {
	if field == "" {
		return ""
	}
	if value := r.URL.Query().Get(field); value != "" {
		return value
	}

	var raw []byte
	if r.Body != nil {
		raw, _ = io.ReadAll(io.LimitReader(r.Body, 1<<20))
		r.Body = io.NopCloser(bytes.NewReader(raw))
	}

	if err := r.ParseForm(); err == nil {
		if value := r.PostForm.Get(field); value != "" {
			return value
		}
		if value := r.Form.Get(field); value != "" {
			return value
		}
	}

	values, err := url.ParseQuery(string(raw))
	if err != nil {
		return ""
	}
	return values.Get(field)
}
