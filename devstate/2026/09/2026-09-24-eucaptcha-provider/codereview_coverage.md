# Test coverage

1. [hard] Assertion does not prove the job — `pkg/captcha/eucaptcha.go:49` — verify URL and JSON field names are checked against the production constant and the same tagged struct; a wrong official URL or `json` tag stays green
   Quote:
      ```
      type eucaptchaVerifyRequest struct {
          SiteKey         string `json:"sitekey"`
          Secret          string `json:"secret"`
          ClientIP        string `json:"client_ip"`
          ClientToken     string `json:"client_token"`
          ClientUserAgent string `json:"client_user_agent"`
      }
      eucaptchaVerifyURL = "https://api.eu-captcha.eu/v1/verify"
      Test: Test_Validate_eucaptchaURLAndJSONFields: got != eucaptchaVerifyURL; json.Unmarshal(trip.lastBody, &eucaptchaVerifyRequest)
      ```
   Fix: Assert the request URL is `https://api.eu-captcha.eu/v1/verify` and the raw JSON keys are `sitekey`, `secret`, `client_ip`, `client_token`, `client_user_agent`
   Status: done
   Argument: Test_Validate_eucaptchaURLAndJSONFields now asserts the literal verify URL and raw JSON keys on the posted body.
2. [hard] Edge case untested — `pkg/captcha/eucaptcha.go:99` — verify body larger than 64KiB is an error return; no test hits that branch
   Quote:
      ```
      body, err := io.ReadAll(io.LimitReader(res.Body, eucaptchaResponseBodyLimit+1))
      if len(body) > eucaptchaResponseBodyLimit {
          return false, errors.New("eucaptcha: response body too large")
      }
      Test: (none)
      ```
   Fix: Assert a verify body larger than 64KiB is an error outcome (None), not Pass or Reject
   Status: done
   Argument: Test_Validate_eucaptchaErrorVersusReject now asserts a 64KiB-oversize success JSON is error/None.
