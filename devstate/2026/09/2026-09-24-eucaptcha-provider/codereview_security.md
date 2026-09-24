# Security

1. [judgement] Download integrity — `pkg/captcha/eucaptcha.go:85` — eucaptcha `http.Client` has no host-bound CheckRedirect, so a cross-host 3xx can resend `secret` (307/308) or let a forged 200 JSON Pass (301/302/303); reachability unknown (needs api.eu-captcha.eu to redirect)
   Fix: Reject redirects whose host is not api.eu-captcha.eu
   Status: skipped
   Argument: judgement; vendor 3xx reachability unknown; sibling siteverify and assessments clients have the same unbounded CheckRedirect.
