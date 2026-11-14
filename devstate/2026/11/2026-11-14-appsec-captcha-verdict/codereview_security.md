# Security

1. [judgement] Client-controlled trust — `pkg/bouncer/bouncer.go:312` — the new marker branch lets any visitor (no captcha decision, rule or AppSec verdict needed) reach the solve redirect `pkg/captcha/captcha.go:116`, whose `Location` is the request's own `req.URL.String()`; a request path `//evil.com` yields `Location: //evil.com` (checked on go1.25 `http.Redirect`), an open redirect when Traefik does not collapse duplicate slashes (`sanitizePath` disabled or an older Traefik) and the POST carries a valid provider token; the sink predates this diff, the diff only widens who can reach it
   Quote:
   ```
   if b.hasUsableCaptcha() && b.loadedCaptcha().HasChallengeMarker(req.Request) {
       return b.serveAppsecCaptchaGate(rw, req)
   }
   ```
   Fix: Redirect to a same-origin path only (e.g. `"/" + strings.TrimLeft(req.URL.EscapedPath(), "/")` plus the raw query) in `ServeHTTP` and `WriteSolvedRedirect`
   Status: skipped
   Argument: outside diff; not applied unattended. Sink is `pkg/captcha` redirect, predates this change; noted in `knowledge/debt/2026-11-14-captcha-redirect-same-origin-path.md`.
