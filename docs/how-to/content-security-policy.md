[Documentation](../README.md) › [How-to](README.md) › Keep a Content-Security-Policy

# Keep a Content-Security-Policy without breaking the challenge or the captcha

Two pages served by this plugin need scripts that a strict Content-Security-Policy (CSP) blocks:

- The AppSec bot-detection challenge runs inline scripts and a `blob:` worker. CrowdSec sends the CSP it needs with every challenge, and the plugin replaces any CSP already on the response with it, as the [challenge protocol](https://docs.crowdsec.net/docs/next/appsec/bot_detection/challenge_protocol/) requires.
- The captcha page loads the provider's script (hCaptcha, reCAPTCHA, Turnstile, …) from the provider's domain and runs inline scripts.

If your policy forbids them, the visitor gets a blank page or a captcha that never shows, and the browser console reports `Refused to execute inline script` or `Refused to load the script`. The challenge or the captcha can never be solved.

Where you list Traefik's `headers` middleware decides whether your policy reaches these pages. That middleware does not set its response headers when the request passes through it. It sets them when the response is written, on top of whatever the middlewares after it set. This holds for `contentSecurityPolicy` and for `customResponseHeaders`.

- Listed **before** this plugin, it overwrites the challenge's CSP and also applies to the captcha page. No setting of this plugin can prevent it.
- Listed **after** this plugin, it never runs when the plugin answers (ban, captcha, challenge), so those pages get none of its headers. Responses from your application still get them.

Put your CSP in its own `headers` middleware listed after this plugin. Your other security headers (HSTS, `X-Frame-Options`, …) can stay in one listed before it, so they reach every page:

```yaml
http:
  routers:
    my-router:
      rule: Host(`app.example`)
      service: my-service
      middlewares:
        - security-headers # before: every response, plugin pages included
        - crowdsec
        - csp # after: only responses from your application
  middlewares:
    security-headers:
      headers:
        frameDeny: true
        stsSeconds: 31536000
    csp:
      headers:
        contentSecurityPolicy: "default-src 'self'"
```

The ban and captcha pages then have no CSP. To give them one, put a `<meta http-equiv="Content-Security-Policy">` tag in your own template (`bouncerBanFilePath`, `captchaFilePath`). On the captcha page it must allow the provider's script and the inline scripts.

CrowdSec describes the same conflict, and the nginx setup, in [enabling bot detection](https://docs.crowdsec.net/docs/next/appsec/bot_detection/enable#content-security-policy).
