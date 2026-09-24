Support EU CAPTCHA (https://eu-captcha.eu/) as a first-class captcha provider in this plugin. Upstream proposed the same provider for the other tree in https://github.com/maxlerebourg/crowdsec-bouncer-traefik-plugin/pull/317. Do not cherry-pick that diff.

Accepted shape:
- Provider value `eucaptcha` beside hcaptcha, recaptcha, turnstile, and custom.
- The stock challenge page already matches the vendor widget (script URL, CSS class, data-sitekey, data-callback, hidden field `eu-captcha-response`). Keep that page.
- Server verify is not today's siteverify and not custom JSON. Vendor contract to implement: POST https://api.eu-captcha.eu/v1/verify with JSON sitekey, secret, client_ip, client_token, client_user_agent. Mint the gate cookie only when success is true and train is false or null. A train true body forces success true when credentials are wrong or protection is off; that must not mint the cookie.
- Forward the client address Validate already receives, and the request User-Agent. An empty client address is a rejection.
- Do not submit empty tokens to the vendor.
- Do not add a startup /verify-credentials probe. The train check is the fail-closed path.
- The delivery card must name upstream pull request https://github.com/maxlerebourg/crowdsec-bouncer-traefik-plugin/pull/317

Vendor page named by the human's prior review: https://docs.eu-captcha.eu/en/api/verify/

That pull request's patch (cache client, FormValue, Content-Type substring, HTTP 400, provider branch inside Validate, startup credential log) is out of scope as a port. It is context, not the diff to apply.
