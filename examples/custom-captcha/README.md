# Example

Read the example captcha before this, to better understand what is done here.

### Traefik configuration

The minimal configuration is defined below to implement custom captcha.  
This documentation use https://github.com/a-ve/wicketkeeper, a self-hosted captcha provider that have a similar API than big providers.

Minimal API requirement:

- the JS file URL to load the captcha on the served `captcha.html`
- the HTML className to tell to the JS where to display the challenge
- the verify URL endpoint to send the field `response` from the captcha with `content-type: application/x-www-form-urlencoded`
- the name of the field when you POST the resolved captcha to Traefik
- the challenge URL the widget fetches from the browser, when the provider has one

Here wicketkeeper serves both the JS file and the challenge endpoint on the protected router,
so a captcha-flagged client must be able to reach `/fast.js` and `/v0/challenge` to solve the
captcha at all. Declaring them as `bouncerCaptchaCustomJsUrl` and `bouncerCaptchaCustomChallengeUrl` is what
lets those two exact paths through to the origin while the client is still unsolved. Banned
clients never get that passthrough.

- the JS file need to respect the `data-callback` on the div that contains the captcha if you use our template, but you can customize it by your side

```yaml
  traefik:
    ...
    labels:
      # Choose captcha provider
      - "traefik.http.middlewares.crowdsec.plugin.bouncer.captchaEnabled=true"
      - "traefik.http.middlewares.crowdsec.plugin.bouncer.bouncerCaptchaProvider=custom"
      # Define captcha grace period seconds
      - "traefik.http.middlewares.crowdsec.plugin.bouncer.bouncerCaptchaGracePeriodSeconds=1800"
      - "traefik.http.middlewares.crowdsec.plugin.bouncer.bouncerCaptchaCustomJsUrl=http://captcha.localhost:8000/fast.js"
      # The widget fetches this from the browser, so it is rendered in captcha.html and passed through to the origin
      - "traefik.http.middlewares.crowdsec.plugin.bouncer.bouncerCaptchaCustomChallengeUrl=http://captcha.localhost:8000/v0/challenge"
      # Inside Traefik container the plugin must be able to reach wicketkeeper service so we can go through a Traefik localhost
      # domain which would resolve traefik itself and the port for the dashboard
      - "traefik.http.middlewares.crowdsec.plugin.bouncer.bouncerCaptchaCustomValidateUrl=http://wicketkeeper:8080/v0/siteverify"
      - "traefik.http.middlewares.crowdsec.plugin.bouncer.bouncerCaptchaCustomKey=wicketkeeper"
      - "traefik.http.middlewares.crowdsec.plugin.bouncer.bouncerCaptchaCustomResponse=wicketkeeper_solution"
      # Define captcha HTML file path
      - "traefik.http.middlewares.crowdsec.plugin.bouncer.bouncerCaptchaFilePath=/captcha.html"
```

```yaml
wicketkeeper:
  image: ghcr.io/a-ve/wicketkeeper:latest
  user: root
  ports:
    - "8080:8080"
  environment:
    - LISTEN_PORT=8080
    - REDIS_ADDR=redis:6379
    - DIFFICULTY=4
    - ALLOWED_ORIGINS=*
    - PRIVATE_KEY_PATH=/data/wicketkeeper.key
  volumes:
    - ./data:/data
  depends_on:
    - redis
redis:
  image: redis/redis-stack-server:latest
```

`data-challenge-url` comes from `bouncerCaptchaCustomChallengeUrl`, so the endpoint is configured once
on the middleware instead of being hard-coded in the template:

```html
<div id="captcha" class="{{ .FrontendKey }}" data-sitekey="{{ .SiteKey }}" data-callback="captchaCallback" data-challenge-url="{{ .ChallengeURL }}">
```

## Exemple navigation

We can try to query normally the whoami server:

```bash
curl http://localhost:8000/foo
```

We can try to ban ourself and retry.

```bash
docker exec crowdsec cscli decisions add --ip 10.0.0.20 -d 10m --type captcha
```

To play the demo environment run:

```bash
make run_custom_captcha
```
