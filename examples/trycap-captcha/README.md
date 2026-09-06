# Example: Cap Standalone (trycap)

First-class `captchaProvider=trycap` for [Cap Standalone](https://trycap.dev/guide/standalone/). The plugin POSTs JSON `{"secret","response"}` to `{instance}/{siteKey}/siteverify` and the default `captcha.html` renders `<cap-widget>`.

Run a Cap Standalone instance yourself (`tiago2/cap`). This example does not ship that container.

## Traefik labels

```yaml
labels:
  - "traefik.http.middlewares.crowdsec.plugin.bouncer.captchaProvider=trycap"
  - "traefik.http.middlewares.crowdsec.plugin.bouncer.captchaTrycapInstanceUrl=https://cap.example.com"
  - "traefik.http.middlewares.crowdsec.plugin.bouncer.captchaSiteKey=FIXME"
  - "traefik.http.middlewares.crowdsec.plugin.bouncer.captchaSecretKey=FIXME"
  - "traefik.http.middlewares.crowdsec.plugin.bouncer.captchaGracePeriodSeconds=1800"
  - "traefik.http.middlewares.crowdsec.plugin.bouncer.captchaHTMLFilePath=/captcha.html"
```

`captchaTrycapInstanceUrl` is the public origin of Cap Standalone (no site-key path). Bind-mount the repo `captcha.html` (or `examples/captcha/captcha.html`) into Traefik as for other captcha examples.

A custom `captchaFilePath` template must include:

- `{{ .FrontendJS }}` as `<script type="module">`
- `<cap-widget data-cap-api-endpoint="{{ .CapApiEndpoint }}">`
- form field `cap-token` (the widget injects it) or a `solve` listener that POSTs that token
