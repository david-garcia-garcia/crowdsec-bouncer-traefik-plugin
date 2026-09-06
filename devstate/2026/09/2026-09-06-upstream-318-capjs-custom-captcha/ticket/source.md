# upstream#318

- title: [FEATURE] CapJS custom captcha
- state: CLOSED
- url: https://github.com/maxlerebourg/crowdsec-bouncer-traefik-plugin/issues/318
- created: 2026-03-11T20:32:55Z
- updated: 2026-03-13T13:03:22Z
- labels: (none)

## Body

**Is your feature request related to a problem? Please describe.** 🐛

I was trying to set up a custom https://capjs.js.org .
Either I’m missing something in the configuration, or it uses a different request format.
On the client side, I managed to set up the CAPTCHA solution itself without much trouble; however, the request containing the solution simply isn't being accepted.
As I understand it, the verification format for the solved CAPTCHA is slightly different.

**Describe the solution you'd like** ✨
It would be great to add more control over how the CAPTCHA verification request is generated.
I managed to set up Wicketkeeper without any issues, but I ran into difficulties with the more popular CapJS.

## Assessment

- relevant: yes
- kind: feature
- affected: yes
- status: present-unfixed
- proof: none
- recommended-action: fix
- slug: 2026-09-06-upstream-318-capjs-custom-captcha
- rationale: The request is for configurable custom-captcha verification so CapJS (JSON `POST` to `/siteverify`) works like Wicketkeeper (urlencoded `secret`/`response`). Our `master` tree already exposes a `custom` provider with `CaptchaCustomJsURL`, `CaptchaCustomValidateURL`, `CaptchaCustomKey`, and `CaptchaCustomResponse` in `pkg/configuration/configuration.go`, and documents Wicketkeeper in `examples/custom-captcha/README.md`, but `pkg/captcha/captcha.go` `Validate` always calls `httpClient.PostForm` with urlencoded `secret` and `response` only. CapJS Standalone expects `Content-Type: application/json` with the same keys in a JSON body, so pointing `CaptchaCustomValidateURL` at CapJS fails unless the operator adds an external adapter (the upstream reporter's Bun proxy). There is no config knob for verification body format or extra fields, and no `pkg/captcha/*_test.go` proves custom verify behavior.

### Evidence
- current: pkg/captcha/captcha.go, pkg/configuration/configuration.go, examples/custom-captcha/README.md
- tests: none

Bound to recommended-action: **fix** — implement the product change and tests on our fork.
