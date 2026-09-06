# upstream#354

- title: [BUG] 405 Method Not Allowed if the CAPTCHA is solved two or more times.
- state: OPEN
- url: https://github.com/maxlerebourg/crowdsec-bouncer-traefik-plugin/issues/354
- created: 2026-07-15T12:58:47Z
- updated: 2026-07-15T12:58:47Z
- labels: (none)

## Body

**Describe the bug** 🐛
If you open two tabs with a CAPTCHA, solve it in the first tab, and then in the second, you will get a "405 Method Not Allowed" error.

**Expected behavior** 👀
As I understand it, this error code is returned by the final application itself; the plugin is no longer processing the request.
It might be worth having the plugin handle all requests that contain CAPTCHA data (i.e., POST requests with `CaptchaCustomResponse`).
Then, for subsequent attempts, you could skip the check if the user has already solved the CAPTCHA and simply redirect them to the standard page.

**Context** 🔎
This behavior occurs with any CAPTCHA.

**Version (please complete the following information):**
 - OS: Docker
 - Traefik version: 3.7
 - Plugin version: 1.6.0
 - Redis: 8.8

**To Reproduce**
Steps to reproduce the behavior:
1. Open any page with a captcha
2. Open the same page in a second tab
3. Solve the captcha on the first page
4. Solve the captcha on the second page
5. See error
Most likely, you'll need to use a real application. In my case, it's Laravel.

---

# Assessment: upstream#354

- relevant: yes
- kind: bug
- affected: yes
- status: present-unfixed
- proof: none
- recommended-action: fix
- slug: 2026-09-06-upstream-354-captcha-duplicate-solve-405
- rationale: Our captcha flow matches upstream: the bundled template POSTs to the same URL (`captcha.html`), `Validate` runs only inside `captcha.ServeHTTP`, and after a successful solve the grace cache (`remoteIP+"_captcha"`) lets later requests through via `handleRemediationServeHTTP` → `Check` → `handleNextServeHTTP` (`pkg/bouncer/bouncer.go:281-284`, `pkg/captcha/captcha.go:96-103`, `121-125`). When a second tab submits that POST after the first tab already solved, `Check` is true but the original POST method is relayed to origin, so a GET-only backend (e.g. Laravel) returns 405. There is no early intercept for captcha form fields in `ServeHTTP`, and the grace-period path never converts an already-solved POST into a redirect the way the first successful verify does.

## Evidence
- current: pkg/bouncer/bouncer.go, pkg/captcha/captcha.go, captcha.html
- tests: none
