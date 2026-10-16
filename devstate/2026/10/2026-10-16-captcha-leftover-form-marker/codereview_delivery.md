# Delivery

## Motivation
After a visitor has already solved the CrowdSec captcha, leftover-form detection still treats a non-empty vendor token field (`g-recaptcha-response`, `h-captcha-response`, `cf-turnstile-response`, `eu-captcha-response`, or a custom TokenField) as proof that the POST is the CrowdSec challenge.

The visitor holds a valid `crowdsec_captcha_gate` cookie and submits an ordinary application form that also embeds the same vendor widget. The plugin answers `302 Found` to that same URL and does not forward the body. Browsers follow the 302 with a GET and drop the POST. A route that accepts only POST then renders its own not-found page; a refresh repeats the GET.

The leftover-tab case is real: the gate cookie is shared across tabs, and a second submit of the CrowdSec challenge must still be kept off origin. Using the vendor field as that proof is the wrong signal, so solved visitors lose application POSTs today.

Priority: P1 — production is serving a wrong public contract today

## Implementation
`IsCaptchaFormPost` still runs after `Check` is true on the captcha-kind path, but it now answers yes only when the POST carries leftover-form marker `crowdsec_captcha_challenge=v1`. It no longer reads `widget.TokenField`. The 64KiB peek, urlencoded/multipart/already-parsed readers, and first-solve `Validate`/`TokenField` path stay. `pkg/captcha` owns the marker name and value constants; the six shipped challenge pages emit the same hidden input. No Config key.

## What this changes
**Operators.** A replaced challenge template that still wants leftover-tab redirect must include hidden `crowdsec_captcha_challenge=v1`; omitting it still first-solves, and a second submit of that template is forwarded.
**Admin users.** None.
**Developers.** After `Check` is true, leftover-form detection is `crowdsec_captcha_challenge=v1` only; a non-empty provider TokenField is not leftover proof.
**End users.** After solving the captcha, an application form POST that includes a vendor token field reaches the application instead of being redirected.
