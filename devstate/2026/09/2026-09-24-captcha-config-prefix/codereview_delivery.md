# Delivery

## Motivation

After the domain-prefix rename, `configuration.Config` keys start with the piece that reads them. Own-axis captcha already uses `captchaEnabled` / `captchaInstanceName`. Bounce-decision fields stay on the bouncer stem even when a value is the word `captcha`.

The seventeen owner-read captcha knobs still sit on `BouncerCaptcha*` / `bouncerCaptcha*`: provider, site and secret keys (and files), gate secret (and file), gate bind, template path, custom widget URLs and validate body, grace seconds, and siteverify timeout. `pkg/captcha` is the piece that reads them — `ownershipFrom` and `newOwnerClient` look up `GetVariable("BouncerCaptchaSiteKey")`, `BouncerCaptchaSecretKey`, and `BouncerCaptchaGateSecret`. The live config-validation spec froze that spelling as the current contract.

Left alone, the prefix rule lies about ownership. Operators and the catalog keep teaching captcha knobs as bouncer knobs. Every new owner-read captcha setting keeps the stale syllable, and the live SHALL keeps that freeze.

Priority: P3 — spec and public-key naming, no current user or operator harm

## Implementation

Rename the seventeen `Config` Go fields `BouncerCaptcha*` → `Captcha*` and JSON tags `bouncerCaptcha*` → `captcha*`. Reorder the struct so the new block sits with `CaptchaEnabled` / `CaptchaInstanceName` (alphabetical by json tag). No old-key aliases. Leave bounce-decision `Bouncer*` fields and the two own-axis captcha keys.

`GetVariable` production strings and `ValidateParams` error text use the new Go names (`CaptchaSiteKey`, `CaptchaSecretKey`, `CaptchaGateSecret`, `CaptchaFilePath`, `CaptchaCustomValidateBody`, `CaptchaProvider`). Leftover owner-read `captcha*` stays non-E2; leftover `captchaInstanceName` stays E2. Dropped `bouncerCaptcha*` never reaches `New`. A leftover pre-prefix `captchaFilePath` binds `CaptchaFilePath` again (field-name match, not an alias).

`pkg/captcha` `ownershipFrom` and `newOwnerClient` read the new `GetVariable` strings and `cfg.Captcha*` knobs. Local argument names stay `siteKey` / `secretKey` / `gateSecret`. Defaults stay the same: template `/captcha.html`, gate bind true, grace 1800, siteverify timeout 10.

README BREAKING names the stem move and the `captchaFilePath` revival. Examples, compose labels, mock and real e2e, unit tests, and the five change-folder spec leaves ship the new names in the same apply.

## What this changes

**Operators.** Rewrite plugin YAML and Traefik labels from `bouncerCaptcha*` to `captcha*` (`captchaProvider`, `captchaSiteKey`, `captchaSecretKey`, `captchaGateSecret`, `captchaFilePath`, and the other twelve); leftover `bouncerCaptcha*` is dropped, and a leftover pre-prefix `captchaFilePath` binds again.

**Admin users.** None.

**Developers.** `configuration.Config` fields and JSON tags are `Captcha*` / `captcha*`; `GetVariable` takes `CaptchaSiteKey`, `CaptchaSecretKey`, and `CaptchaGateSecret`; validation errors name those fields.

**End users.** None.
