Rename the public plugin config fields that belong to the captcha leg from the BouncerCaptcha stem to the Captcha stem. Go field names and JSON tags both move. Breaking the public contract is accepted; this product is still beta. Do not keep old-key aliases.

These fields belong to the captcha component (pkg/captcha reads them; they are instance-owned captcha Open-key knobs) and must be renamed:

- BouncerCaptchaCustomChallengeURL / bouncerCaptchaCustomChallengeUrl → CaptchaCustomChallengeURL / captchaCustomChallengeUrl
- BouncerCaptchaCustomJsURL / bouncerCaptchaCustomJsUrl → CaptchaCustomJsURL / captchaCustomJsUrl
- BouncerCaptchaCustomKey / bouncerCaptchaCustomKey → CaptchaCustomKey / captchaCustomKey
- BouncerCaptchaCustomResponse / bouncerCaptchaCustomResponse → CaptchaCustomResponse / captchaCustomResponse
- BouncerCaptchaCustomValidateBody / bouncerCaptchaCustomValidateBody → CaptchaCustomValidateBody / captchaCustomValidateBody
- BouncerCaptchaCustomValidateURL / bouncerCaptchaCustomValidateUrl → CaptchaCustomValidateURL / captchaCustomValidateUrl
- BouncerCaptchaFilePath / bouncerCaptchaFilePath → CaptchaFilePath / captchaFilePath
- BouncerCaptchaGateBindIP / bouncerCaptchaGateBindIp → CaptchaGateBindIP / captchaGateBindIp
- BouncerCaptchaGateSecret / bouncerCaptchaGateSecret → CaptchaGateSecret / captchaGateSecret
- BouncerCaptchaGateSecretFile / bouncerCaptchaGateSecretFile → CaptchaGateSecretFile / captchaGateSecretFile
- BouncerCaptchaGracePeriodSeconds / bouncerCaptchaGracePeriodSeconds → CaptchaGracePeriodSeconds / captchaGracePeriodSeconds
- BouncerCaptchaProvider / bouncerCaptchaProvider → CaptchaProvider / captchaProvider
- BouncerCaptchaSecretKey / bouncerCaptchaSecretKey → CaptchaSecretKey / captchaSecretKey
- BouncerCaptchaSecretKeyFile / bouncerCaptchaSecretKeyFile → CaptchaSecretKeyFile / captchaSecretKeyFile
- BouncerCaptchaSiteKey / bouncerCaptchaSiteKey → CaptchaSiteKey / captchaSiteKey
- BouncerCaptchaSiteKeyFile / bouncerCaptchaSiteKeyFile → CaptchaSiteKeyFile / captchaSiteKeyFile
- BouncerCaptchaSiteverifyHTTPTimeoutSeconds / bouncerCaptchaSiteverifyHttpTimeoutSeconds → CaptchaSiteverifyHTTPTimeoutSeconds / captchaSiteverifyHttpTimeoutSeconds

Already on the captcha stem; leave them:
- CaptchaEnabled / captchaEnabled
- CaptchaInstanceName / captchaInstanceName

Stay on the bouncer stem. They are bounce decisions, not captcha client knobs:
- BouncerLapiFailureAction / bouncerLapiFailureAction (the value may be the word captcha)
- BouncerAppsecFailureAction / bouncerAppsecFailureAction (the value may be the word captcha)
- BouncerBanFilePath / bouncerBanFilePath
- BouncerRemediationHeadersCustomName
- BouncerRemediationStatusCode

The live config-validation spec currently says owner-read captcha settings stay bouncerCaptcha*. That recorded freeze is what this rename replaces. GetVariable lookup strings, validation error text, README, e2e labels, and tests that name the old keys move with the fields.
