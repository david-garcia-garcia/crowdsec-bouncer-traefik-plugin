# Standards

1. [hard] Leave a trail — `pkg/configuration/configuration.go:620` — the new `CaptchaCustomValidateBody` token-check block has no one-line intro
   → Add a one-line comment that the block accepts only empty/form/json after trim and rejects `json` on a non-custom provider
   Status: done
   Argument: one-line block comment in validateCaptcha (01596af9).
