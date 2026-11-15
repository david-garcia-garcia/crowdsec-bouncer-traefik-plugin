---
url: https://docs.hcaptcha.com/integrations/react
title: React | hCaptcha
fetched: 2026-10-16
authority: official
---

Official `@hcaptcha/react-hcaptcha` component inside `<form method="POST" action="/login">` with email/password fields and a submit button. The form sends `h-captcha-response` to `/login` with the other fields. JSX has no extra hidden input.

For asynchronous submissions, capture the token with `onVerify` instead of relying on a native form POST.
