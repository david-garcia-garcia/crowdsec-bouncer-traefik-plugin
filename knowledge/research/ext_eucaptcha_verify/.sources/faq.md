---
url: https://docs.eu-captcha.eu/en/troubleshooting/faq/
title: FAQ - Myra EU CAPTCHA Online Help
fetched: 2026-09-24
authority: official
---

Each token is valid one time. A second verification of the same token responds with `timeout-or-duplicate`. The same code also stands for an expired challenge.

Why the endpoint reports success although there was no verification: the response contains `success: true` together with `train: true`. `train: true` means there was no real verification. Each transmission then counts as successful. This occurs with an unknown sitekey, with a secret that does not agree, with a sitekey whose protection is off, and with each other malfunction of the verification. In production, always examine the two fields.

At the end of the trial period the widget returns the `TRIAL_EXPIRED` error code and lets requests through. That code is not listed on the `/verify` error-codes table.
