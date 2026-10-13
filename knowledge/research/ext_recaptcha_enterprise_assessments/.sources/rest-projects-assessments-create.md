---
url: https://cloud.google.com/recaptcha/docs/reference/rest/v1/projects.assessments/create
title: Method: projects.assessments.create | Google Cloud Fraud Defense
fetched: 2026-09-24
authority: official
---

Creates an Assessment of the likelihood an event is legitimate.

HTTP request: `POST https://recaptchaenterprise.googleapis.com/v1/{parent=projects/*}/assessments`

`parent` is required, format `projects/{project}`.

Request body is an Assessment. If successful, the response body contains a newly created Assessment.

Authorization scopes listed: OAuth `https://www.googleapis.com/auth/cloud-platform`. IAM: `recaptchaenterprise.assessments.create` on `parent`.

This method page does not mention API keys, `X-Goog-Api-Key`, or `?key=`. It does not list HTTP status codes. Last updated 2025-05-14 UTC on fetch.
