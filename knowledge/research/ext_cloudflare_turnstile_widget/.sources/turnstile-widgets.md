---
url: https://developers.cloudflare.com/turnstile/concepts/widget/
title: Turnstile widgets · Cloudflare Turnstile docs
fetched: 2026-10-16
authority: official
---

A Turnstile widget has a mode, a label, a sitekey, and a secret key. Hosted under `challenges.cloudflare.com`.

Available modes: Managed, Non-Interactive, and Invisible.

- Managed (recommended): automatically chooses between non-interactive or a checkbox challenge based on visitor risk. No images or text to decipher. Interaction, when required, is selecting a box.
- Non-Interactive: visible widget with a loading spinner. Visitors are never required or prompted to interact.
- Invisible: similar to Non-Interactive in that visitors never interact. Visitors also do not see a widget or any indication that a challenge is in progress.

This page does not name `cf-turnstile-response`, `response-field`, or any other form input. Mode is described as visibility and interaction behavior.
