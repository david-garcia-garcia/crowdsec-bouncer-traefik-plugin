---
url: https://trycap.dev/guide/standalone/
title: Cap Standalone
fetched: 2026-09-06
authority: official
---

Cap Standalone is the recommended self-hosted Cap backend. Runs on Bun; idle memory ~50 MB. Built-in instrumentation challenges. Siteverify API compatible with reCAPTCHA. Web dashboard for multiple site keys. Docker recommended.

Docker image: `tiago2/cap:latest`. Port 3000. Requires Redis/Valkey (`REDIS_URL`). `ADMIN_KEY` is dashboard login (≥32 chars recommended). Dashboard at `http://localhost:3000`. Create site key + secret key in dashboard. Instance must be publicly reachable from the internet.

Client-side: set `data-cap-api-endpoint` to `https://<instance_url>/<site_key>/`. Example: `<cap-widget data-cap-api-endpoint="https://cap.example.com/d9256640cb53/"></cap-widget>`.

Server-side verification: POST to `https://<instance_url>/<site_key>/siteverify` with JSON body `{ "secret": "<key_secret>", "response": "<captcha_token>" }`. Header `Content-Type: application/json`. `<key_secret>` is the secret key from dashboard (not ADMIN_KEY). `<captcha_token>` is the widget token. Success response: `{ "success": true }`.
