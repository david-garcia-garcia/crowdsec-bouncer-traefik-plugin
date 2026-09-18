---
url: https://trycap.dev/guide/widget.html
title: Cap Widget
fetched: 2026-09-18
authority: official
---

Client widget is a web component. Standalone endpoint: `https://<your-instance>/<site-key>/`.

Inside a form, the widget injects a hidden `cap-token` input. Attribute `data-cap-hidden-field-name` overrides that name (default `cap-token`).

`solve` event detail: `{ token: string }`.

This page does not document `/siteverify` request encoding.
