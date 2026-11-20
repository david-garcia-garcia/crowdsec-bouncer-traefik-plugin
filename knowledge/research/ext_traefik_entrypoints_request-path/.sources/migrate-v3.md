---
url: https://doc.traefik.io/traefik/migrate/v3/
title: Traefik v3 minor migrations — request path sections
fetched: 2026-11-20
authority: official
---

Section headings by version: v3.3.6 "Request Path Sanitization"; v3.4.1 "Request Path Normalization", "Reserved Character Handling in Routing"; v3.6.4 "Encoded Characters in Request Path"; v3.6.7 "Encoded Characters Configuration Default Values"; v3.7.18 "Dot-Segments with Path Parameters".

v3.7.18: "when the `sanitizePath` entry point option is enabled (default), a `..`, `.` or empty segment with path parameters is now resolved like a plain dot-segment or duplicate slash". Example on the page: `/foo/.;bar/baz` is forwarded as `/foo/baz`.

The bodies of the v3.3.6, v3.4.1, v3.6.4 and v3.6.7 sections were not extracted word for word; only their headings are quoted here.
