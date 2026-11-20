---
url: https://doc.traefik.io/traefik/security/request-path/
title: Traefik — Request Path
fetched: 2026-11-20
authority: official
---

Documentation branch: v3.7.

Order of the three steps on the request path: "1. Encoded Character Filtering", "2. Path Normalization", "3. Path Sanitization".

Encoded character filtering: "Traefik inspects the path for potentially dangerous encoded characters and rejects requests containing them unless explicitly allowed." Characters covered: `%2f`/`%2F` (`/`), `%5c`/`%5C` (`\`), `%00` (NULL), `%3b`/`%3B` (`;`), `%25` (`%`), `%3f`/`%3F` (`?`), `%23` (`#`).

Default: "All encoded character filtering is disabled by default (`true` means encoded characters are allowed)."

"This filtering occurs before path sanitization".

Normalization: "Traefik normalizes the request path by decoding the unreserved percent-encoded characters, as they are equivalent to their non-encoded form" and "capitalizing the percent-encoded characters".

Sanitization: "removing the `..`, `.` and duplicate slash segments". "Path sanitization is enabled by default". Examples on the page: `/foo/..;bar/baz` → `/baz`; `/foo/.;bar/baz` → `/foo/baz`; `/./foo/../bar//` → `/bar/`.

Per route: "you can use the `EncodedCharacters` middleware".

The page does not say which path a middleware receives, and does not name the HTTP status of a rejected request.
