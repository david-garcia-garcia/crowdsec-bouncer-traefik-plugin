# Traefik entrypoint request path

What Traefik does to the request path on the entry point, before a plugin middleware and the backend see it. This plugin matches `bouncerActionRules` `path` patterns on `http.Request.URL.Path`, so these facts decide which raw URLs a path rule matches.

## What Traefik rewrites

Traefik handles the path in three steps, in this order: encoded character filtering, normalization, sanitization.

Owner: [Traefik — Request Path](https://doc.traefik.io/traefik/security/request-path/). Extract: `.sources/request-path.md`.

- Normalization decodes the unreserved percent-encoded characters, so `%2e` becomes `.`. It has no option.
- Sanitization removes `.` and `..` segments and duplicate slashes. It is the entry point option `http.sanitizePath`, default `true`.

Owner: [Traefik EntryPoints](https://doc.traefik.io/traefik/reference/install-configuration/entrypoints/). Extract: `.sources/entrypoints.md`.

- From v3.7.18, a `.`, `..` or empty segment that carries a path parameter (`..;x`) is resolved like a plain dot segment.

Owner: [Traefik v3 minor migrations](https://doc.traefik.io/traefik/migrate/v3/). Extract: `.sources/migrate-v3.md`.

## What Traefik leaves alone by default

Encoded reserved characters are allowed by default: `%2F`, `%5C`, `%00`, `%3B`, `%25`, `%3F`, `%23`. Each has an entry point option under `http.encodedCharacters` (`allowEncodedSlash`, `allowEncodedBackSlash`, `allowEncodedNullCharacter`, `allowEncodedSemicolon`, `allowEncodedPercent`, `allowEncodedQuestionMark`, `allowEncodedHash`), default `true`. Set to `false`, Traefik rejects a path that holds that character.

Owner: same two pages. Extracts: `.sources/request-path.md`, `.sources/entrypoints.md`.

## What a plugin middleware and the backend receive

The documentation does not say which path a middleware receives. Measured 2026-11-20 on Traefik v3.7.11 and v3.7.19 with this plugin loaded and an anchored `^/api/` path rule (`authority: inference`, extract `.sources/path-probe.md`):

- `/api/../other`, `/api/%2e%2e/other`, `/api/.%2e/other` and `/api/..\other` reach the plugin and the backend as `/other`. The rule does not match.
- `/api/..;/other` and `/api/%2E%2E;/other` reach both unchanged on v3.7.11, and the rule matches. On v3.7.19 they arrive as `/other`, and the rule does not match.
- `/api/..%2Fother`, `/api/..%5Cother`, `/api/..%3B/other`, `/api%2Fx` and `/api/%252e%252e/other` reach both unchanged on both versions, and the rule matches. `URL.Path` holds the decoded form (`/api/../other` for the first one); the backend gets the encoded form.
- With `allowEncodedSlash`, `allowEncodedBackSlash`, `allowEncodedSemicolon` and `allowEncodedPercent` set to `false`, Traefik answers `400` to every one of those encoded forms, before the plugin runs.

So with the default entry point options, a path rule that matches a prefix also matches a request whose path leaves that prefix through an encoded `/`, `\` or `;`, or through double encoding. Whether that request is served as another resource depends on how the backend reads the path.

This plugin's `httprule.SingleReadingPath` exists for that case (`knowledge/devdocs/core_plugin_httprule.md`).
