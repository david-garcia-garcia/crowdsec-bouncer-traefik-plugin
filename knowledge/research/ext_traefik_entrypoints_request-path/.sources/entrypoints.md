---
url: https://doc.traefik.io/traefik/reference/install-configuration/entrypoints/
title: Traefik EntryPoints — sanitizePath and encodedCharacters
fetched: 2026-11-20
authority: official
---

`http.sanitizePath`, default `true`: "Defines whether to enable the request path sanitization."

"When disabled, the incoming request path is passed to the backend as is." "Setting the sanitizePath option to false is not safe."

Examples with `sanitizePath: true`: `/foo/../bar` → `/bar`; `/foo/bar//` → `/foo/bar/`; `/./foo/../bar//` → `/bar/`.

`http.encodedCharacters`: "Defines which encoded characters are allowed in the request path." Sub-options, each default `true`: `allowEncodedSlash`, `allowEncodedBackSlash`, `allowEncodedNullCharacter`, `allowEncodedSemicolon`, `allowEncodedPercent`, `allowEncodedQuestionMark`, `allowEncodedHash`.

"By default, Traefik do not reject requests with path containing certain encoded characters".

"This check is not done against the request query parameters, but only against the request path".
