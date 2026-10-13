# HTTP media types

How RFC 9110 treats `type/subtype` tokens on `Content-Type`.

Fetched: 2026-09-18.

## Type and subtype are case-insensitive

RFC 9110 § 8.3.1 defines `media-type = type "/" subtype parameters`. The type and subtype tokens are case-insensitive. The four examples `text/html;charset=utf-8`, `Text/HTML;Charset="utf-8"`, `text/html; charset="utf-8"`, and `text/html;charset=UTF-8` are equivalent. ([RFC 9110 § 8.3.1](https://www.rfc-editor.org/rfc/rfc9110.html#section-8.3.1), extract `.sources/rfc9110-media-type.md`)

A recipient that matches only the lowercase prefix `application/json` will reject `Application/JSON` even when the body is JSON.

## Parameters are not the type

The type/subtype MAY be followed by semicolon-delimited parameters. Presence of a parameter does not change the type/subtype. Parameter *names* are case-insensitive (RFC 9110 § 5.6.6). Parameter *values* may or may not be, depending on the parameter. Charset names on Content-Type are matched case-insensitively (RFC 9110 § 8.3.2).

Comparing the media type *before parameters* to `application/json` case-insensitively is the RFC match for JSON. `strings.HasPrefix(..., "application/json")` is not that match.

## Sources

- Official: [RFC 9110 § 8.3.1 Media Type](https://www.rfc-editor.org/rfc/rfc9110.html#section-8.3.1)
- Official: [RFC 9110 § 8.3.2 Charset](https://www.rfc-editor.org/rfc/rfc9110.html#section-8.3.2)
- Extracts: `.sources/`
