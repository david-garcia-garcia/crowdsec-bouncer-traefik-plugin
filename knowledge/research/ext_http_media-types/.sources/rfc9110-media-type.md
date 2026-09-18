---
url: https://www.rfc-editor.org/rfc/rfc9110.html#section-8.3.1
title: RFC 9110 § 8.3.1 Media Type
fetched: 2026-09-18
authority: official
---

HTTP uses media types [RFC2046] in the Content-Type (Section 8.3) and Accept (Section 12.5.1) header fields.

media-type = type "/" subtype parameters

The type and subtype tokens are case-insensitive.

The type/subtype MAY be followed by semicolon-delimited parameters (Section 5.6.6) in the form of name/value pairs. Parameter values might or might not be case-sensitive, depending on the semantics of the parameter name.

These media types are equivalent:

- text/html;charset=utf-8
- Text/HTML;Charset="utf-8"
- text/html; charset="utf-8"
- text/html;charset=UTF-8

Charset names on Content-Type are matched case-insensitively (Section 8.3.2).
