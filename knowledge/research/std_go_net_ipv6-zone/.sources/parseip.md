---
url: https://pkg.go.dev/net#ParseIP
title: net.ParseIP
fetched: 2026-09-18
authority: official
---

ParseIP parses s as an IP address. The string s can be in IPv4 dotted decimal ("192.0.2.1"), IPv6 ("2001:db8::68"), or IPv4-mapped IPv6 ("::ffff:192.0.2.1") form. If s is not a valid textual representation of an IP address, ParseIP returns nil. The returned address is always 16 bytes; IPv4 addresses are returned in IPv4-mapped IPv6 form.

No scoped-zone form is listed.
