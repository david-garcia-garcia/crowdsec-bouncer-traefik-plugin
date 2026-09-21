---
url: https://pkg.go.dev/net/http#Request
title: net/http Request
fetched: 2026-09-17
authority: official
---

For client requests, certain headers such as Content-Length and Connection are automatically written when needed and values in Header may be ignored. See Request.Write.

ContentLength records the length of the associated content. -1 means unknown. Values >= 0 indicate that number of bytes may be read from Body. For client requests, a value of 0 with a non-nil Body is also treated as unknown.

Request.Write: If Body is present, Content-Length is <= 0 and TransferEncoding is not identity, Write adds Transfer-Encoding: chunked.
