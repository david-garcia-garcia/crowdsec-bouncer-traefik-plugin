---
url: https://pkg.go.dev/net/http#Client.Do
title: net/http Client.Do
fetched: 2026-09-17
authority: official
---

Do sends an HTTP request and returns an HTTP response. A non-2xx status code does not cause an error.

If the returned error is nil, the Response contains a non-nil Body which the user is expected to close. If the Body is not both read to EOF and closed, the Client's underlying RoundTripper (typically Transport) may not be able to re-use a persistent TCP connection to the server for a subsequent keep-alive request.

On error, any Response can be ignored. A non-nil Response with a non-nil error only occurs when CheckRedirect fails, and even then Response.Body is already closed.
