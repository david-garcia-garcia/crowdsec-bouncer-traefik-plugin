---
url: https://github.com/golang/go/blob/go1.25.6/src/net/http/responsecontroller.go
title: net/http ResponseController.SetReadDeadline
fetched: 2026-11-14
authority: source
ref: golang/go@go1.25.6:src/net/http/responsecontroller.go
---

Type doc (L23-24): the ResponseWriter should be the original value passed to `ServeHTTP`, or have an `Unwrap() ResponseWriter` method returning it.

`func (c *ResponseController) SetReadDeadline` (L80-97) doc: "sets the deadline for reading the entire request, including the body. Reads from the request body after the deadline has been exceeded will return an error. A zero value means no deadline. Setting the read deadline after it has been exceeded will not extend it." Walks `Unwrap()` until a writer has `SetReadDeadline(time.Time) error`; otherwise returns `errNotSupported()` = `fmt.Errorf("%w", ErrNotSupported)` (L145-146).
