# Performance

1. [judgement] Whole body on the heap — `pkg/appsec/query.go:282` — the same capped body is held twice: `io.ReadAll` builds `bodyBytes` while the `TeeReader` fills `bodyBuffer` for the origin restore at `:305`. Peak heap is about 2x `appsecBodyLimit` (default 10 MiB) per in-flight request, plus `ReadAll` regrowth, and it grows with body size times concurrent callers. The diff now also reads HTTP/2 and HTTP/3 bodies of unknown length, which were not read before, for up to `appsecBodyReadTimeoutSeconds` (default 30 s). The cap and the deadline bound each request, so this is judgement, not hard
   Quote:
      ```
      var bodyBuffer bytes.Buffer
      bodyBytes, err := io.ReadAll(io.TeeReader(io.LimitReader(clientBody, c.appsecBodyLimit), &bodyBuffer))
      ...
      req.Body = io.NopCloser(io.MultiReader(&bodyBuffer, clientBody))
      ```
   Fix: Drop the tee and restore origin from the one slice: `io.MultiReader(bytes.NewReader(bodyBytes), clientBody)`
   Status: skipped
   Argument: judgement; the tee + ReadAll double copy predates this change (same shape on master) and is bounded by appsecBodyLimit and the deadline; not applied unattended.
