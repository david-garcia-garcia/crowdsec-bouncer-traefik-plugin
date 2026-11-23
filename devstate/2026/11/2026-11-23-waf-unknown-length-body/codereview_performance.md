# Performance

1. [judgement] Slice or map grown from an unbounded input — `pkg/wafhop/body.go:120` — a body without Content-Length skips `Grow`, so `buf.ReadFrom` walks the `bytes.Buffer` doubling ladder; any body past about 8 MiB (and the limit+1 probe at both defaults, 10 MiB AppSec and 8 MiB ModSec) ends at about 16 MiB of capacity per leg, plus the 8 MiB slice it copies from, held up to that leg's read timeout. This diff makes HTTP/2 and HTTP/3 streams reach this path (HTTP/1.1 chunked already did). What grows: heap per concurrent upload without Content-Length; still bounded per request by the limit and the 30 s timeout, so not hard.
   Quote:
   ```
   if httpReq.ContentLength > 0 && httpReq.ContentLength <= limit {
   	buf.Grow(int(httpReq.ContentLength))
   }
   if httpReq.ContentLength < 0 {
   	timer := time.AfterFunc(timeout, func() { cutBodyRead(ctrl, src) })
   	_, err = buf.ReadFrom(reader)
   ```
   Fix: When ContentLength < 0, cap buffer growth at limit+1 (grow to min(2×cap, limit+1) per step) instead of ReadFrom's free doubling
   Status: skipped
   Argument: Judgement: bounded per request by the leg limit and the read timeout; the same doubling already applied to HTTP/1.1 chunked bodies. Optimisation beyond the ask, not applied unattended.
2. [judgement] Second leg copies a prefix the first leg already holds — `pkg/wafhop/body.go:109` — reuse only covers a complete prior body; when AppSec's buffer is incomplete (body over appsecBodyLimit), ModSec re-reads limit+1 bytes out of AppSec's in-memory data into a second buffer (about 16 MiB more at defaults) only to answer 413, so peak per request is about 32 MiB across the two legs. Same shape existed for long bodies with Content-Length; this diff extends it to HTTP/2 and HTTP/3 bodies without one. What grows: heap per concurrent oversize upload; bounded per request.
   Quote:
   ```
   if prior, ok := httpReq.Body.(*bufferedBody); ok && prior.complete && !prior.touched {
   	return prior.data, false, nil
   }
   ```
   Fix: In bufferBody, return an untouched prior's data as is when len(prior.data) > limit, so ReadBody truncates or rejects without a second read
   Status: skipped
   Argument: Judgement: bounded per request and the same shape already existed for bodies with Content-Length; changing reuse semantics is beyond the ask. Not applied unattended.
