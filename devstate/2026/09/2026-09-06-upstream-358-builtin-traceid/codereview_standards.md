# Standards

1. [hard] Symmetry and consistency — `pkg/captcha/captcha.go:23` — `traceIDHeader` holds `RemediationTraceIDCustomName` (the configured remediation trace response header name) while bouncer names the same role `remediationTraceIDHeader`; captcha already mirrors bouncer with `remediationCustomHeader` for the sibling knob
   → Rename the captcha field, `New` parameter, and uses to `remediationTraceIDHeader` to match bouncer and the existing `remediationCustomHeader` pairing
   Status: done
   Argument: renamed captcha field, New param, and uses to remediationTraceIDHeader.

2. [hard] Leave a trail — `pkg/bouncer/traceid.go:20` — `b.log.Warn("newRemediationTraceID: " + err.Error())` drops router name and client IP that callers already hold (`b.name`, `req.remoteIP` in `handleBanServeHTTP` / `handleRemediationServeHTTP`)
   → Pass remediation context into the generator or log at the call site with `b.name` and `req.remoteIP`
   Status: done
   Argument: newRemediationTraceID(remoteIP) warn includes name: and ip:.

3. [judgement] Smallest durable delta — `pkg/bouncer/bouncer.go:26` — adding `remediationTraceIDHeader` re-aligns the entire `Bouncer` struct and `New` literal (`appsecClient` through `traceCustomHeader`)
   → Insert the one new field without column-aligning every neighbor
   Status: skipped
   Argument: judgement — gofmt alignment of one added field; not a commandment hard miss.

4. [judgement] Duplicated Code — `tests/e2e/mock/scenarios/builtin-traceid/run.sh:24` and `tests/e2e/mock/scenarios/captcha/run.sh:25` — the same curl/awk/grep block asserts a 16-hex `X-Trace-ID` matches the body trace line
   → Extract a shared helper in `tests/e2e/mock/lib/` and call it from both scenarios
   Status: skipped
   Argument: judgement — two short scenario scripts; extract helper is extra to Bound the ask.
