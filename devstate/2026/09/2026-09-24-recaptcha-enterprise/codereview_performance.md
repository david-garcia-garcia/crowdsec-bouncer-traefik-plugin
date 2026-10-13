# Performance

1. [hard] Unbounded payload or download — `pkg/captcha/assessments.go:104` — `io.ReadAll(res.Body)` has no byte cap; assessments 2xx body size grows the heap on each enterprise captcha `Validate`
   Fix: Cap the read with `io.LimitReader` before `ReadAll`
   Status: done
   Argument: assessments 2xx body is capped with LimitReader at 64KiB.
