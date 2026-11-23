---
url: https://github.com/traefik/traefik/tree/v3.7.19/pkg
ref: traefik/traefik@v3.7.19:pkg (grep `func (.*) Unwrap() http.ResponseWriter`)
title: Traefik ResponseWriter wrappers exposing Unwrap
fetched: 2026-11-23
authority: source
---

Non-test matches of `func (.*) Unwrap() http.ResponseWriter` under `pkg/` in v3.7.19:

- `pkg/middlewares/capture/capture.go:179` captureResponseWriter
- `pkg/middlewares/compress/compression_handler.go:383` responseWriter
- `pkg/middlewares/customerrors/custom_errors.go:307` codeCatcher, `:396` codeModifier
- `pkg/middlewares/ingressnginx/snippet/snippet.go:553` snippetResponseWriter
- `pkg/middlewares/observability/status_code.go:30` statusCodeRecorder
- `pkg/middlewares/recovery/recovery.go:91` responseWriterWrapper
- `pkg/middlewares/response_modifier.go:89` ResponseModifier
- `pkg/middlewares/retry/retry.go:397` responseWriter
- `pkg/plugins/external.go:92` entryWriter, `:143` exitWriter
- `pkg/healthcheck/healthcheck.go:486` codeCatcher
- `pkg/server/service/loadbalancer/failover/response_writer.go:78` responseWriter

Structs under `pkg/` that hold an `http.ResponseWriter` without `Unwrap`: `pkg/proxy/fast/proxy.go` writeFlusher and `pkg/server/service/loadbalancer/mirror/mirror.go` (field `rw`). Both sit at the service/proxy end, after the middlewares.
