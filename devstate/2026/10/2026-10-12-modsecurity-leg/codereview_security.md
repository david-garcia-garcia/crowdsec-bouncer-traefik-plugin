# Security

1. [hard] Secrets in logs — `pkg/modsecurity/inspect.go:127` — sidecar `Do` error logs operator `modsecUrl` plus client `RequestURI` (query; userinfo if present)
   Fix: Log sidecar host and that the hop failed, not `err`; redact query and userinfo
   Status: open
   Argument: none.
