# Spec

1. [wrong] Nil trusted-IP attrs — `pkg/bouncer/bouncer.go:148` — JSON slog emits `null` for a nil `[]string`; `openspec/changes/init-log-component/specs/std_go_logger_debug-attrs/spec.md` Requirement: Construct-time Bouncer initialized lists trusted IPs — Empty or nil slices SHALL still appear as empty lists
   Fix: Coerce nil trusted-IP config slices to empty lists on that DEBUG line
   Status: done
   Argument: Coerced nil trusted-IP config slices to empty lists on DEBUG `Bouncer initialized` in `pkg/bouncer/bouncer.go`; added `TestNew_BouncerInitializedNilTrustedIPs`.
