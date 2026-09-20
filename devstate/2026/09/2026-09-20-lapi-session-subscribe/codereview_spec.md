# Spec

1. [wrong] `README.md:157` — shared-session Note still says two stream configs on the same key from the same Traefik instance fight over one cursor; `openspec/changes/2026-09-20-lapi-session-subscribe/specs/core_plugin_lapi_reclaim-key/spec.md` Requirement: README names ignored Redis and interval SHALL say one LAPI key in this instance is one stream ticker and that Redis/interval disagreements are ignored, not isolated
   Status: done
   Argument: README same-instance sentence now says share one ticker; Redis/interval ignored
