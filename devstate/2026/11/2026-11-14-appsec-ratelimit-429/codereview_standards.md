# Standards

1. [judgement] Leave a trail — `knowledge/devdocs/core_plugin_middleware_ban-page.md:43` — the Gotcha "All ban call sites inherit the one Set on `handleBanServeHTTP`" is left unchanged, but this diff moved the `Cache-Control`/`Content-Type`/`WriteHeader` writes into `handleBanStatusServeHTTP`, and the AppSec ban no longer goes through `handleBanServeHTTP`; the statement is no longer true
   Fix: Reword to "All ban call sites inherit the one Set on `handleBanStatusServeHTTP` (`handleBanServeHTTP` forwards `remediationStatusCode` to it)"
   Status: done
   Argument: Reworded the Gotcha to name `handleBanStatusServeHTTP` as the one Set, with `handleBanServeHTTP` forwarding `remediationStatusCode`.
