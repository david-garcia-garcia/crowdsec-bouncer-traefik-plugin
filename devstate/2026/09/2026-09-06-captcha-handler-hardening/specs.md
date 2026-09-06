# Specs
IssueKey: 2026-09-06-captcha-handler-hardening
Change: captcha-handler-hardening

## FindSpecHost verdicts

| deltaId | verdict | spec-id | confidence | candidates |
| --- | --- | --- | --- | --- |
| captcha-handler | new | core_plugin_captcha_handler | high | core_plugin_middleware_instance-reclaim (captcha pages mentioned), none existing captcha leaf |
| cache-set-error | fold | core_cache_client_isolated-store | high | core_cache_client_isolated-store |

## Added

- `core_plugin_captcha_handler` — captcha page, siteverify, grace cache, template validation, retryable-error UX

## Modified

- `core_cache_client_isolated-store` — `Client.Set` returns `error`
