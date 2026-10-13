# Delivery

## Motivation

When Traefik rebuilds a captcha-owning middleware, captcha Open reclaims by OwnershipKey: middleware name plus instance-owned captcha knobs (provider, keys, files, timeouts, template, gate, custom paths, and the recaptcha-enterprise knobs). Create is the only path that stores the constructor logger on the Client. Reclaim Wakes that Client; bindIdentity does not replace the logger.

A rebuild that changes only log config still hashes the same Open key. The operator example is `logLevel` from `trace` to `debug`; `logFilePath` and `logFormat` are omitted the same way. Those three knobs already freeze into one logger at middleware New, then Open reclaims the prior Client, so captcha keeps the old TRACE logger (or the old file and format).

Left alone, a log-config-only rebuild does not change captcha logging. TRACE stays noisy after the operator turned it down; DEBUG never appears after they turned it up. The same stale logger remains until some other ownership knob changes or the process disposes that incarnation.

Priority: P2 — real operator pain, with a workaround or limited blast radius

## Implementation

The captcha ownership payload now hashes `LogLevel`, `LogFilePath`, and `LogFormat` as stored on Config, so OwnershipKey forks when any of those knobs change. A log-config-only rebuild therefore misses the old key; Open creates and the constructor stores the rebuilt logger. Reclaim, bindIdentity, and logger construction stay as they were. The previous incarnation follows the existing table path: Sleep, grace, Close; the captcha instance alias remaps to the new Client. Coverage is key-inequality for each of the three knobs. The instance-slots ownership Open-key SHALL now includes `logLevel`, `logFilePath`, and `logFormat`.

## What this changes
**Operators.** Changing `logLevel`, `logFilePath`, or `logFormat` on a captcha owner now starts a new captcha client instead of waking the previous one.
**Admin users.** None.
**Developers.** Captcha `OwnershipKey` now includes those three log knobs, so a log-config-only rebuild is a different Open key, and the instance-slots SHALL lists them.
**End users.** None.
