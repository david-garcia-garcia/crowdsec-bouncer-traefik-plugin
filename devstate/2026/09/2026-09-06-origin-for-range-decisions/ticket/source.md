# origin-for-range-decisions

Goal: Range-only drops and Lookup origin match Ip/header (`t`/`c` + U+001F + MetricsOrigin).

Today: `connection_stream` writes `rangeUpserts[cidr] = RemediationValue(type)` (letter). Blob `cidr=t`. `RangeMembership` is two boolean Helpers; `Remediation()` returns bare `t`/`c`. `LookupCachedRemediation` then has empty origin for Range-only. Gauge already has origin via `rememberActiveDecision` (leave that).

Do: at stream apply, upsert `RemediationWithOrigin(letter, MetricsOrigin(origin, scenario))`. `parseIndexLine` already splits on first `=`; suffix has no `=`. Bare `cidr=t` must still match. `MembershipFromIndex` / `Remediation` must return the suffixed string of the **winning** CIDR (ban over captcha; if several bans contain the IP, pick one rule and test it — Helper is boolean today, no payload). `PreferRemediation` already keeps a ban’s suffix. Redis stays **one** `range-index` key. Do not add per-CIDR keys or per-host keys.

Spec/docs: `core_plugin_lapi_usage-metrics` Range-only origin; `core_plugin_decisions_scopes` blob MAY carry suffix; usage packet gotcha that says range-index stays letter-only.

Tests: blob round-trip suffix; Range-only lookup origin; old letter-only line still bans.
