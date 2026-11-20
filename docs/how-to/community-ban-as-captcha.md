[Documentation](../README.md) › [How-to](README.md) › Show a community ban as a captcha

# Show a community ban as a captcha

`bouncerOriginBasedDecisionRemap` softens decisions from specific origins on this router only. For example, to show a captcha instead of a ban to IPs from the community blocklist or from one list:

```yaml
bouncerOriginBasedDecisionRemap:
  CAPI:
    ban: captcha
  lists:firehol_level1:
    ban: captcha
```

- The outer key is the origin: `CAPI` (community blocklist), `lists` (every blocklist), or `lists:<name>` (one blocklist).
- The inner key is what CrowdSec decided (`ban` or `captcha`); the value is what this router does instead (`captcha` or `pass`).
- `pass` lets the request through the decision check; AppSec still runs if enabled.
- Rules do not chain: with `ban: captcha` and `captcha: pass`, a ban becomes a captcha, not a pass.

The router needs a captcha configured; otherwise the remapped captcha is served as a ban. Two routers sharing one LAPI connection can remap differently (see [Middleware architecture](../middleware-architecture.md)).
