# Unknown decision type fallback

How official CrowdSec remediation components handle a LAPI decision whose `type` they do not support, on add (`new`) and on delete (`deleted`).

Fetched: 2026-11-14. Pins: `github.com/crowdsecurity/lua-cs-bouncer@4aad1dfa653d9d96fb5c0114ae930eb2353214c8`, `github.com/crowdsecurity/cs-firewall-bouncer@a09363eebbd5ba90e8aea205728bf26194d11bf2`. Related: decision `type` is free text (`ban`, `captcha` "or something custom") — see `ext_crowdsec_decisions_scopes/`. Apply order of `deleted` vs `new` — see `ext_crowdsec_bouncers_stream-apply/`. LAPI/AppSec outage fallback (a different knob) — see `ext_crowdsec_bouncers_failure-action/`.

**Summary.** The spec gives a component three choices for an unknown type: ignore, ban, captcha (`remediation_fallback`). lua-cs-bouncer (the reference) maps any type other than `ban`/`captcha`/`challenge` to `FALLBACK_REMEDIATION` (`ban` | `captcha`) at request time and deletes by IP/range key with no type check. cs-firewall-bouncer has no fallback: it drops unsupported types on add **and** on delete (`supported_decisions_types`, default `[ban]`).

## Spec: remediation_fallback

- "Remediation property will be “ban”, “captcha” or potentially any custom string". Owner: [bouncer specs](https://docs.crowdsec.net/docs/next/contributing/specs/bouncer_appsec_specs). Extract: `.sources/bouncer_appsec_specs.md`
- Custom remediation: "Defaults to ignore/ban/captcha configurable field remediation_fallback". Same owner.
- Exact ignore sentence: "If ignored, you don’t even need to store the decision". Same owner.
- The spec lists the three values but does not pick a single default value. It says nothing about how deletes of an ignored type are handled (consistent with "don't store": nothing to delete). Same owner; the delete part is `authority: inference` from absence.
- Default priority "Ban then Captcha". Same owner.

## Nginx docs: FALLBACK_REMEDIATION

- Values "ban | captcha"; sample `FALLBACK_REMEDIATION=ban`. "The fallback remediation is applied if the component receives a decision with an unknown remediation." Owner: [nginx bouncer](https://docs.crowdsec.net/u/bouncers/nginx). Extract: `.sources/nginx-bouncer.md`
- `BOUNCING_ON_TYPE` = all | ban | captcha, sample `all`: "If you choose `ban` only and receive a decision with `captcha` as remediation, the component will skip the decision." Same owner.
- No `ignore` value in docs. Ignoring is done with `BOUNCING_ON_TYPE` (type not bounced at all), not with the fallback.

## lua-cs-bouncer (`@4aad1dfa`)

Known types: `ban`, `captcha`, `challenge` (challenge needs an AppSec response body; without one it logs "challenge remediation for '<ip>' but no response data, falling back to ban").

**Request time.** `lib/crowdsec.lua` L906-916:

```lua
if runtime.fallback ~= "" then
  -- if we can't use captcha, fallback
  if remediation == "captcha" and captcha_ok == false then remediation = runtime.fallback end
  -- if remediation is not supported, fallback
  if remediation ~= "captcha" and remediation ~= "ban" and remediation ~= "challenge" then
    remediation = runtime.fallback
  end
end
```

Owner: [crowdsec.lua](https://github.com/crowdsecurity/lua-cs-bouncer/blob/4aad1dfa653d9d96fb5c0114ae930eb2353214c8/lib/crowdsec.lua#L906-L916). Extract: `.sources/crowdsec.lua.md`

**FALLBACK_REMEDIATION values and default.** Accepted `{'captcha', 'ban'}`; anything else logs "unsupported value '<v>' for variable 'FALLBACK_REMEDIATION'. Using default value 'ban' instead". The key is **absent** from `default_values` (L8-37), so the in-code default when the line is missing is unset, not `ban`; the shipped example and the docs set `FALLBACK_REMEDIATION=ban`. Owner: [config.lua](https://github.com/crowdsecurity/lua-cs-bouncer/blob/4aad1dfa653d9d96fb5c0114ae930eb2353214c8/lib/plugins/crowdsec/config.lua#L128-L131); [config_example.conf](https://github.com/crowdsecurity/lua-cs-bouncer/blob/4aad1dfa653d9d96fb5c0114ae930eb2353214c8/config_example.conf#L9-L11). Extracts: `.sources/config.lua.md`, `.sources/config_example.conf.md`. What an unset fallback does at request time is `authority: inference` from `crowdsec.lua` L906-L967, not tested: nil replaces the remediation, none of the ban/challenge/captcha branches match, and the handler ends at `ngx.exit(ngx.DECLINED)` (request passes).

**Add (stream).** `new` decisions are stored only when `BOUNCING_ON_TYPE == decision.type` or `BOUNCING_ON_TYPE == "all"` (L279). In-code default `BOUNCING_ON_TYPE = "ban"` (config.lua L14); example/docs use `all`. So with the in-code default a custom type is never stored (= ignore); with `all` it is stored with its raw type and mapped to the fallback at request time. Owner: [stream.lua](https://github.com/crowdsecurity/lua-cs-bouncer/blob/4aad1dfa653d9d96fb5c0114ae930eb2353214c8/lib/plugins/crowdsec/stream.lua#L273-L299); [config.lua](https://github.com/crowdsecurity/lua-cs-bouncer/blob/4aad1dfa653d9d96fb5c0114ae930eb2353214c8/lib/plugins/crowdsec/config.lua#L6-L14). Extracts: `.sources/stream.lua.md`, `.sources/config.lua.md`

**Add (live).** Same `BOUNCING_ON_TYPE` test on the first decision returned by `GET /v1/decisions?ip=` (L130). Owner: [live.lua](https://github.com/crowdsecurity/lua-cs-bouncer/blob/4aad1dfa653d9d96fb5c0114ae930eb2353214c8/lib/plugins/crowdsec/live.lua#L130-L134). Extract: `.sources/live.lua.md`

**Delete (stream).** `deleted` loop (L238-L270) deletes `decision_cache/<ip-or-range key>` for every entry, **no type check**; for `captcha` it also clears `captcha_<value>` state. Owner: [stream.lua](https://github.com/crowdsecurity/lua-cs-bouncer/blob/4aad1dfa653d9d96fb5c0114ae930eb2353214c8/lib/plugins/crowdsec/stream.lua#L238-L270). Extract: `.sources/stream.lua.md`

## cs-firewall-bouncer (`@a09363ee`)

No fallback. A type not in `supported_decisions_types` (lower-cased compare) is skipped on both halves of the stream:

- delete, `cmd/root.go` L68-L69: `log.Debugf("decisions for ip '%s' will not be deleted because its type is '%s'", *d.Value, *d.Type)` then `continue`. Owner: [root.go](https://github.com/crowdsecurity/cs-firewall-bouncer/blob/a09363eebbd5ba90e8aea205728bf26194d11bf2/cmd/root.go#L64-L71)
- add, L108-L109: `log.Debugf("decisions for ip '%s' will not be added because its type is '%s'", *d.Value, *d.Type)` then `continue`. Owner: [root.go](https://github.com/crowdsecurity/cs-firewall-bouncer/blob/a09363eebbd5ba90e8aea205728bf26194d11bf2/cmd/root.go#L104-L111)

Extract: `.sources/root.go.md`

Default: empty list becomes `[]string{"ban"}` (`pkg/cfg/config.go` L109-L110); shipped YAML `supported_decisions_types: [ban]` (L20-L21). Owners: [config.go](https://github.com/crowdsecurity/cs-firewall-bouncer/blob/a09363eebbd5ba90e8aea205728bf26194d11bf2/pkg/cfg/config.go#L109-L110), [crowdsec-firewall-bouncer.yaml](https://github.com/crowdsecurity/cs-firewall-bouncer/blob/a09363eebbd5ba90e8aea205728bf26194d11bf2/config/crowdsec-firewall-bouncer.yaml#L20-L21). Extracts: `.sources/config.go.md`, `.sources/crowdsec-firewall-bouncer.yaml.md`. The firewall docs page has no `supported_decisions_types` entry ([firewall](https://docs.crowdsec.net/u/bouncers/firewall), fetched 2026-11-14).

## Delete symmetry (what a new component must decide)

| component | unknown type on add | unknown type on delete |
|---|---|---|
| spec | ignore / ban / captcha (`remediation_fallback`); ignored → need not store | not stated |
| lua-cs-bouncer | stored iff `BOUNCING_ON_TYPE` matches or `all`; mapped to `FALLBACK_REMEDIATION` at request | deleted by IP/range key, type not checked |
| cs-firewall-bouncer | skipped (Debug log) | skipped (Debug log), same filter |

lua keeps one cache value per IP/range key and deletes by key without a type check, so a `deleted` entry of any type clears whatever decision sits on that key. The firewall filters both halves with the same list, so an unsupported-type delete never removes a supported-type entry. Both points are `authority: inference` from the files above.
