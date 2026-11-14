# Allowlists and parser whitelists

How CrowdSec lets traffic through (parser / postoverflow whitelists, centralized LAPI allowlists), when each acts relative to decision creation, and whether "allow" / "whitelist" exist as decision types.

Fetched: 2026-11-14. Pin: `github.com/crowdsecurity/crowdsec@e20782bb3c532f0b9b9a469c0bdaa003588ec8e5`. Related: decision `type` vocabulary: `ext_crowdsec_decisions_scopes/`. How expired decisions reach bouncers in `deleted`: `ext_crowdsec_lapi_stream-cursor/`, `ext_crowdsec_bouncers_stream-apply/`. Unknown-type handling in bouncers: `ext_crowdsec_bouncers_remediation-fallback/`.

**Summary.** Allowing traffic is done upstream of decisions. Parser whitelists drop events; postoverflow whitelists drop triggered overflows; LAPI allowlists drop alerts, blocklist entries and cscli adds, and (source) also expire matching decisions that already exist. No owner defines a decision `type` of `whitelist` or `allow`; a bouncer never receives an "allow" decision to act on.

## Three whitelist mechanisms

- "There are three whitelist types in CrowdSec:" Parser, Postoverflow, AllowLists. Owner: [whitelists](https://docs.crowdsec.net/u/getting_started/post_installation/whitelists). Extract: `.sources/whitelists.md`
- Parser: "Parser-based whitelists are applied while the event is being enriched." "They prevent the log line from reaching the scenario stage". Same owner.
- Postoverflow: "Postoverflow whitelists are applied after a scenario triggers." Same owner.
- AllowLists: "AllowLists let you centrally manage whitelisted IP addresses and CIDR ranges using `cscli`." "This is the preferred method". Same owner.
- LAPI allowlists: "The AllowLists feature in CrowdSec lets you manage IP-based allowlists at the LAPI level." "AllowLists are limited to IP/range-based rules." Owner: [centralized allowlists](https://docs.crowdsec.net/docs/next/local_api/centralized_allowlists). Extract: `.sources/centralized_allowlists.md`

## When they act relative to a decision

### Before a decision exists

- Parser and postoverflow whitelists act on events / overflows, so the alert and its decision are never produced. Owner: [whitelists](https://docs.crowdsec.net/u/getting_started/post_installation/whitelists).
- Allowlist table. Owner: [centralized allowlists](https://docs.crowdsec.net/docs/next/local_api/centralized_allowlists).
  - Local alerts: "Alert is dropped, action logged." (real time)
  - Blocklists: "IP is removed before database insertion" (real time)
  - WAF (AppSec): "Request bypasses AppSec entirely, action logged." ("Refreshed every minute")
  - Bot Detection (AppSec): "Request bypasses Bot detection entirely." ("Refreshed every minute")
  - cscli: "Decision is blocked unless special flag is provided" (real time)
- Source confirms the alert path: LAPI `isAllowListed` checks scope `Ip`/`Range` only ("Allowlist only works for IP/range") and logs "alert source %s is allowlisted by %s, skipping". Alerts that already carry decisions (cscli) skip this check. Owner: [alerts.go](https://github.com/crowdsecurity/crowdsec/blob/e20782bb3c532f0b9b9a469c0bdaa003588ec8e5/pkg/apiserver/controllers/v1/alerts.go#L128-L145), L181-L182. Extract: `.sources/alerts.go.md`
- cscli: "%s is allowlisted by item %s, use --bypass-allowlist to add the decision anyway"; flag `--bypass-allowlist` / `-B`. Owner: [decisions.go](https://github.com/crowdsecurity/crowdsec/blob/e20782bb3c532f0b9b9a469c0bdaa003588ec8e5/cmd/crowdsec-cli/clidecision/decisions.go#L301-L306). Extract: `.sources/decisions.go.md`

### Existing decisions (docs and source differ by mechanism)

- Docs, whitelists page, general statement: "Whitelisting an IP address or event will prevent the events from triggering new decisions" "however, any existing decisions will still be applied." "You must manually remove the decisions by running:" `cscli decisions delete`. Owner: [whitelists](https://docs.crowdsec.net/u/getting_started/post_installation/whitelists). Holds for parser/postoverflow whitelists (they only see events).
- Allowlist docs do not say what happens to existing decisions. Owners: [centralized allowlists](https://docs.crowdsec.net/docs/next/local_api/centralized_allowlists); [cscli allowlists add](https://docs.crowdsec.net/docs/next/cscli/cscli_allowlists_add) (extract `.sources/cscli_allowlists_add.md`).
- Source `@e20782bb`: allowlist changes **expire** matching decisions. `ApplyAllowlistsToExistingDecisions`, comment "Soft delete (set expiration to now) all decisions that matches any allowlist", runs `Decision.Update().SetUntil(now)` on every still-active decision whose IP range is inside, equal to, or contains an active allowlist item. No filter on decision type. Owner: [allowlists.go L404-L405](https://github.com/crowdsecurity/crowdsec/blob/e20782bb3c532f0b9b9a469c0bdaa003588ec8e5/pkg/database/allowlists.go#L404-L405) and [L529-L536](https://github.com/crowdsecurity/crowdsec/blob/e20782bb3c532f0b9b9a469c0bdaa003588ec8e5/pkg/database/allowlists.go#L529-L536). Extract: `.sources/allowlists.go.md`
- Callers: `cscli allowlists add` (prints "%d decisions deleted by allowlists"), `cscli allowlists import`, CAPI pull that pulled allowlists, PAPI console force-pull (log "deleted %d decisions from allowlists"). Owners: [cliallowlists/allowlists.go](https://github.com/crowdsecurity/crowdsec/blob/e20782bb3c532f0b9b9a469c0bdaa003588ec8e5/cmd/crowdsec-cli/cliallowlists/allowlists.go#L514-L520), [import.go](https://github.com/crowdsecurity/crowdsec/blob/e20782bb3c532f0b9b9a469c0bdaa003588ec8e5/cmd/crowdsec-cli/cliallowlists/import.go#L175-L182), [apic.go](https://github.com/crowdsecurity/crowdsec/blob/e20782bb3c532f0b9b9a469c0bdaa003588ec8e5/pkg/apiserver/apic.go#L785-L793), [papi_cmd.go](https://github.com/crowdsecurity/crowdsec/blob/e20782bb3c532f0b9b9a469c0bdaa003588ec8e5/pkg/apiserver/papi_cmd.go#L283-L289). Extracts: `.sources/cliallowlists.go.md`, `.sources/import.go.md`, `.sources/apic.go.md`, `.sources/papi_cmd.go.md`
- Ranking (official vs source): follow source for this version. The docs sentence is right for parser/postoverflow whitelists and silent for allowlists. The CrowdSec release that introduced the expiry was not determined (shallow clone, no tags).
- Consequence for bouncers: an expired decision (`until < now`) is what LAPI returns in the stream `deleted` array, so a bouncer sees a new allowlist entry as an ordinary delete of the original `ban`/`captcha` decision, never as a new decision. `authority: inference`, joining `allowlists.go` (SetUntil now) with the `deleted` query documented in `ext_crowdsec_lapi_stream-cursor/` and `ext_crowdsec_bouncers_stream-apply/`. Not tested end to end.

## No "whitelist" or "allow" decision type

`authority: inference`. No owner states "there is no allow type"; no owner read defines one.

- LAPI swagger Decision `type`: "the type of decision, might be 'ban', 'captcha' or something custom." Owner: [localapi_swagger.yaml L1105](https://github.com/crowdsecurity/crowdsec/blob/e20782bb3c532f0b9b9a469c0bdaa003588ec8e5/pkg/models/localapi_swagger.yaml#L1105); extract already in `ext_crowdsec_decisions_scopes/`.
- Bouncer spec: "Remediation property will be “ban”, “captcha” or potentially any custom string". Owner: [bouncer specs](https://docs.crowdsec.net/docs/next/contributing/specs/bouncer_appsec_specs); extract in `ext_crowdsec_bouncers_remediation-fallback/.sources/bouncer_appsec_specs.md`.
- `cscli decisions add --type` help: "Decision type (ie. ban,captcha,throttle)", default `ban`. Owner: [decisions.go L394](https://github.com/crowdsecurity/crowdsec/blob/e20782bb3c532f0b9b9a469c0bdaa003588ec8e5/cmd/crowdsec-cli/clidecision/decisions.go#L394). Extract: `.sources/decisions.go.md`
- Only decision-type constant: `DecisionTypeBan = "ban"`. Grep of non-test Go under `pkg/` and `cmd/` found no decision `Type` of `whitelist` / `allow` / `allowlist`. Owner: [constants.go L20](https://github.com/crowdsecurity/crowdsec/blob/e20782bb3c532f0b9b9a469c0bdaa003588ec8e5/pkg/types/constants.go#L20). Extract: `.sources/constants.go.md`
- `"allow"` exists only as the AppSec per-request verdict (`AllowRemediation`, `DefaultPassAction`), next to ban/captcha/challenge. It is not a LAPI decision. Owner: [appsec.go L97-L102](https://github.com/crowdsecurity/crowdsec/blob/e20782bb3c532f0b9b9a469c0bdaa003588ec8e5/pkg/appsec/appsec.go#L97-L102). Extract: `.sources/appsec.go.md`. AppSec protocol detail: `ext_crowdsec_appsec_protocol/`.
- Because `type` is free text, an operator can still run `cscli decisions add --type allow`; LAPI stores and serves it like any custom type, and official bouncers then treat it as unknown (fallback or skip). `authority: inference` from the swagger text plus `ext_crowdsec_bouncers_remediation-fallback/`.
