[Documentation](../README.md) › [How-to](README.md) › Test a ban or a captcha

# Test a ban or a captcha from the browser

`bouncerActionRules` can force a ban or a captcha when a request carries a header you choose:

```yaml
bouncerActionRules:
  - name: decision-ban
    headers:
      X-Crowdsec-Decision: "^b$"
    action: [ban]
  - name: decision-captcha
    headers:
      X-Crowdsec-Decision: "^c$"
    action: [captcha]
captchaEnabled: true
captchaProvider: hcaptcha
captchaSiteKey: FIXME
captchaSecretKey: FIXME
captchaGateSecret: FIXME
bouncerEnabled: true
```

Header values are regular expressions, so use `^b$` for an exact match (a bare `b` also matches `abc`).

Then send the header yourself, with a browser header extension, DevTools, or `curl`:

```bash
curl -D - -H "X-Crowdsec-Decision: b" https://app.example/
curl -D - -H "X-Crowdsec-Decision: c" https://app.example/
```

| Value | What you get |
| ----- | ------------ |
| `b` | Ban immediately, with status `bouncerRemediationStatusCode` (default 403). CrowdSec is not consulted. |
| `c` | A captcha, unless CrowdSec bans the client anyway (a ban always wins). Use `action: [captcha, bypass]` to skip the CrowdSec checks and always get the captcha. |
| anything else | No rule matches; the request is checked normally. |

Once you solve the captcha, you will not see it again until the grace period ends. Delete the `crowdsec_captcha_gate` cookie to get challenged again.

Clients listed in `bouncerClientTrustedIps` skip the plugin entirely, including these rules, so test from another address.

Do not leave a header that visitors can set on a public route: anyone could ban or captcha their own requests. Either have an earlier middleware set the header only for traffic you control, or use it on a staging router and remove it afterwards.

All rule conditions and actions are described in [`bouncerActionRules`](../configuration.md#bounceractionrules).

## Test with a real decision

Add a decision for your IP to the blocklist with `cscli`:

```bash
docker compose up -d crowdsec
docker exec crowdsec cscli decisions add --ip 10.0.0.10 -d 10m # this will be effective 10min
docker exec crowdsec cscli decisions remove --ip 10.0.0.10
docker exec crowdsec cscli decisions add --ip 10.0.0.10 -d 10m -t captcha # this will return a captcha challenge
docker exec crowdsec cscli decisions remove --ip 10.0.0.10 -t captcha
```

In `stream` mode, the decision applies after the next refresh (`lapiUpdateIntervalSeconds`, 60 seconds by default).
