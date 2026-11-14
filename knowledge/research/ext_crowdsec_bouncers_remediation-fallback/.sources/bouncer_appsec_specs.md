---
url: https://docs.crowdsec.net/docs/next/contributing/specs/bouncer_appsec_specs
title: Specifications for Remediation Component and AppSec Capabilities
fetched: 2026-11-14
authority: official
---

Apply remediation / Remediation type: "Remediation property will be “ban”, “captcha” or potentially any custom string".

Apply remediation / Custom remediation: "Defaults to ignore/ban/captcha configurable field remediation_fallback". "If ignored, you don’t even need to store the decision".

Remediation priority: "Default priority order Ban then Captcha".

Stream mode / storing: "Store each decision independently, as each has its own remediation action and TTL". "When you GET you’ll receive “deleted” decisions". No rule on deleting a decision whose type the component does not support.

Page has no "whitelist" or "allow" decision type. "passthrough" exists only as lapi/appsec failure-action value.
