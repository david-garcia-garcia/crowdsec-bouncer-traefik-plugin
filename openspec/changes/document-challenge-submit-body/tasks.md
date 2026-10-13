## 1. README

- [ ] 1.1 In the AppSec / bot-detection paragraph, state that `/crowdsec-internal/challenge/submit` must reach AppSec with the full form, the default 10MB is enough, a smaller positive limit cuts the proof short, and `0` means no limit (the whole body is sent). Do not write that `0` sends nothing.
- [ ] 1.2 On the **AppsecBodyLimit** key, state the same facts. Keep the existing default `10485760` / 10MB and “`0` means no limit” meaning (whole body sent).

## 2. Verify

- [ ] 2.1 Re-run `Test_appsecQuery_zeroBodyLimitForwardsPost`. Do not change that test or add a duplicate.
