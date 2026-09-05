# Code review
change: add-real-e2e
fixedPoint: origin/master (23ce76d3dae355fa3dc22ee7b243ca823819022a)
diff: git diff origin/master...HEAD -- . ':!devstate' ':!.cursor'

## Standards
1. [hard] Leave a trail — `tests/e2e/real/Test-Integration.ps1` — runner functions had no job comments
2. [hard] Consume before produce — runner duplicated wait/LAPI poll while TestUtils already owns Wait-ForHttpStatus / Wait-ForCondition / Invoke-CrowdSecAPI
3. [hard] Name for the scope — `Write-Error` shadowed the cmdlet
4. [judgement] Duplicated BeforeAll LAPI wait across *.Tests.ps1
5. [judgement] Wait-ForHttpStatus unused until runner reuse
6. [judgement] Unused Scenario / ExpectedStatusCode parameters on TestUtils helpers

## Spec
1. [wrong] live mode did not assert the cached allow still passes immediately after the ban
2. [wrong] stream mode only waits until forbidden, does not prove a pre-interval allow (racy vs 5s tick)
3. [wrong] captcha case accepted 429 without HTML
4. [extra] knowledge/research/ not named in proposal impact

## Security
none

## Performance
none

Standards: 3 hard + 3 judgement, worst: Consume before produce at Test-Integration.ps1
Spec: 4 findings, worst: live mode cache assertion
Security: none
Performance: none

## Applied
- Standards 1: job comments on remaining runner print helpers
- Standards 2: runner dot-sources TestUtils and uses Wait-ForHttpStatus / Wait-ForCondition / Invoke-CrowdSecAPI
- Standards 3: renamed Write-Error → Write-StepError (and Write-Warning → Write-ConsoleWarning)
- Spec 1: live test asserts 200 immediately after the ban, then waits for 403
- Spec 3: captcha case requires HTTP 200 and captcha/challenge HTML

## Recorded and skipped
- Standards 4–6: judgement; Bound the ask, not unattended hard
- Spec 2: asserting stream still allows before the 5s tick is racy; 333 also waited then asserted 403
- Spec 4: research packets came from sbs-dev-research, not an extra product requirement to drop
