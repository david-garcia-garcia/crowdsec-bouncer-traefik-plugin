#!/usr/bin/env pwsh

# AppSec admission gate with the shipped defaults (dynamic/waf-backoff.yml): period 30 s,
# failure budget 5, bouncerAppsecFailureAction ban. The listener is waf-5xx, which answers 503.

BeforeAll {
    . "$PSScriptRoot/TestUtils.ps1"

    $script:TraefikUrl = "http://localhost:8000"
    $script:ClientIP = "10.82.0.10"
}

Describe "CrowdSec AppSec admission gate" {
    Context "Default backoff against a failing listener" -Tag "appsec" {
        It "Should ban each admitted failure, then skip AppSec without FailureAction after the trip" {
            $since = (Get-Date).ToUniversalTime().AddSeconds(-2).ToString('yyyy-MM-ddTHH:mm:ssZ')
            $responses = foreach ($i in 1..8) {
                Test-HttpRequest -Endpoint "/waf-backoff-default" -IP $script:ClientIP -TraefikUrl $script:TraefikUrl -TimeoutSec 8
            }
            $codes = @($responses | ForEach-Object { $_.StatusCode })

            $listenerHits = @(
                (docker logs --since $since waf-5xx-test 2>&1 | Out-String) -split "`r?`n" |
                    Where-Object { $_ -match 'GET /waf-backoff-default' }
            ).Count

            # A fresh stack sees 5 bans (the default budget) then 3 skips. A rerun within the 30 s
            # cooldown starts already tripped, so it sees fewer listener calls, never more.
            $listenerHits | Should -BeLessOrEqual 5 -Because "the default budget trips the gate after 5 failures"
            @($codes | Where-Object { $_ -eq 403 }).Count | Should -Be $listenerHits -Because "every admitted failure applies the default FailureAction ban, and only those"
            $codes[-1] | Should -Be 200 -Because "after the trip AppSec is skipped and the request reaches the origin"
            $firstPass = [array]::IndexOf($codes, 200)
            @($codes[$firstPass..($codes.Count - 1)] | Where-Object { $_ -ne 200 }).Count | Should -Be 0 -Because "no request is banned once the gate skips AppSec"
            $responses[-1].Content | Should -Match "Hostname:"

            if ($listenerHits -eq 5) {
                $wait = Wait-ForCondition -Description "appsec backoff started log" -TimeoutSeconds 10 -Condition {
                    $script:BackoffLines = @(
                        (docker logs --since $since traefik-test 2>&1 | Out-String) -split "`r?`n" |
                            Where-Object { $_ -match 'crowdsec appsec backoff started' -and $_ -match 'bouncer-waf-backoff-default' }
                    )
                    return ($script:BackoffLines.Count -ge 1)
                }
                $wait.Success | Should -Be $true
                $script:BackoffLines.Count | Should -Be 1 -Because "skipped requests must not log one line each"
            }
        }
    }
}
