#!/usr/bin/env pwsh

# Live mode from upstream PR 333: first allow is cached, then LAPI is re-queried
# after defaultDecisionSeconds.

BeforeAll {
    . "$PSScriptRoot/TestUtils.ps1"

    $script:TraefikUrl = "http://localhost:8000"
    $script:CrowdSecApiUrl = "http://localhost:8081"
    $script:ApiKey = "40796d93c2958f9e58345514e67740e5"
    $script:LiveBannedIP = "172.19.0.20"
    $script:LiveCleanIP = "172.19.0.21"

    $result = Wait-ForCondition -Description "CrowdSec LAPI to be ready" -TimeoutSeconds 60 -RetryIntervalSeconds 2 -Condition {
        Invoke-CrowdSecAPI -Endpoint "/v1/decisions?limit=1" -TimeoutSec 5 -ApiKey $script:ApiKey -CrowdSecApiUrl $script:CrowdSecApiUrl
        return $true
    }
    if (-not $result.Success) {
        throw "CrowdSec LAPI failed to become ready"
    }
}

Describe "CrowdSec Bouncer Live Mode Tests" {
    Context "Live mode cache then re-query" -Tag "live" {
        BeforeEach {
            Clear-TraefikAccessLogs
            Remove-AllTestDecisions
        }

        It "Should keep the first allow cached until defaultDecisionSeconds, then see a new ban" {
            $allow = Test-HttpRequest -Endpoint "/live" -IP $script:LiveBannedIP -TraefikUrl $script:TraefikUrl
            $allow.StatusCode | Should -Be 200

            Add-TestDecision -IP $script:LiveBannedIP -Type "ban"

            $stillCached = Test-HttpRequest -Endpoint "/live" -IP $script:LiveBannedIP -TraefikUrl $script:TraefikUrl
            $stillCached.StatusCode | Should -Be 200 -Because "live mode must keep the cached allow until defaultDecisionSeconds expires"

            $blocked = Wait-ForCondition -Description "live mode to re-query LAPI and block $($script:LiveBannedIP)" -TimeoutSeconds 15 -RetryIntervalSeconds 1 -Condition {
                $response = Test-HttpRequest -Endpoint "/live" -IP $script:LiveBannedIP -TraefikUrl $script:TraefikUrl
                return ($response.StatusCode -in @(403, 429))
            }
            $blocked.Success | Should -Be $true -Because "After the cached allow expires, live mode must see the ban"

            $clean = Test-HttpRequest -Endpoint "/live" -IP $script:LiveCleanIP -TraefikUrl $script:TraefikUrl
            $clean.StatusCode | Should -Be 200
        }
    }
}
