#!/usr/bin/env pwsh

# CrowdSec allow decisions are a whitelist: an IP with type=allow must pass even
# when a ban for the same IP exists. cscli writes both; the plugin must not let
# the ban win.

BeforeAll {
    . "$PSScriptRoot/TestUtils.ps1"

    $script:TraefikUrl = "http://localhost:8000"
    $script:CrowdSecApiUrl = "http://localhost:8081"
    $script:ApiKey = "40796d93c2958f9e58345514e67740e5"
    $script:NoneIP = "10.82.0.10"
    $script:StreamIP = "10.82.0.11"

    $result = Wait-ForCondition -Description "CrowdSec LAPI to be ready" -TimeoutSeconds 60 -RetryIntervalSeconds 2 -Condition {
        Invoke-CrowdSecAPI -Endpoint "/v1/decisions?limit=1" -TimeoutSec 5 -ApiKey $script:ApiKey -CrowdSecApiUrl $script:CrowdSecApiUrl
        return $true
    }
    if (-not $result.Success) {
        throw "CrowdSec LAPI failed to become ready"
    }
}

Describe "CrowdSec allow decisions" {
    Context "Allow is a whitelist" -Tag "allow" {
        BeforeEach {
            Clear-TraefikAccessLogs
            Remove-AllTestDecisions
        }

        It "Should not remediate an IP that only has an allow decision" {
            Add-TestDecision -IP $script:NoneIP -Type "allow"

            $response = Test-HttpRequest -Endpoint "/whoami" -IP $script:NoneIP -TraefikUrl $script:TraefikUrl
            $response.StatusCode | Should -Be 200 -Because "type=allow is not a ban or captcha"
        }

        It "Should let an allow decision whitelist a banned IP in none mode" {
            Add-TestDecision -IP $script:NoneIP -Type "ban"
            Add-TestDecision -IP $script:NoneIP -Type "allow"

            $banned = Test-HttpRequest -Endpoint "/whoami" -IP $script:NoneIP -TraefikUrl $script:TraefikUrl
            $banned.StatusCode | Should -Be 200 -Because "CrowdSec type=allow must whitelist the same IP over a ban; a 403 means strongestLiveDecision picked ban and ignored allow"
        }

        It "Should let an allow decision whitelist a banned IP in stream mode" {
            Add-TestDecision -IP $script:StreamIP -Type "ban"
            Add-TestDecision -IP $script:StreamIP -Type "allow"

            $blocked = Wait-ForCondition -Description "stream to see the ban for $($script:StreamIP)" -TimeoutSeconds 30 -RetryIntervalSeconds 2 -Condition {
                $response = Test-HttpRequest -Endpoint "/stream" -IP $script:StreamIP -TraefikUrl $script:TraefikUrl
                return ($response.StatusCode -in @(403, 429))
            }
            if ($blocked.Success) {
                $whitelisted = Wait-ForCondition -Description "stream to honour allow over ban for $($script:StreamIP)" -TimeoutSeconds 30 -RetryIntervalSeconds 2 -Condition {
                    $response = Test-HttpRequest -Endpoint "/stream" -IP $script:StreamIP -TraefikUrl $script:TraefikUrl
                    return ($response.StatusCode -eq 200)
                }
                $whitelisted.Success | Should -Be $true -Because "stream must drop the ban when type=allow is present; a leftover 403 means allow was treated as an unknown stream type"
            }
            else {
                $response = Test-HttpRequest -Endpoint "/stream" -IP $script:StreamIP -TraefikUrl $script:TraefikUrl
                $response.StatusCode | Should -Be 200 -Because "if stream never applied the ban, allow already won"
            }
        }
    }
}
