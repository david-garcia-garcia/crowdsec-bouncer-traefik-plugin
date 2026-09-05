#!/usr/bin/env pwsh

# Range and header-mapped CrowdSec scopes against a live LAPI.

BeforeAll {
    . "$PSScriptRoot/TestUtils.ps1"

    $script:TraefikUrl = "http://localhost:8000"
    $script:CrowdSecApiUrl = "http://localhost:8081"
    $script:ApiKey = "40796d93c2958f9e58345514e67740e5"

    $script:NoneRange = "10.55.0.0/16"
    $script:NoneInside = "10.55.1.8"
    $script:NoneOutside = "10.56.1.8"
    $script:StreamRange = "10.57.0.0/16"
    $script:StreamInside = "10.57.1.8"
    $script:HeaderIP = "172.19.0.80"

    $result = Wait-ForCondition -Description "CrowdSec LAPI to be ready" -TimeoutSeconds 60 -RetryIntervalSeconds 2 -Condition {
        Invoke-CrowdSecAPI -Endpoint "/v1/decisions?limit=1" -TimeoutSec 5 -ApiKey $script:ApiKey -CrowdSecApiUrl $script:CrowdSecApiUrl
        return $true
    }

    if (-not $result.Success) {
        throw "❌ CrowdSec LAPI failed to become ready"
    }
}

Describe "CrowdSec Range and header-mapped scopes" {

    Context "Range in none mode" -Tag "scopes" {
        BeforeEach {
            Clear-TraefikAccessLogs
            Remove-AllTestDecisions
        }

        It "Should block an IP inside a Range decision and allow one outside" {
            Add-TestRangeDecision -Range $script:NoneRange -Type "ban"

            $blocked = Test-HttpRequest -Endpoint "/scope-none" -IP $script:NoneInside -TraefikUrl $script:TraefikUrl
            $blocked.StatusCode | Should -BeIn @(403, 429)

            $allowed = Test-HttpRequest -Endpoint "/scope-none" -IP $script:NoneOutside -TraefikUrl $script:TraefikUrl
            $allowed.StatusCode | Should -Be 200
        }
    }

    Context "Range in stream mode" -Tag "scopes" {
        BeforeEach {
            Clear-TraefikAccessLogs
            Remove-AllTestDecisions
        }

        It "Should block an IP inside a Range decision after the stream poll" {
            Add-TestRangeDecision -Range $script:StreamRange -Type "ban"

            $result = Wait-ForCondition -Description "Stream mode to block Range $($script:StreamRange)" -TimeoutSeconds 30 -RetryIntervalSeconds 2 -Condition {
                $response = Test-HttpRequest -Endpoint "/scope-stream" -IP $script:StreamInside -TraefikUrl $script:TraefikUrl
                return ($response.StatusCode -in @(403, 429))
            }
            $result.Success | Should -Be $true -Because "Stream mode should match Range via range-index"

            Remove-TestRangeDecision -Range $script:StreamRange

            $result = Wait-ForCondition -Description "Stream mode to allow IP after Range delete" -TimeoutSeconds 30 -RetryIntervalSeconds 2 -Condition {
                $response = Test-HttpRequest -Endpoint "/scope-stream" -IP $script:StreamInside -TraefikUrl $script:TraefikUrl
                return ($response.StatusCode -eq 200)
            }
            $result.Success | Should -Be $true -Because "Stream mode should drop the Range after delete"
        }
    }

    Context "Country header in none mode" -Tag "scopes" {
        BeforeEach {
            Clear-TraefikAccessLogs
            Remove-AllTestDecisions
        }

        It "Should block when the mapped Country header matches and skip when it does not" {
            Add-TestScopeDecision -Scope "Country" -Value "FR" -Type "ban"

            $blocked = Test-HttpRequest -Endpoint "/scope-none" -IP $script:HeaderIP -TraefikUrl $script:TraefikUrl -ExtraHeaders @{ "CF-IPCountry" = "fr" }
            $blocked.StatusCode | Should -BeIn @(403, 429)

            $other = Test-HttpRequest -Endpoint "/scope-none" -IP $script:HeaderIP -TraefikUrl $script:TraefikUrl -ExtraHeaders @{ "CF-IPCountry" = "DE" }
            $other.StatusCode | Should -Be 200

            $missing = Test-HttpRequest -Endpoint "/scope-none" -IP $script:HeaderIP -TraefikUrl $script:TraefikUrl
            $missing.StatusCode | Should -Be 200
        }
    }

    Context "Country header in stream mode" -Tag "scopes" {
        BeforeEach {
            Clear-TraefikAccessLogs
            Remove-AllTestDecisions
        }

        It "Should block after the stream poll when the mapped Country header matches" {
            Add-TestScopeDecision -Scope "Country" -Value "US" -Type "ban"

            $result = Wait-ForCondition -Description "Stream mode to block Country US" -TimeoutSeconds 30 -RetryIntervalSeconds 2 -Condition {
                $response = Test-HttpRequest -Endpoint "/scope-stream" -IP $script:HeaderIP -TraefikUrl $script:TraefikUrl -ExtraHeaders @{ "CF-IPCountry" = "us" }
                return ($response.StatusCode -in @(403, 429))
            }
            $result.Success | Should -Be $true -Because "Stream scopes= must include Country"
        }
    }
}
