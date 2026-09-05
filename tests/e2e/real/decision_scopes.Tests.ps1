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
    $script:PublicIP = "8.8.8.8"

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

    Context "Country via geoblock enrich in none mode" -Tag "scopes" {
        BeforeEach {
            Clear-TraefikAccessLogs
            Remove-AllTestDecisions
        }

        It "Should block a public IP after CrowdSec bans the enriched country" {
            $probe = Test-HttpRequest -Endpoint "/scope-none" -IP $script:PublicIP -TraefikUrl $script:TraefikUrl
            $probe.StatusCode | Should -Be 200
            $country = Get-WhoamiCountryCode -Content $probe.Content
            $country | Should -Match '^[A-Z]{2}$' -Because "geoblock must enrich X-IPCountry for a public IP; body was: $($probe.Content)"
            $country | Should -Not -BeIn @("XX", "T1")

            Add-TestScopeDecision -Scope "Country" -Value $country -Type "ban"

            $blocked = Test-HttpRequest -Endpoint "/scope-none" -IP $script:PublicIP -TraefikUrl $script:TraefikUrl
            $blocked.StatusCode | Should -BeIn @(403, 429)

            $private = Test-HttpRequest -Endpoint "/scope-none" -IP $script:NoneInside -TraefikUrl $script:TraefikUrl
            $private.StatusCode | Should -Be 200 -Because "PRIVATE country from a RFC1918 IP must skip Country matching"
        }
    }

    Context "Country via geoblock enrich in stream mode" -Tag "scopes" {
        BeforeEach {
            Clear-TraefikAccessLogs
            Remove-AllTestDecisions
        }

        It "Should block after the stream poll when CrowdSec bans the enriched country" {
            $probe = Test-HttpRequest -Endpoint "/scope-stream" -IP $script:PublicIP -TraefikUrl $script:TraefikUrl
            $probe.StatusCode | Should -Be 200
            $country = Get-WhoamiCountryCode -Content $probe.Content
            $country | Should -Match '^[A-Z]{2}$' -Because "geoblock must enrich X-IPCountry for a public IP"

            Add-TestScopeDecision -Scope "Country" -Value $country -Type "ban"

            $result = Wait-ForCondition -Description "Stream mode to block Country $country" -TimeoutSeconds 30 -RetryIntervalSeconds 2 -Condition {
                $response = Test-HttpRequest -Endpoint "/scope-stream" -IP $script:PublicIP -TraefikUrl $script:TraefikUrl
                return ($response.StatusCode -in @(403, 429))
            }
            $result.Success | Should -Be $true -Because "Stream scopes= must include Country"
        }
    }
}
