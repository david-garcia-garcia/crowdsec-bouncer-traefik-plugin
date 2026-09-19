#!/usr/bin/env pwsh

# Header-mapped CrowdSec scopes that mock e2e already covers (username, AS, Country
# placeholder) but real-stack only proved via geoblock Country until now.

BeforeAll {
    . "$PSScriptRoot/TestUtils.ps1"

    $script:TraefikUrl = "http://localhost:8000"
    $script:CrowdSecApiUrl = "http://localhost:8081"
    $script:ApiKey = "40796d93c2958f9e58345514e67740e5"
    $script:ClientIP = "10.80.0.10"

    $result = Wait-ForCondition -Description "CrowdSec LAPI to be ready" -TimeoutSeconds 60 -RetryIntervalSeconds 2 -Condition {
        Invoke-CrowdSecAPI -Endpoint "/v1/decisions?limit=1" -TimeoutSec 5 -ApiKey $script:ApiKey -CrowdSecApiUrl $script:CrowdSecApiUrl
        return $true
    }
    if (-not $result.Success) {
        throw "CrowdSec LAPI failed to become ready"
    }
}

Describe "CrowdSec header-mapped custom scopes" {
    Context "username AS and Country via client headers" -Tag "scopes" {
        BeforeEach {
            Clear-TraefikAccessLogs
            Remove-AllTestDecisions
        }

        It "Should ban a matching username header and skip a missing or other user" {
            Add-TestScopeDecision -Scope "username" -Value "alice" -Type "ban"

            $blocked = Test-HttpRequest -Endpoint "/header-none" -IP $script:ClientIP -TraefikUrl $script:TraefikUrl `
                -ExtraHeaders @{ "X-User" = "alice" }
            $blocked.StatusCode | Should -BeIn @(403, 429)

            $other = Test-HttpRequest -Endpoint "/header-none" -IP $script:ClientIP -TraefikUrl $script:TraefikUrl `
                -ExtraHeaders @{ "X-User" = "bob" }
            $other.StatusCode | Should -Be 200 -Because "username matching is exact; bob must not inherit alice"

            $missing = Test-HttpRequest -Endpoint "/header-none" -IP $script:ClientIP -TraefikUrl $script:TraefikUrl
            $missing.StatusCode | Should -Be 200 -Because "a missing X-User must skip the username scope"
        }

        It "Should treat username as case-sensitive" {
            Add-TestScopeDecision -Scope "username" -Value "alice" -Type "ban"

            $upper = Test-HttpRequest -Endpoint "/header-none" -IP $script:ClientIP -TraefikUrl $script:TraefikUrl `
                -ExtraHeaders @{ "X-User" = "Alice" }
            $upper.StatusCode | Should -Be 200 -Because "custom scopes match the trimmed header exactly"
        }

        It "Should ban AS 13335 when CF-ASN carries an AS prefix" {
            Add-TestScopeDecision -Scope "AS" -Value "13335" -Type "ban"

            $blocked = Test-HttpRequest -Endpoint "/header-none" -IP $script:ClientIP -TraefikUrl $script:TraefikUrl `
                -ExtraHeaders @{ "CF-ASN" = "AS13335" }
            $blocked.StatusCode | Should -BeIn @(403, 429)

            $other = Test-HttpRequest -Endpoint "/header-none" -IP $script:ClientIP -TraefikUrl $script:TraefikUrl `
                -ExtraHeaders @{ "CF-ASN" = "15169" }
            $other.StatusCode | Should -Be 200
        }

        It "Should ignore Country placeholder XX" {
            Add-TestScopeDecision -Scope "Country" -Value "FR" -Type "ban"

            $fr = Test-HttpRequest -Endpoint "/header-none" -IP $script:ClientIP -TraefikUrl $script:TraefikUrl `
                -ExtraHeaders @{ "CF-IPCountry" = "fr" }
            $fr.StatusCode | Should -BeIn @(403, 429)

            $placeholder = Test-HttpRequest -Endpoint "/header-none" -IP $script:ClientIP -TraefikUrl $script:TraefikUrl `
                -ExtraHeaders @{ "CF-IPCountry" = "XX" }
            $placeholder.StatusCode | Should -Be 200 -Because "XX and T1 must not match a Country ban"
        }

        It "Should ban a matching username after the stream poll" {
            Add-TestScopeDecision -Scope "username" -Value "alice" -Type "ban"

            $result = Wait-ForCondition -Description "stream to ban username alice" -TimeoutSeconds 45 -RetryIntervalSeconds 2 -Condition {
                $response = Test-HttpRequest -Endpoint "/scope-stream" -IP $script:ClientIP -TraefikUrl $script:TraefikUrl `
                    -ExtraHeaders @{ "X-User" = "alice" }
                return ($response.StatusCode -in @(403, 429))
            }
            $result.Success | Should -Be $true -Because "stream scopes= must include username from the live-router union"

            $other = Test-HttpRequest -Endpoint "/scope-stream" -IP $script:ClientIP -TraefikUrl $script:TraefikUrl `
                -ExtraHeaders @{ "X-User" = "bob" }
            $other.StatusCode | Should -Be 200
        }
    }
}
