#!/usr/bin/env pwsh

# Real AppSec from upstream PR 333: OWASP CRS inband on a live Crowdsec engine.
# Not the mock suite's rpc2 stand-in.

BeforeAll {
    . "$PSScriptRoot/TestUtils.ps1"

    $script:TraefikUrl = "http://localhost:8000"
    $script:CrowdSecApiUrl = "http://localhost:8081"
    $script:ApiKey = "40796d93c2958f9e58345514e67740e5"
    $script:ClientIP = "172.19.0.40"

    $result = Wait-ForCondition -Description "CrowdSec LAPI to be ready" -TimeoutSeconds 60 -RetryIntervalSeconds 2 -Condition {
        Invoke-CrowdSecAPI -Endpoint "/v1/decisions?limit=1" -TimeoutSec 5 -ApiKey $script:ApiKey -CrowdSecApiUrl $script:CrowdSecApiUrl
        return $true
    }
    if (-not $result.Success) {
        throw "CrowdSec LAPI failed to become ready"
    }
}

Describe "CrowdSec Bouncer Real AppSec Tests" {
    Context "OWASP CRS inband" -Tag "appsec" {
        BeforeEach {
            Clear-TraefikAccessLogs
            Remove-AllTestDecisions
        }

        It "Should allow a benign AppSec request" {
            $response = Test-HttpRequest -Endpoint "/appsec" -IP $script:ClientIP -TraefikUrl $script:TraefikUrl
            $response.StatusCode | Should -Be 200
        }

        It "Should block a SQL-injection query string via CRS" {
            $response = Test-HttpRequest -Endpoint "/appsec?id=1%27%20OR%20%271%27%3D%271" -IP $script:ClientIP -TraefikUrl $script:TraefikUrl
            $response.StatusCode | Should -Be 403
        }
    }

    Context "AppSec bot-detection challenge" -Tag "appsec", "bot-detection" {
        BeforeEach {
            Clear-TraefikAccessLogs
            Remove-AllTestDecisions
        }

        It "Should not silently ban when bot-detection is loaded" {
            $browser = @{
                "User-Agent" = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
            }
            $response = Test-HttpRequest -Endpoint "/bot-detection" -IP $script:ClientIP -TraefikUrl $script:TraefikUrl -ExtraHeaders $browser
            $cookie = ""
            if ($response.Headers -and $response.Headers["Set-Cookie"]) {
                $cookie = [string]$response.Headers["Set-Cookie"]
            }
            $isChallenge = ($response.Content -match "crowdsec|fpscanner|challenge") -or ($cookie -match "__crowdsec_challenge")
            $isExemptAllow = ($response.StatusCode -eq 200) -and ($response.Content -match "Hostname:")
            $isSilentBan = ($response.StatusCode -eq 403) -and (-not $isChallenge)
            $isSilentBan | Should -BeFalse
            ($isChallenge -or $isExemptAllow) | Should -BeTrue
        }

        It "Should keep challenge assets off the origin whoami" {
            $response = Test-HttpRequest -Endpoint "/crowdsec-internal/challenge/fpscanner.js" -IP $script:ClientIP -TraefikUrl $script:TraefikUrl
            $response.Content | Should -Not -Match "Hostname:"
        }
    }
}
