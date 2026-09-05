#!/usr/bin/env pwsh

# Trusted IPs from upstream PR 333: clientTrustedIPs bypass even when that IP is banned.

BeforeAll {
    . "$PSScriptRoot/TestUtils.ps1"

    $script:TraefikUrl = "http://localhost:8000"
    $script:CrowdSecApiUrl = "http://localhost:8081"
    $script:ApiKey = "40796d93c2958f9e58345514e67740e5"
    $script:TrustedIP = "172.19.0.10"
    $script:UntrustedIP = "172.19.0.11"

    $result = Wait-ForCondition -Description "CrowdSec LAPI to be ready" -TimeoutSeconds 60 -RetryIntervalSeconds 2 -Condition {
        Invoke-CrowdSecAPI -Endpoint "/v1/decisions?limit=1" -TimeoutSec 5 -ApiKey $script:ApiKey -CrowdSecApiUrl $script:CrowdSecApiUrl
        return $true
    }
    if (-not $result.Success) {
        throw "CrowdSec LAPI failed to become ready"
    }
}

Describe "CrowdSec Bouncer Trusted IP Tests" {
    Context "clientTrustedIPs bypass" -Tag "trusted" {
        BeforeEach {
            Clear-TraefikAccessLogs
            Remove-AllTestDecisions
        }

        It "Should allow a banned trusted IP and block a banned untrusted IP" {
            Add-TestDecision -IP $script:TrustedIP -Type "ban"
            Add-TestDecision -IP $script:UntrustedIP -Type "ban"

            $untrustedBlocked = Wait-ForCondition -Description "stream mode to block untrusted $($script:UntrustedIP)" -TimeoutSeconds 30 -RetryIntervalSeconds 2 -Condition {
                $response = Test-HttpRequest -Endpoint "/trusted" -IP $script:UntrustedIP -TraefikUrl $script:TraefikUrl
                return ($response.StatusCode -in @(403, 429))
            }
            $untrustedBlocked.Success | Should -Be $true -Because "The untrusted banned IP proves the bouncer is active"

            $trusted = Test-HttpRequest -Endpoint "/trusted" -IP $script:TrustedIP -TraefikUrl $script:TraefikUrl
            $trusted.StatusCode | Should -Be 200 -Because "clientTrustedIPs must bypass even when that IP is banned"
        }
    }
}
