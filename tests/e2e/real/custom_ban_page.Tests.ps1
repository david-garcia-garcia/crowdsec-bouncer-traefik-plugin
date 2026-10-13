#!/usr/bin/env pwsh

# Custom ban page from upstream PR 333: HTML Content-Type, marker body, templated ClientIP.

BeforeAll {
    . "$PSScriptRoot/TestUtils.ps1"

    $script:TraefikUrl = "http://localhost:8000"
    $script:CrowdSecApiUrl = "http://localhost:8081"
    $script:ApiKey = "40796d93c2958f9e58345514e67740e5"
    $script:BannedIP = "172.19.0.30"

    $result = Wait-ForCondition -Description "CrowdSec LAPI to be ready" -TimeoutSeconds 60 -RetryIntervalSeconds 2 -Condition {
        Invoke-CrowdSecAPI -Endpoint "/v1/decisions?limit=1" -TimeoutSec 5 -ApiKey $script:ApiKey -CrowdSecApiUrl $script:CrowdSecApiUrl
        return $true
    }
    if (-not $result.Success) {
        throw "CrowdSec LAPI failed to become ready"
    }
}

Describe "CrowdSec Bouncer Custom Ban Page Tests" {
    Context "Custom ban HTML" -Tag "ban-page" {
        BeforeEach {
            Clear-TraefikAccessLogs
            Remove-AllTestDecisions
        }

        It "Should serve the custom ban HTML with Content-Type and marker" {
            Add-TestDecision -IP $script:BannedIP -Type "ban"

            $response = Test-HttpRequest -Endpoint "/custom-ban" -IP $script:BannedIP -TraefikUrl $script:TraefikUrl
            $response.StatusCode | Should -BeIn @(403, 429)
            $response.ContentType | Should -Match "text/html"
            $response.Content | Should -Match "E2E_CUSTOM_BAN_PAGE_MARKER"
            $response.Content | Should -Match $script:BannedIP
        }
    }
}
