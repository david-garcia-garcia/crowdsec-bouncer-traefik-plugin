#!/usr/bin/env pwsh

# LAPI and AppSec failure actions against a closed port (crowdsec:9), not a mock.

BeforeAll {
    . "$PSScriptRoot/TestUtils.ps1"

    $script:TraefikUrl = "http://localhost:8000"
    $script:ClientIP = "10.81.0.10"
}

Describe "CrowdSec LAPI and AppSec failure actions" {
    Context "Unreachable LAPI" -Tag "failure-action" {
        It "Should ban when crowdsecLapiFailureAction is ban" {
            $response = Test-HttpRequest -Endpoint "/lapi-fail-ban" -IP $script:ClientIP -TraefikUrl $script:TraefikUrl -TimeoutSec 8
            $response.StatusCode | Should -BeIn @(403, 429) -Because "none-mode LiveLookup errors must apply crowdsecLapiFailureAction=ban; a 200 means this router joined the healthy crowdsec:8080 Client instead of crowdsec:9"
        }

        It "Should pass when crowdsecLapiFailureAction is passthrough" {
            $response = Test-HttpRequest -Endpoint "/lapi-fail-pass" -IP $script:ClientIP -TraefikUrl $script:TraefikUrl -TimeoutSec 8
            $response.StatusCode | Should -Be 200 -Because "passthrough must not remediate an unreachable LAPI"
            $response.Content | Should -Match "Hostname:"
        }
    }

    Context "Unreachable AppSec" -Tag "failure-action" {
        It "Should ban when crowdsecAppsecFailureAction is ban" {
            $response = Test-HttpRequest -Endpoint "/waf-fail-ban" -IP $script:ClientIP -TraefikUrl $script:TraefikUrl -TimeoutSec 8
            $response.StatusCode | Should -Be 403 -Because "AppSec transport failure with action ban remediates"
        }

        It "Should pass when crowdsecAppsecFailureAction is passthrough" {
            $response = Test-HttpRequest -Endpoint "/waf-fail-pass" -IP $script:ClientIP -TraefikUrl $script:TraefikUrl -TimeoutSec 8
            $response.StatusCode | Should -Be 200 -Because "passthrough must continue when AppSec is unreachable"
            $response.Content | Should -Match "Hostname:"
        }
    }
}
