#!/usr/bin/env pwsh

# Inspect-only Apache CRS sidecar (modsec leg). Client identity is X-Forwarded-For only.

BeforeAll {
    . "$PSScriptRoot/TestUtils.ps1"

    $script:TraefikUrl = "http://localhost:8000"
    $script:ClientIP = "172.19.0.50"

    $result = Wait-ForCondition -Description "ModSec allow route" -TimeoutSeconds 90 -RetryIntervalSeconds 3 -Condition {
        $response = Test-HttpRequest -Endpoint "/modsec-allow" -IP $script:ClientIP -TraefikUrl $script:TraefikUrl
        return ($response.StatusCode -eq 200)
    }
    if (-not $result.Success) {
        throw "ModSec allow route failed to become ready"
    }
}

Describe "CrowdSec Bouncer ModSec CRS sidecar" {
    Context "Inspect-only Apache CRS" -Tag "modsec" {
        It "Should allow a benign request" {
            $response = Test-HttpRequest -Endpoint "/modsec-allow" -IP $script:ClientIP -TraefikUrl $script:TraefikUrl
            $response.StatusCode | Should -Be 200
            $response.Content | Should -Match "Hostname:"
        }

        It "Should block CRS path traversal ../etc" {
            $response = Test-HttpRequest -Endpoint "/modsec-crs/?test=../etc" -IP $script:ClientIP -TraefikUrl $script:TraefikUrl
            $response.StatusCode | Should -Be 403
            $response.Headers["X-Crowdsec-Remediation"] | Should -Match "ban:modsec"
        }

        It "Should return 413 when the body exceeds modsecBodyLimit" {
            $body = "a" * 2048
            $response = Test-HttpRequest -Endpoint "/modsec-body" -IP $script:ClientIP -TraefikUrl $script:TraefikUrl `
                -Method POST -Body $body -ExtraHeaders @{ "Content-Type" = "text/plain" }
            $response.StatusCode | Should -Be 413
        }

        It "Should reject GET with a body" {
            $response = Test-HttpRequest -Endpoint "/modsec-deny-get" -IP $script:ClientIP -TraefikUrl $script:TraefikUrl `
                -Method GET -Body "x" -ExtraHeaders @{ "Content-Type" = "text/plain" }
            $response.StatusCode | Should -Be 400
        }

        It "Should continue on failMode open" {
            $response = Test-HttpRequest -Endpoint "/modsec-fail-open" -IP $script:ClientIP -TraefikUrl $script:TraefikUrl
            $response.StatusCode | Should -Be 200
            $response.Content | Should -Match "Hostname:"
        }

        It "Should write 502 on failMode close" {
            $response = Test-HttpRequest -Endpoint "/modsec-fail-close" -IP $script:ClientIP -TraefikUrl $script:TraefikUrl
            $response.StatusCode | Should -Be 502
        }

        It "Should skip the sidecar after a backoff trip and still fail-open" {
            $first = Test-HttpRequest -Endpoint "/modsec-backoff" -IP $script:ClientIP -TraefikUrl $script:TraefikUrl
            $first.StatusCode | Should -Be 200
            $second = Test-HttpRequest -Endpoint "/modsec-backoff" -IP $script:ClientIP -TraefikUrl $script:TraefikUrl
            $second.StatusCode | Should -Be 200
            $second.Content | Should -Match "Hostname:"
        }

        It "Should honor bypassModsec on a CRS-blocked query" {
            $skipped = Test-HttpRequest -Endpoint "/modsec-skip/ok?test=../etc" -IP $script:ClientIP -TraefikUrl $script:TraefikUrl
            $skipped.StatusCode | Should -Be 200
            $blocked = Test-HttpRequest -Endpoint "/modsec-skip/hit?test=../etc" -IP $script:ClientIP -TraefikUrl $script:TraefikUrl
            $blocked.StatusCode | Should -Be 403
        }
    }
}
