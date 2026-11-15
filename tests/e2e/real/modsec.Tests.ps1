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

        It "Should skip the sidecar after a backoff trip and log the transition once" {
            # waf-5xx answers 503; threshold 1 trips on the first miss. failMode open keeps every
            # response 200, so the proof is the sidecar hit count and the single transition line.
            $since = (Get-Date).ToUniversalTime().AddSeconds(-2).ToString('yyyy-MM-ddTHH:mm:ssZ')
            foreach ($i in 1..4) {
                $response = Test-HttpRequest -Endpoint "/modsec-backoff" -IP $script:ClientIP -TraefikUrl $script:TraefikUrl
                $response.StatusCode | Should -Be 200 -Because "failMode open continues to the origin (request $i)"
                $response.Content | Should -Match "Hostname:"
            }

            $sidecarHits = @(
                (docker logs --since $since waf-5xx-test 2>&1 | Out-String) -split "`r?`n" |
                    Where-Object { $_ -match 'GET /modsec-backoff' }
            ).Count
            $sidecarHits | Should -Be 1 -Because "after the trip the gate must skip the sidecar"

            $wait = Wait-ForCondition -Description "modsec backoff started log" -TimeoutSeconds 10 -Condition {
                $script:BackoffLines = @(
                    (docker logs --since $since traefik-test 2>&1 | Out-String) -split "`r?`n" |
                        Where-Object { $_ -match 'crowdsec modsec backoff started' -and $_ -match 'bouncer-modsec-backoff' }
                )
                return ($script:BackoffLines.Count -ge 1)
            }
            $wait.Success | Should -Be $true
            $script:BackoffLines.Count | Should -Be 1 -Because "skipped requests must not log one line each"
        }

        It "Should echo two WebSocket frames after the handshake is inspected" {
            $first = "ws-echo-a-$(Get-Random)"
            $second = "ws-echo-b-$(Get-Random)"
            $echoed = Invoke-WebSocketEcho -Uri "ws://localhost:8000/modsec-ws" -Message @($first, $second)
            $echoed | Should -Be @($first, $second) -Because "inspecting the handshake GET must leave a working tunnel, not a 101-only upgrade"
        }

        It "Should block a WebSocket handshake that carries a CRS payload" {
            $response = Test-HttpRequest -Endpoint "/modsec-ws?test=../etc" -IP $script:ClientIP -TraefikUrl $script:TraefikUrl `
                -MaximumRedirection 0 -ExtraHeaders @{
                    "Upgrade"               = "websocket"
                    "Connection"            = "Upgrade"
                    "Sec-WebSocket-Key"     = "dGhlIHNhbXBsZSBub25jZQ=="
                    "Sec-WebSocket-Version" = "13"
                }
            $response.StatusCode | Should -Be 403 -Because "Upgrade headers must not skip CRS"
        }

        It "Should inspect a forged Upgrade header without a Connection upgrade token" {
            $response = Test-HttpRequest -Endpoint "/modsec-crs/?test=../etc" -IP $script:ClientIP -TraefikUrl $script:TraefikUrl `
                -MaximumRedirection 0 -ExtraHeaders @{ "Upgrade" = "websocket" }
            $response.StatusCode | Should -Be 403 -Because "a lone Upgrade header must still be CRS-inspected"
        }

        It "Should honor bypassModsec on a CRS-blocked query" {
            $skipped = Test-HttpRequest -Endpoint "/modsec-skip/ok?test=../etc" -IP $script:ClientIP -TraefikUrl $script:TraefikUrl
            $skipped.StatusCode | Should -Be 200
            $blocked = Test-HttpRequest -Endpoint "/modsec-skip/hit?test=../etc" -IP $script:ClientIP -TraefikUrl $script:TraefikUrl
            $blocked.StatusCode | Should -Be 403
        }
    }
}
