#!/usr/bin/env pwsh

# Live-mode Redis cache backed by Dragonfly (functional Redis-protocol backend).

BeforeAll {
    . "$PSScriptRoot/TestUtils.ps1"

    $script:TraefikUrl = "http://localhost:8000"
    $script:CrowdSecApiUrl = "http://localhost:8081"
    $script:ApiKey = "40796d93c2958f9e58345514e67740e5"
    $script:RedisBannedIP = "172.19.0.30"
    $script:RedisCleanIP = "172.19.0.31"

    $result = Wait-ForCondition -Description "CrowdSec LAPI to be ready" -TimeoutSeconds 60 -RetryIntervalSeconds 2 -Condition {
        Invoke-CrowdSecAPI -Endpoint "/v1/decisions?limit=1" -TimeoutSec 5 -ApiKey $script:ApiKey -CrowdSecApiUrl $script:CrowdSecApiUrl
        return $true
    }
    if (-not $result.Success) {
        throw "CrowdSec LAPI failed to become ready"
    }
}

Describe "CrowdSec Bouncer Dragonfly Redis cache" {
    Context "Live mode against Dragonfly" -Tag "redis-cache" {
        BeforeEach {
            Clear-TraefikAccessLogs
            Remove-AllTestDecisions
        }

        It "Should keep the first allow cached until defaultDecisionSeconds, then see a new ban" {
            $allow = Test-HttpRequest -Endpoint "/redis-cache" -IP $script:RedisBannedIP -TraefikUrl $script:TraefikUrl
            $allow.StatusCode | Should -Be 200

            Add-TestDecision -IP $script:RedisBannedIP -Type "ban"

            $stillCached = Test-HttpRequest -Endpoint "/redis-cache" -IP $script:RedisBannedIP -TraefikUrl $script:TraefikUrl
            $stillCached.StatusCode | Should -Be 200 -Because "live mode must keep the Dragonfly-cached allow until defaultDecisionSeconds expires"

            $blocked = Wait-ForCondition -Description "live Redis cache to re-query LAPI and block $($script:RedisBannedIP)" -TimeoutSeconds 15 -RetryIntervalSeconds 1 -Condition {
                $response = Test-HttpRequest -Endpoint "/redis-cache" -IP $script:RedisBannedIP -TraefikUrl $script:TraefikUrl
                return ($response.StatusCode -in @(403, 429))
            }
            $blocked.Success | Should -Be $true -Because "After the cached allow expires, live mode must see the ban from LAPI via Dragonfly"

            $clean = Test-HttpRequest -Endpoint "/redis-cache" -IP $script:RedisCleanIP -TraefikUrl $script:TraefikUrl
            $clean.StatusCode | Should -Be 200
        }

        It "Should still block after Traefik restart when the ban lives in Dragonfly" {
            Add-TestDecision -IP $script:RedisBannedIP -Type "ban"

            $blocked = Test-HttpRequest -Endpoint "/hold-redis" -IP $script:RedisBannedIP -TraefikUrl $script:TraefikUrl
            $blocked.StatusCode | Should -BeIn @(403, 429) -Because "first miss must query LAPI and cache the ban in Dragonfly"

            Remove-TestDecision -IP $script:RedisBannedIP

            docker restart traefik-test
            if ($LASTEXITCODE -ne 0) {
                throw "docker restart traefik-test failed"
            }

            $ready = Wait-ForCondition -Description "Traefik to be ready after restart" -TimeoutSeconds 60 -RetryIntervalSeconds 2 -Condition {
                try {
                    $response = Invoke-WebRequest -Uri "http://localhost:8000/disabled" -TimeoutSec 3 -UseBasicParsing
                    return ($response.StatusCode -eq 200)
                }
                catch {
                    return $false
                }
            }
            if (-not $ready.Success) {
                throw "Traefik did not become ready after restart"
            }

            $stillBlocked = Wait-ForCondition -Description "Dragonfly-cached ban on /hold-redis after Traefik restart" -TimeoutSeconds 30 -RetryIntervalSeconds 1 -Condition {
                $response = Test-HttpRequest -Endpoint "/hold-redis" -IP $script:RedisBannedIP -TraefikUrl $script:TraefikUrl
                return ($response.StatusCode -in @(403, 429))
            }
            $stillBlocked.Success | Should -Be $true -Because "in-memory cache would miss after restart; Dragonfly must still hold the ban"
        }
    }
}
