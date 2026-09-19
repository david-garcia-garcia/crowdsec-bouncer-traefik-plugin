#!/usr/bin/env pwsh

# Real-stack proof that this plugin's POST /v1/usage-metrics shows up in
# `cscli metrics show bouncers`. Stream interval is 1s on /stream and /trusted
# (shared session) and on /appsec.

BeforeAll {
    . "$PSScriptRoot/TestUtils.ps1"

    $script:TraefikUrl = "http://localhost:8000"
    $script:CrowdSecApiUrl = "http://localhost:8081"
    $script:ApiKey = "40796d93c2958f9e58345514e67740e5"
    $script:BannedIP = "172.19.0.90"
    $script:CleanIP = "172.19.0.91"
    $script:AppsecIP = "172.19.0.92"

    $result = Wait-ForCondition -Description "CrowdSec LAPI to be ready" -TimeoutSeconds 60 -RetryIntervalSeconds 2 -Condition {
        Invoke-CrowdSecAPI -Endpoint "/v1/decisions?limit=1" -TimeoutSec 5 -ApiKey $script:ApiKey -CrowdSecApiUrl $script:CrowdSecApiUrl
        return $true
    }
    if (-not $result.Success) {
        throw "CrowdSec LAPI failed to become ready"
    }

    $streamReady = Wait-ForHttpStatus -Url "http://localhost:8000/stream" -Headers @{ "X-Forwarded-For" = $script:CleanIP } -ExpectedStatusCodes @(200) -TimeoutSeconds 60
    if (-not $streamReady.Success) {
        throw "/stream failed to become ready"
    }
}

Describe "CrowdSec Bouncer usage-metrics" {
    Context "cscli metrics show bouncers" -Tag "metrics" {
        BeforeEach {
            Clear-TraefikAccessLogs
            Remove-AllTestDecisions
        }

        AfterEach {
            Remove-TestDecision -IP $script:BannedIP
        }

        It "Should record processed requests with no origin row" {
            $before = Get-CscliBouncerMetricValue -Origin "" -Name "processed" -Unit "request"
            $response = Test-HttpRequest -Endpoint "/stream" -IP $script:CleanIP -TraefikUrl $script:TraefikUrl
            $response.StatusCode | Should -Be 200

            $waited = Wait-ForCondition -Description "processed count to increase in cscli metrics" -TimeoutSeconds 20 -RetryIntervalSeconds 1 -Condition {
                $after = Get-CscliBouncerMetricValue -Origin "" -Name "processed" -Unit "request"
                return ($after -gt $before)
            }
            $waited.Success | Should -Be $true -Because "an allowed /stream request must increment processed (empty origin)"
        }

        It "Should record cscli origin dropped and active_decisions after a banned request" {
            Add-TestDecision -IP $script:BannedIP -Type "ban"

            $blocked = Wait-ForCondition -Description "stream to ban $($script:BannedIP)" -TimeoutSeconds 30 -RetryIntervalSeconds 2 -Condition {
                $response = Test-HttpRequest -Endpoint "/stream" -IP $script:BannedIP -TraefikUrl $script:TraefikUrl
                return ($response.StatusCode -in @(403, 429))
            }
            $blocked.Success | Should -Be $true -Because "stream must apply the cscli ban before metrics can count a drop"

            $droppedBefore = Get-CscliBouncerMetricValue -Origin "cscli" -Name "dropped" -Unit "request"
            $null = Test-HttpRequest -Endpoint "/stream" -IP $script:BannedIP -TraefikUrl $script:TraefikUrl

            $dropped = Wait-ForCondition -Description "cscli dropped requests in cscli metrics" -TimeoutSeconds 20 -RetryIntervalSeconds 1 -Condition {
                $after = Get-CscliBouncerMetricValue -Origin "cscli" -Name "dropped" -Unit "request"
                return ($after -gt $droppedBefore)
            }
            $dropped.Success | Should -Be $true -Because "a banned /stream hit must POST dropped with origin=cscli"

            $active = Wait-ForCondition -Description "cscli active_decisions gauge in cscli metrics" -TimeoutSeconds 20 -RetryIntervalSeconds 1 -Condition {
                $gauge = Get-CscliBouncerMetricValue -Origin "cscli" -Name "active_decisions" -Unit "ip"
                return ($gauge -ge 1)
            }
            $active.Success | Should -Be $true -Because "stream must report at least one active cscli decision"
        }

        It "Should record appsec origin dropped after a CRS injection" {
            $response = Test-HttpRequest -Endpoint "/appsec?id=1%27%20OR%20%271%27%3D%271" -IP $script:AppsecIP -TraefikUrl $script:TraefikUrl
            $response.StatusCode | Should -Be 403 -Because "OWASP CRS inband must block the SQLi probe"

            $droppedBefore = Get-CscliBouncerMetricValue -Origin "appsec" -Name "dropped" -Unit "request"
            $null = Test-HttpRequest -Endpoint "/appsec?id=1%27%20OR%20%271%27%3D%271" -IP $script:AppsecIP -TraefikUrl $script:TraefikUrl

            $dropped = Wait-ForCondition -Description "appsec dropped requests in cscli metrics" -TimeoutSeconds 20 -RetryIntervalSeconds 1 -Condition {
                $after = Get-CscliBouncerMetricValue -Origin "appsec" -Name "dropped" -Unit "request"
                return ($after -gt $droppedBefore)
            }
            $dropped.Success | Should -Be $true -Because "an AppSec ban must POST dropped with origin=appsec"
        }
    }
}
