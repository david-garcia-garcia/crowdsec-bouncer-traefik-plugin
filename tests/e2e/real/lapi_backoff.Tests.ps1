#!/usr/bin/env pwsh

# LAPI live-mode admission gate (backoff) against a real outage (dynamic/lapi-backoff.yml).
#
# /lapi-cycle is a live LAPI connection through lapi-flaky (nginx proxy to crowdsec:8080) with a
# 10 s cooldown, a 2 s LAPI timeout, and the default actions: bouncerLapiFailureAction ban and
# bouncerLapiBackOffAction ban. Stopping lapi-flaky-test makes every lookup fail: the first 5
# get the failure action (ban:lapi-failure) and trip the gate, then lookups get the backoff
# action (ban:lapi-backoff) at once, without a GET. Once lapi-flaky-test is back and the
# cooldown ends, a probe reopens LAPI. Each transition is logged once: "crowdsec lapi backoff
# started" (WARN) and "crowdsec lapi backoff ended" (INFO).
#
# Live mode caches a clean answer for lapiDefaultDecisionSeconds, so every request uses a client
# address it has not seen. Only this route uses lapi-flaky, and AfterAll always starts it again.

BeforeAll {
    . "$PSScriptRoot/TestUtils.ps1"

    $script:TraefikUrl = "http://localhost:8000"
    $script:Header = "X-Crowdsec-Remediation"
    $script:TripFailures = 5
    $script:Container = "lapi-flaky-test"
    $script:Middleware = "bouncer-lapi-cycle"
    $script:ClientCount = 0

    # One GET to /lapi-cycle from a client address live mode has not cached yet.
    function script:Invoke-LapiCycle {
        param([string]$Path = "/lapi-cycle/")
        $script:ClientCount++
        $ip = "10.83.$([math]::Floor($script:ClientCount / 250)).$(($script:ClientCount % 250) + 1)"
        return Test-HttpRequest -Endpoint $Path -IP $ip -TraefikUrl $script:TraefikUrl -TimeoutSec 8
    }

    # Plugin log lines with $Message for the lapi-cycle middleware since $Since.
    function script:Get-GateLines {
        param([string]$Since, [string]$Message)
        return Get-ContainerLogLines -Container "traefik-test" -Since $Since -Contains @($Message, $script:Middleware)
    }

    function script:Start-Container {
        param([string]$Name)
        docker start $Name 2>&1 | Out-Null
    }

    function script:Stop-Container {
        param([string]$Name)
        docker stop -t 5 $Name 2>&1 | Out-Null
        $state = (docker inspect -f '{{.State.Running}}' $Name 2>&1 | Out-String).Trim()
        if ($state -ne "false") {
            throw "container $Name is still running after docker stop (state=$state)"
        }
    }
}

Describe "LAPI live admission gate" {
    Context "LAPI outage and recovery in live mode" -Tag "lapi" {
        BeforeAll {
            Start-Container $script:Container
            # Also waits out a cooldown left by an earlier run on the same stack.
            $ready = Wait-ForCondition -Description "lapi-cycle route with LAPI healthy" -TimeoutSeconds 90 -RetryIntervalSeconds 2 -Condition {
                return ((Invoke-LapiCycle -Path "/lapi-cycle/ready").StatusCode -eq 200)
            }
            if (-not $ready.Success) {
                throw "lapi-cycle route never reached a healthy LAPI through lapi-flaky"
            }
        }

        AfterAll {
            Start-Container $script:Container
        }

        It "Should ban until the trip, then ban at once without LAPI, and recover after the cooldown" {
            $since = Get-LogSince
            Stop-Container $script:Container

            # 1. Each lookup LAPI does not answer applies bouncerLapiFailureAction: ban, until the budget is spent.
            foreach ($i in 1..$script:TripFailures) {
                $response = Invoke-LapiCycle -Path "/lapi-cycle/fail"
                $response.StatusCode | Should -Be 403 -Because "failure $i of $($script:TripFailures) applies the failure action"
                Get-ResponseHeader $response $script:Header | Should -Be "ban:lapi-failure"
            }

            # 2. Tripped: LAPI is not called and the default backoff action ban answers at once.
            $clock = [System.Diagnostics.Stopwatch]::StartNew()
            $skipped = Invoke-LapiCycle -Path "/lapi-cycle/skip"
            $clock.Stop()
            $skipped.StatusCode | Should -Be 403 -Because "the default bouncerLapiBackOffAction is ban"
            Get-ResponseHeader $skipped $script:Header | Should -Be "ban:lapi-backoff" -Because "a gate skip is not a failure"
            $clock.Elapsed.TotalMilliseconds | Should -BeLessThan 1500 -Because "a skipped lookup does not wait for the 2 s LAPI timeout"
            $again = Invoke-LapiCycle -Path "/lapi-cycle/skip"
            Get-ResponseHeader $again $script:Header | Should -Be "ban:lapi-backoff"

            $started = Wait-ForCondition -Description "lapi backoff started log" -TimeoutSeconds 10 -Silent -Condition {
                (Get-GateLines -Since $since -Message "crowdsec lapi backoff started").Count -ge 1
            }
            $started.Success | Should -Be $true
            @(Get-GateLines -Since $since -Message "crowdsec lapi backoff started").Count | Should -Be 1 -Because "skipped lookups must not log one line each"

            # 3. Recovery: once LAPI is reachable again and the cooldown ends, a probe reopens LAPI.
            Start-Container $script:Container
            $recovered = Wait-ForCondition -Description "LAPI answer after the cooldown" -TimeoutSeconds 60 -RetryIntervalSeconds 1 -Condition {
                return ((Invoke-LapiCycle -Path "/lapi-cycle/probe").StatusCode -eq 200)
            }
            $recovered.Success | Should -Be $true -Because "LAPI must decide again after a successful probe"
            $clean = Invoke-LapiCycle -Path "/lapi-cycle/clean"
            $clean.StatusCode | Should -Be 200
            Get-ResponseHeader $clean $script:Header | Should -BeNullOrEmpty

            # 4. One line per transition for this outage.
            $ended = Wait-ForCondition -Description "lapi backoff ended log" -TimeoutSeconds 10 -Silent -Condition {
                (Get-GateLines -Since $since -Message "crowdsec lapi backoff ended").Count -ge 1
            }
            $ended.Success | Should -Be $true
            @(Get-GateLines -Since $since -Message "crowdsec lapi backoff started").Count | Should -Be 1
            @(Get-GateLines -Since $since -Message "crowdsec lapi backoff ended").Count | Should -Be 1
        }
    }
}
