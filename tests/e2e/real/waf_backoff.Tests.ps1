#!/usr/bin/env pwsh

# Admission gates (backoff) of both WAF legs against real outages (dynamic/waf-backoff.yml).
#
# A gate trips after 5 failures in a row. Until then each failure applies the leg's failure
# action. After the trip the leg is skipped for the cooldown: no call and no failure action.
# The next request after the cooldown is a probe; a successful probe reopens the leg.
# Each transition is logged once per outage: "crowdsec <leg> backoff started" (WARN) and
# "crowdsec <leg> backoff ended" (INFO).
#
# The cycle tests stop and start a container (appsec-flaky-test, waf-flaky-test) that only
# their own route uses, and AfterAll always starts it again.

BeforeAll {
    . "$PSScriptRoot/TestUtils.ps1"

    $script:TraefikUrl = "http://localhost:8000"
    $script:Header = "X-Crowdsec-Remediation"
    $script:TripFailures = 5
    $script:SqlInjection = "?id=1%27%20OR%20%271%27%3D%271"

    function script:Invoke-Cycle {
        param([string]$Endpoint, [string]$IP)
        return Test-HttpRequest -Endpoint $Endpoint -IP $IP -TraefikUrl $script:TraefikUrl -TimeoutSec 8
    }

    # Plugin log lines with $Message for one middleware since $Since.
    function script:Get-GateLines {
        param([string]$Since, [string]$Message, [string]$Middleware)
        return Get-ContainerLogLines -Container "traefik-test" -Since $Since -Contains @($Message, $Middleware)
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

Describe "WAF admission gates" {
    Context "AppSec gate with the shipped defaults" -Tag "modsec" {
        It "Should ban each admitted failure, then skip AppSec without FailureAction after the trip" {
            $ip = "10.82.0.10"
            $since = Get-LogSince
            $responses = foreach ($i in 1..8) {
                Invoke-Cycle -Endpoint "/waf-backoff-default" -IP $ip
            }
            $codes = @($responses | ForEach-Object { $_.StatusCode })

            $listenerHits = @(Get-ContainerLogLines -Container "waf-5xx-test" -Since $since -Contains @("GET /waf-backoff-default")).Count

            # A fresh stack sees 5 bans (the default budget) then 3 skips. A rerun within the 30 s
            # cooldown starts already tripped, so it sees fewer listener calls, never more.
            $listenerHits | Should -BeLessOrEqual $script:TripFailures -Because "the default budget trips the gate after 5 failures"
            @($codes | Where-Object { $_ -eq 403 }).Count | Should -Be $listenerHits -Because "every admitted failure applies the default FailureAction ban, and only those"
            $codes[-1] | Should -Be 200 -Because "after the trip AppSec is skipped and the request reaches the origin"
            $firstPass = [array]::IndexOf($codes, 200)
            @($codes[$firstPass..($codes.Count - 1)] | Where-Object { $_ -ne 200 }).Count | Should -Be 0 -Because "no request is banned once the gate skips AppSec"
            $responses[-1].Content | Should -Match "Hostname:"

            if ($listenerHits -eq $script:TripFailures) {
                $wait = Wait-ForCondition -Description "appsec backoff started log" -TimeoutSeconds 10 -Silent -Condition {
                    $script:Lines = Get-GateLines -Since $since -Message "crowdsec appsec backoff started" -Middleware "bouncer-waf-backoff-default"
                    return ($script:Lines.Count -ge 1)
                }
                $wait.Success | Should -Be $true
                $script:Lines.Count | Should -Be 1 -Because "skipped requests must not log one line each"
            }
        }
    }

    Context "AppSec outage and recovery, with ModSec on the same router" -Tag "modsec" {
        BeforeAll {
            $script:Container = "appsec-flaky-test"
            $script:IP = "10.82.0.20"
            Start-Container $script:Container
            $ready = Wait-ForCondition -Description "appsec-cycle route with AppSec healthy" -TimeoutSeconds 90 -RetryIntervalSeconds 2 -Condition {
                $clean = Invoke-Cycle -Endpoint "/appsec-cycle/ready" -IP $script:IP
                $sqli = Invoke-Cycle -Endpoint "/appsec-cycle/ready$($script:SqlInjection)" -IP $script:IP
                return ($clean.StatusCode -eq 200 -and (Get-ResponseHeader $sqli $script:Header) -eq "ban:appsec")
            }
            if (-not $ready.Success) {
                throw "appsec-cycle route never reached a healthy AppSec through appsec-flaky"
            }
        }

        AfterAll {
            Start-Container $script:Container
        }

        It "Should ban until the trip, skip AppSec while ModSec keeps blocking, and recover after the cooldown" {
            $since = Get-LogSince
            Stop-Container $script:Container

            # 1. Each admitted failure applies bouncerAppsecFailureAction: ban, until the budget is spent.
            foreach ($i in 1..$script:TripFailures) {
                $response = Invoke-Cycle -Endpoint "/appsec-cycle/clean" -IP $script:IP
                $response.StatusCode | Should -Be 403 -Because "failure $i of $($script:TripFailures) applies the failure action"
                Get-ResponseHeader $response $script:Header | Should -Be "ban:appsec-failure"
            }

            # 2. Tripped: AppSec is skipped without the failure action. ModSec on the same router still runs.
            $clean = Invoke-Cycle -Endpoint "/appsec-cycle/clean" -IP $script:IP
            $clean.StatusCode | Should -Be 200 -Because "a skipped AppSec does not ban"
            Get-ResponseHeader $clean $script:Header | Should -BeNullOrEmpty
            $sqli = Invoke-Cycle -Endpoint "/appsec-cycle/skip$($script:SqlInjection)" -IP $script:IP
            $sqli.StatusCode | Should -Be 403
            Get-ResponseHeader $sqli $script:Header | Should -Be "ban:modsec" -Because "ModSec keeps protecting while AppSec is skipped"

            # 3. Recovery: once AppSec is back and the cooldown ends, a probe reopens AppSec.
            Start-Container $script:Container
            $recovered = Wait-ForCondition -Description "AppSec verdict after the cooldown" -TimeoutSeconds 60 -RetryIntervalSeconds 1 -Condition {
                $probe = Invoke-Cycle -Endpoint "/appsec-cycle/probe$($script:SqlInjection)" -IP $script:IP
                return ((Get-ResponseHeader $probe $script:Header) -eq "ban:appsec")
            }
            $recovered.Success | Should -Be $true -Because "AppSec must decide again after a successful probe"
            (Invoke-Cycle -Endpoint "/appsec-cycle/clean" -IP $script:IP).StatusCode | Should -Be 200

            # 4. One line per transition for this outage.
            $wait = Wait-ForCondition -Description "appsec backoff ended log" -TimeoutSeconds 10 -Silent -Condition {
                (Get-GateLines -Since $since -Message "crowdsec appsec backoff ended" -Middleware "bouncer-appsec-cycle").Count -ge 1
            }
            $wait.Success | Should -Be $true
            @(Get-GateLines -Since $since -Message "crowdsec appsec backoff started" -Middleware "bouncer-appsec-cycle").Count | Should -Be 1
            @(Get-GateLines -Since $since -Message "crowdsec appsec backoff ended" -Middleware "bouncer-appsec-cycle").Count | Should -Be 1
        }
    }

    Context "ModSec outage and recovery, with AppSec on the same router" -Tag "modsec" {
        BeforeAll {
            $script:Container = "waf-flaky-test"
            $script:IP = "10.82.0.30"
            Start-Container $script:Container
            $ready = Wait-ForCondition -Description "modsec-cycle route with the sidecar healthy" -TimeoutSeconds 90 -RetryIntervalSeconds 2 -Condition {
                $clean = Invoke-Cycle -Endpoint "/modsec-cycle/ready" -IP $script:IP
                $crs = Invoke-Cycle -Endpoint "/modsec-cycle/ready?test=../etc" -IP $script:IP
                return ($clean.StatusCode -eq 200 -and (Get-ResponseHeader $crs $script:Header) -eq "ban:modsec")
            }
            if (-not $ready.Success) {
                throw "modsec-cycle route never reached a healthy waf-flaky sidecar"
            }
        }

        AfterAll {
            Start-Container $script:Container
        }

        It "Should ban until the trip, skip ModSec while AppSec keeps blocking, and recover after the cooldown" {
            $since = Get-LogSince
            Stop-Container $script:Container

            # 1. Each admitted failure applies bouncerModsecFailureAction: ban, until the budget is spent.
            foreach ($i in 1..$script:TripFailures) {
                $response = Invoke-Cycle -Endpoint "/modsec-cycle/clean" -IP $script:IP
                $response.StatusCode | Should -Be 403 -Because "failure $i of $($script:TripFailures) applies the failure action"
                Get-ResponseHeader $response $script:Header | Should -Be "ban:modsec-failure"
            }

            # 2. Tripped: ModSec is skipped without the failure action. The AppSec listener on this
            #    route runs no CRS, so the CRS payload now reaches the origin: the skip is real.
            $clean = Invoke-Cycle -Endpoint "/modsec-cycle/clean" -IP $script:IP
            $clean.StatusCode | Should -Be 200 -Because "a skipped ModSec does not ban"
            Get-ResponseHeader $clean $script:Header | Should -BeNullOrEmpty
            $crs = Invoke-Cycle -Endpoint "/modsec-cycle/skip?test=../etc" -IP $script:IP
            $crs.StatusCode | Should -Be 200 -Because "the sidecar is not called while the gate skips it"
            $drop = Invoke-Cycle -Endpoint "/modsec-cycle/appsec-drop" -IP $script:IP
            $drop.StatusCode | Should -Be 403
            Get-ResponseHeader $drop $script:Header | Should -Be "ban:appsec" -Because "AppSec keeps protecting while ModSec is skipped"

            # 3. Recovery: once the sidecar is back and the cooldown ends, a probe reopens ModSec.
            Start-Container $script:Container
            $recovered = Wait-ForCondition -Description "CRS verdict after the cooldown" -TimeoutSeconds 90 -RetryIntervalSeconds 1 -Condition {
                $probe = Invoke-Cycle -Endpoint "/modsec-cycle/probe?test=../etc" -IP $script:IP
                return ((Get-ResponseHeader $probe $script:Header) -eq "ban:modsec")
            }
            $recovered.Success | Should -Be $true -Because "ModSec must decide again after a successful probe"
            (Invoke-Cycle -Endpoint "/modsec-cycle/clean" -IP $script:IP).StatusCode | Should -Be 200

            # 4. One line per transition for this outage.
            $wait = Wait-ForCondition -Description "modsec backoff ended log" -TimeoutSeconds 10 -Silent -Condition {
                (Get-GateLines -Since $since -Message "crowdsec modsec backoff ended" -Middleware "bouncer-modsec-cycle").Count -ge 1
            }
            $wait.Success | Should -Be $true
            @(Get-GateLines -Since $since -Message "crowdsec modsec backoff started" -Middleware "bouncer-modsec-cycle").Count | Should -Be 1
            @(Get-GateLines -Since $since -Message "crowdsec modsec backoff ended" -Middleware "bouncer-modsec-cycle").Count | Should -Be 1
        }
    }
}
