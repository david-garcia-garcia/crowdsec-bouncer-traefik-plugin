#!/usr/bin/env pwsh

# Range and header-mapped CrowdSec scopes against a live LAPI.

function Add-IpSpellingDecision {
    param(
        [string]$Stored,
        [string]$Reason
    )
    # Avoid TestUtils' `sh -c` string: IPv6/mapped values must stay one argv.
    $add = docker exec crowdsec-test cscli decisions add --ip $Stored --duration 1h --type ban --reason $Reason 2>&1 | Out-String
    if ($LASTEXITCODE -eq 0) {
        return
    }
    $scope = docker exec crowdsec-test cscli decisions add --scope Ip --value $Stored --duration 1h --type ban --reason $Reason 2>&1 | Out-String
    if ($LASTEXITCODE -eq 0) {
        return
    }
    throw "cscli --ip: $add --scope Ip: $scope"
}

function Assert-IpSpellingBan {
    param(
        [string]$Endpoint,
        [string]$Stored,
        [string]$Request,
        [int]$TimeoutSeconds = 15
    )
    $addError = $null
    try {
        Add-IpSpellingDecision -Stored $Stored -Reason "Ip spelling $Stored"
    }
    catch {
        $addError = $_.Exception.Message
    }
    $addError | Should -BeNullOrEmpty -Because "cscli must accept stored $Stored : $addError"
    $result = Wait-ForCondition -Description "LAPI/bouncer to ban stored $Stored as $Request on $Endpoint" -TimeoutSeconds $TimeoutSeconds -RetryIntervalSeconds 2 -Condition {
        $response = Test-HttpRequest -Endpoint $Endpoint -IP $Request -TraefikUrl $script:TraefikUrl
        return ($response.StatusCode -in @(403, 429))
    }
    $result.Success | Should -Be $true -Because "stored $Stored must ban request $Request on $Endpoint (last wait $($result.TimeTaken)s; $($result.Error))"
}

BeforeAll {
    . "$PSScriptRoot/TestUtils.ps1"

    $script:TraefikUrl = "http://localhost:8000"
    $script:CrowdSecApiUrl = "http://localhost:8081"
    $script:ApiKey = "40796d93c2958f9e58345514e67740e5"

    $script:NoneRange = "10.55.0.0/16"
    $script:NoneInside = "10.55.1.8"
    $script:NoneOutside = "10.56.1.8"
    $script:StreamRange = "10.57.0.0/16"
    $script:StreamInside = "10.57.1.8"
    $script:StreamOutside = "10.58.1.8"
    $script:PublicIP = "8.8.8.8"

    $result = Wait-ForCondition -Description "CrowdSec LAPI to be ready" -TimeoutSeconds 60 -RetryIntervalSeconds 2 -Condition {
        Invoke-CrowdSecAPI -Endpoint "/v1/decisions?limit=1" -TimeoutSec 5 -ApiKey $script:ApiKey -CrowdSecApiUrl $script:CrowdSecApiUrl
        return $true
    }

    if (-not $result.Success) {
        throw "❌ CrowdSec LAPI failed to become ready"
    }
}

Describe "CrowdSec Range and header-mapped scopes" {

    Context "Range in none mode" -Tag "scopes" {
        BeforeEach {
            Clear-TraefikAccessLogs
            Remove-AllTestDecisions
        }

        It "Should block an IP inside a Range decision and allow one outside" {
            Add-TestRangeDecision -Range $script:NoneRange -Type "ban"

            $blocked = Test-HttpRequest -Endpoint "/scope-none" -IP $script:NoneInside -TraefikUrl $script:TraefikUrl
            $blocked.StatusCode | Should -BeIn @(403, 429)

            $allowed = Test-HttpRequest -Endpoint "/scope-none" -IP $script:NoneOutside -TraefikUrl $script:TraefikUrl
            $allowed.StatusCode | Should -Be 200
        }
    }

    Context "Range in stream mode" -Tag "scopes" {
        BeforeEach {
            Clear-TraefikAccessLogs
            Remove-AllTestDecisions
        }

        It "Should block an IP inside a Range decision after the stream poll" {
            Add-TestRangeDecision -Range $script:StreamRange -Type "ban"

            $result = Wait-ForCondition -Description "Stream mode to block Range $($script:StreamRange)" -TimeoutSeconds 45 -RetryIntervalSeconds 2 -Condition {
                $response = Test-HttpRequest -Endpoint "/scope-stream" -IP $script:StreamInside -TraefikUrl $script:TraefikUrl
                return ($response.StatusCode -in @(403, 429))
            }
            $result.Success | Should -Be $true -Because "Stream mode should match Range via range-index"

            $allowed = Test-HttpRequest -Endpoint "/scope-stream" -IP $script:StreamOutside -TraefikUrl $script:TraefikUrl
            $allowed.StatusCode | Should -Be 200 -Because "an IP outside the Range must stay allowed while the ban is active"

            Remove-TestRangeDecision -Range $script:StreamRange

            $result = Wait-ForCondition -Description "Stream mode to allow IP after Range delete" -TimeoutSeconds 30 -RetryIntervalSeconds 2 -Condition {
                $response = Test-HttpRequest -Endpoint "/scope-stream" -IP $script:StreamInside -TraefikUrl $script:TraefikUrl
                return ($response.StatusCode -eq 200)
            }
            $result.Success | Should -Be $true -Because "Stream mode should drop the Range after delete"
        }
    }

    Context "Country via geoblock enrich in none mode" -Tag "scopes" {
        BeforeEach {
            Clear-TraefikAccessLogs
            Remove-AllTestDecisions
        }

        It "Should block a public IP after CrowdSec bans the enriched country" {
            $probe = Test-HttpRequest -Endpoint "/scope-none" -IP $script:PublicIP -TraefikUrl $script:TraefikUrl
            $probe.StatusCode | Should -Be 200
            $country = Get-WhoamiCountryCode -Content $probe.Content
            $country | Should -Match '^[A-Z]{2}$' -Because "geoblock must enrich X-IPCountry for a public IP; body was: $($probe.Content)"
            $country | Should -Not -BeIn @("XX", "T1")

            Add-TestScopeDecision -Scope "Country" -Value $country -Type "ban"

            $blocked = Test-HttpRequest -Endpoint "/scope-none" -IP $script:PublicIP -TraefikUrl $script:TraefikUrl
            $blocked.StatusCode | Should -BeIn @(403, 429)

            $private = Test-HttpRequest -Endpoint "/scope-none" -IP $script:NoneInside -TraefikUrl $script:TraefikUrl
            $private.StatusCode | Should -Be 200 -Because "PRIVATE country from a RFC1918 IP must skip Country matching"
        }
    }

    Context "Country via geoblock enrich in stream mode" -Tag "scopes" {
        BeforeEach {
            Clear-TraefikAccessLogs
            Remove-AllTestDecisions
        }

        It "Should block after the stream poll when CrowdSec bans the enriched country" {
            $ready = Wait-ForCondition -Description "Stream mode to allow public IP before Country probe" -TimeoutSeconds 30 -RetryIntervalSeconds 2 -Condition {
                $response = Test-HttpRequest -Endpoint "/scope-stream" -IP $script:PublicIP -TraefikUrl $script:TraefikUrl
                return ($response.StatusCode -eq 200)
            }
            $ready.Success | Should -Be $true -Because "stale Country cache from the none-mode test must drain before the probe"

            $probe = Test-HttpRequest -Endpoint "/scope-stream" -IP $script:PublicIP -TraefikUrl $script:TraefikUrl
            $probe.StatusCode | Should -Be 200
            $country = Get-WhoamiCountryCode -Content $probe.Content
            $country | Should -Match '^[A-Z]{2}$' -Because "geoblock must enrich X-IPCountry for a public IP"

            Add-TestScopeDecision -Scope "Country" -Value $country -Type "ban"

            $result = Wait-ForCondition -Description "Stream mode to block Country $country" -TimeoutSeconds 45 -RetryIntervalSeconds 2 -Condition {
                $response = Test-HttpRequest -Endpoint "/scope-stream" -IP $script:PublicIP -TraefikUrl $script:TraefikUrl
                return ($response.StatusCode -in @(403, 429))
            }
            $result.Success | Should -Be $true -Because "Stream scopes= must include Country"
        }
    }

    Context "Ip spelling in none mode" -Tag "scopes" {
        BeforeEach {
            Clear-TraefikAccessLogs
            Remove-AllTestDecisions
        }

        It "Should block an expanded IPv6 ban under a compressed request spelling" {
            Assert-IpSpellingBan -Endpoint "/scope-none" -Stored "2001:0db8:0000:0000:0000:0000:00b1:0001" -Request "2001:db8::b1:1"
        }

        It "Should block an upper-case IPv6 ban under a lower-case request spelling" {
            Assert-IpSpellingBan -Endpoint "/scope-none" -Stored "2001:DB8::B1:2" -Request "2001:db8::b1:2"
        }

        It "Should block an IPv4-mapped ban under a dotted request spelling" {
            Assert-IpSpellingBan -Endpoint "/scope-none" -Stored "::ffff:10.59.0.81" -Request "10.59.0.81"
        }
    }

    Context "Ip spelling in stream mode" -Tag "scopes" {
        BeforeEach {
            Clear-TraefikAccessLogs
            Remove-AllTestDecisions
        }

        It "Should block an expanded IPv6 ban under a compressed request spelling after the stream poll" {
            Assert-IpSpellingBan -Endpoint "/scope-stream" -Stored "2001:0db8:0000:0000:0000:0000:00b2:0001" -Request "2001:db8::b2:1" -TimeoutSeconds 45
        }

        It "Should block an upper-case IPv6 ban under a lower-case request spelling after the stream poll" {
            Assert-IpSpellingBan -Endpoint "/scope-stream" -Stored "2001:DB8::B2:2" -Request "2001:db8::b2:2" -TimeoutSeconds 45
        }

        It "Should block an IPv4-mapped ban under a dotted request spelling after the stream poll" {
            Assert-IpSpellingBan -Endpoint "/scope-stream" -Stored "::ffff:10.59.0.82" -Request "10.59.0.82" -TimeoutSeconds 45
        }
    }
}
