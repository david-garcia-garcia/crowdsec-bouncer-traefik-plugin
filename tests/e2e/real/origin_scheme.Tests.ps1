#!/usr/bin/env pwsh

# Real-stack Secure flag. Traefik stays on HTTP :80. The published-port peer is
# the compose gateway 172.28.0.1, which entrypoint trustedIPs already includes
# (172.16.0.0/12), so Traefik keeps X-Forwarded-Proto. CrowdSec mints
# __crowdsec_challenge on /origin-scheme via GrantChallengeCookie. The captcha
# route mints crowdsec_captcha_gate on a dummy solve.

BeforeAll {
    . "$PSScriptRoot/TestUtils.ps1"

    $script:TraefikUrl = "http://localhost:8000"
    $script:CrowdSecApiUrl = "http://localhost:8081"
    $script:ApiKey = "40796d93c2958f9e58345514e67740e5"
    $script:ClientIP = "172.19.0.60"

    $result = Wait-ForCondition -Description "CrowdSec LAPI to be ready" -TimeoutSeconds 60 -RetryIntervalSeconds 2 -Condition {
        Invoke-CrowdSecAPI -Endpoint "/v1/decisions?limit=1" -TimeoutSec 5 -ApiKey $script:ApiKey -CrowdSecApiUrl $script:CrowdSecApiUrl
        return $true
    }
    if (-not $result.Success) {
        throw "CrowdSec LAPI failed to become ready"
    }

    function script:Get-CookieSecure {
        param($Headers, [string]$CookieName)

        $raw = $Headers["Set-Cookie"]
        if ($null -eq $raw) {
            return $null
        }
        $lines = @()
        if ($raw -is [System.Array]) {
            $lines = @($raw | ForEach-Object { [string]$_ })
        } else {
            $lines = @([string]$raw)
        }
        foreach ($line in $lines) {
            $parts = $line -split ";"
            if ($parts[0].Trim() -notlike "$CookieName=*") {
                continue
            }
            foreach ($attr in ($parts | Select-Object -Skip 1)) {
                if ($attr.Trim() -ieq "Secure") {
                    return $true
                }
            }
            return $false
        }
        return $null
    }

    function script:Assert-BothCookiesSecure {
        param([string]$Proto, [bool]$WantSecure)

        $protoHeader = @{ "X-Forwarded-Proto" = $Proto }

        $challenge = Test-HttpRequest -Endpoint "/origin-scheme" -IP $script:ClientIP -TraefikUrl $script:TraefikUrl `
            -ExtraHeaders $protoHeader -MaximumRedirection 0
        $challenge.StatusCode | Should -Be 307 -Because "grant status=$($challenge.StatusCode) content=$($challenge.Content)"
        $challengeSecure = Get-CookieSecure -Headers $challenge.Headers -CookieName "__crowdsec_challenge"
        $challengeSecure | Should -Be $WantSecure -Because "proto=$Proto Set-Cookie=$($challenge.Headers['Set-Cookie'])"

        Add-TestDecision -IP $script:ClientIP -Type "captcha"
        $formHeaders = @{
            "Content-Type"      = "application/x-www-form-urlencoded"
            "X-Forwarded-Proto" = $Proto
        }
        $solve = Test-HttpRequest -Endpoint "/captcha" -IP $script:ClientIP -TraefikUrl $script:TraefikUrl `
            -Method POST -Body "dummy-captcha-response=ok" -ExtraHeaders $formHeaders -MaximumRedirection 0
        $solve.StatusCode | Should -Be 302 -Because "solve status=$($solve.StatusCode) content=$($solve.Content)"
        $gateSecure = Get-CookieSecure -Headers $solve.Headers -CookieName "crowdsec_captcha_gate"
        $gateSecure | Should -Be $WantSecure -Because "proto=$Proto Set-Cookie=$($solve.Headers['Set-Cookie'])"
    }
}

Describe "CrowdSec Bouncer origin scheme Secure cookies" {
    Context "Trusted X-Forwarded-Proto on the HTTP entrypoint" -Tag "appsec", "captcha" {
        BeforeEach {
            Clear-TraefikAccessLogs
            Remove-AllTestDecisions
        }

        It "Should mark both cookies Secure when proto is https" {
            Assert-BothCookiesSecure -Proto "https" -WantSecure $true
        }

        It "Should omit Secure on both cookies when proto is http" {
            Assert-BothCookiesSecure -Proto "http" -WantSecure $false
        }
    }
}
