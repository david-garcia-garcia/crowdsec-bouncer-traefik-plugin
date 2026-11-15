#!/usr/bin/env pwsh

# Real AppSec from upstream PR 333: OWASP CRS inband on a live Crowdsec engine.
# Not the mock suite's rpc2 stand-in.

BeforeAll {
    . "$PSScriptRoot/TestUtils.ps1"

    $script:TraefikUrl = "http://localhost:8000"
    $script:CrowdSecApiUrl = "http://localhost:8081"
    $script:ApiKey = "40796d93c2958f9e58345514e67740e5"
    $script:ClientIP = "172.19.0.40"

    $result = Wait-ForCondition -Description "CrowdSec LAPI to be ready" -TimeoutSeconds 60 -RetryIntervalSeconds 2 -Condition {
        Invoke-CrowdSecAPI -Endpoint "/v1/decisions?limit=1" -TimeoutSec 5 -ApiKey $script:ApiKey -CrowdSecApiUrl $script:CrowdSecApiUrl
        return $true
    }
    if (-not $result.Success) {
        throw "CrowdSec LAPI failed to become ready"
    }
}

Describe "CrowdSec Bouncer Real AppSec Tests" {
    Context "OWASP CRS inband" -Tag "appsec" {
        BeforeEach {
            Clear-TraefikAccessLogs
            Remove-AllTestDecisions
        }

        It "Should allow a benign AppSec request" {
            $response = Test-HttpRequest -Endpoint "/appsec" -IP $script:ClientIP -TraefikUrl $script:TraefikUrl
            $response.StatusCode | Should -Be 200
        }

        It "Should block a SQL-injection query string via CRS" {
            $response = Test-HttpRequest -Endpoint "/appsec?id=1%27%20OR%20%271%27%3D%271" -IP $script:ClientIP -TraefikUrl $script:TraefikUrl
            $response.StatusCode | Should -Be 403
        }
    }

    # CrowdSec 1.8.2 crowdsecurity/appsec-bot-challenge on listener 7423 (bouncer-bot, cscli bouncer BOT).
    # /crowdsec-internal/challenge has its own router through bouncer-bot whose service is that listener,
    # as the README asks; the listener itself answers a direct request with 401. Only the plugin relay
    # writes X-Remediation captcha:challenge, so that header tells a relay apart from a forward.
    Context "AppSec bot-detection challenge" -Tag "appsec", "bot-detection" {
        BeforeAll {
            $script:BotIP = "172.19.0.41"
            $script:Browser = @{
                "User-Agent" = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
            }

            function script:Get-FirstHeader {
                param($Headers, [string]$Name)
                $value = $Headers[$Name]
                if ($value -is [System.Array]) {
                    return [string]$value[0]
                }
                return [string]$value
            }

            # GrantChallengeCookie on /origin-scheme (e2e/origin-scheme-grant) mints a valid
            # __crowdsec_challenge without running the browser proof of work.
            function script:Get-GrantedChallengeCookie {
                $grant = Test-HttpRequest -Endpoint "/origin-scheme" -IP $script:BotIP -TraefikUrl $script:TraefikUrl `
                    -ExtraHeaders $script:Browser -MaximumRedirection 0
                $grant.StatusCode | Should -Be 307 -Because "grant status=$($grant.StatusCode)"
                foreach ($line in @($grant.Headers["Set-Cookie"])) {
                    $pair = ([string]$line -split ";")[0].Trim()
                    if ($pair -like "__crowdsec_challenge=*") {
                        return $pair
                    }
                }
                throw "no __crowdsec_challenge in Set-Cookie: $($grant.Headers['Set-Cookie'])"
            }

            function script:Get-BotAppsecDropped {
                return Get-CscliBouncerMetricValue -Bouncer "BOT" -Origin "appsec" -Name "dropped" -Unit "request"
            }
        }

        BeforeEach {
            Clear-TraefikAccessLogs
            Remove-AllTestDecisions
        }

        It "Should serve the CrowdSec challenge page to a browser with no challenge cookie" {
            $response = Test-HttpRequest -Endpoint "/bot-detection" -IP $script:BotIP -TraefikUrl $script:TraefikUrl -ExtraHeaders $script:Browser
            $response.StatusCode | Should -Be 200
            (Get-FirstHeader -Headers $response.Headers -Name "X-Remediation") | Should -Be "captcha:challenge"
            $response.Content | Should -Match "<title>CrowdSec Challenge</title>"
            $response.Content | Should -Not -Match "Hostname:" -Because "the origin whoami must not answer a challenged request"
        }

        It "Should relay the challenge script <Script> from AppSec" -TestCases @(
            @{ Script = "fpscanner.js" }
            @{ Script = "pow-worker.js" }
        ) {
            param($Script)
            $response = Test-HttpRequest -Endpoint "/crowdsec-internal/challenge/$Script" -IP $script:BotIP -TraefikUrl $script:TraefikUrl -ExtraHeaders $script:Browser
            $response.StatusCode | Should -Be 200
            (Get-FirstHeader -Headers $response.Headers -Name "X-Remediation") | Should -Be "captcha:challenge"
            $response.ContentType | Should -Match "javascript"
        }

        It "Should relay the challenge submit answer from AppSec" {
            $response = Test-HttpRequest -Endpoint "/crowdsec-internal/challenge/submit" -IP $script:BotIP -TraefikUrl $script:TraefikUrl `
                -Method POST -Body "{}" -ExtraHeaders ($script:Browser + @{ "Content-Type" = "application/json" })
            $response.StatusCode | Should -Be 200
            (Get-FirstHeader -Headers $response.Headers -Name "X-Remediation") | Should -Be "captcha:challenge"
            $response.Content | Should -Match '"status"' -Because "an unsolved submit is CrowdSec's JSON verdict, not the origin"
        }

        It "Should let a visitor with a valid challenge cookie through to origin" {
            $cookie = Get-GrantedChallengeCookie
            $response = Test-HttpRequest -Endpoint "/bot-detection" -IP $script:BotIP -TraefikUrl $script:TraefikUrl `
                -ExtraHeaders ($script:Browser + @{ "Cookie" = $cookie })
            $response.StatusCode | Should -Be 200
            $response.Content | Should -Match "Hostname:"
            (Get-FirstHeader -Headers $response.Headers -Name "X-Remediation") | Should -BeNullOrEmpty
        }

        It "Should answer 404 on a challenge path AppSec allows instead of forwarding it" {
            # With a valid cookie AppSec allows a challenge path it does not serve. The plugin answers 404;
            # forwarding would reach the listener service, which answers 401.
            $cookie = Get-GrantedChallengeCookie
            $response = Test-HttpRequest -Endpoint "/crowdsec-internal/challenge/e2e-unknown" -IP $script:BotIP -TraefikUrl $script:TraefikUrl `
                -ExtraHeaders ($script:Browser + @{ "Cookie" = $cookie })
            $response.StatusCode | Should -Be 404
            (Get-FirstHeader -Headers $response.Headers -Name "X-Remediation") | Should -BeNullOrEmpty
        }

        It "Should count a challenge page and its callbacks as one AppSec drop" -Tag "metrics" {
            # bouncer-bot posts usage metrics every 10s. Start from a settled count so earlier drops are already in.
            $settled = Wait-ForCondition -Description "BOT appsec dropped to settle" -TimeoutSeconds 60 -RetryIntervalSeconds 1 -Condition {
                $first = Get-BotAppsecDropped
                Start-Sleep -Seconds 12
                $script:SettledDropped = Get-BotAppsecDropped
                return ($script:SettledDropped -eq $first)
            }
            $settled.Success | Should -Be $true
            $before = $script:SettledDropped

            Test-HttpRequest -Endpoint "/bot-detection" -IP $script:BotIP -TraefikUrl $script:TraefikUrl -ExtraHeaders $script:Browser | Out-Null
            Test-HttpRequest -Endpoint "/crowdsec-internal/challenge/fpscanner.js" -IP $script:BotIP -TraefikUrl $script:TraefikUrl -ExtraHeaders $script:Browser | Out-Null
            Test-HttpRequest -Endpoint "/crowdsec-internal/challenge/pow-worker.js" -IP $script:BotIP -TraefikUrl $script:TraefikUrl -ExtraHeaders $script:Browser | Out-Null
            Test-HttpRequest -Endpoint "/crowdsec-internal/challenge/submit" -IP $script:BotIP -TraefikUrl $script:TraefikUrl `
                -Method POST -Body "{}" -ExtraHeaders ($script:Browser + @{ "Content-Type" = "application/json" }) | Out-Null

            $pushed = Wait-ForCondition -Description "BOT appsec dropped to increase" -TimeoutSeconds 30 -RetryIntervalSeconds 2 -Condition {
                return ((Get-BotAppsecDropped) -gt $before)
            }
            $pushed.Success | Should -Be $true -Because "the challenge page is a drop"
            Start-Sleep -Seconds 12
            ((Get-BotAppsecDropped) - $before) | Should -Be 1 -Because "fpscanner.js, pow-worker.js and submit are the same solve as the page"
        }
    }

    Context "AppSec request body and appsec mode" -Tag "appsec" {
        BeforeEach {
            Clear-TraefikAccessLogs
            Remove-AllTestDecisions
        }

        It "Should block SQL injection in a POST body via CRS" {
            $response = Test-HttpRequest -Endpoint "/appsec" -IP $script:ClientIP -TraefikUrl $script:TraefikUrl `
                -Method POST -Body "id=1' OR '1'='1" `
                -ExtraHeaders @{ "Content-Type" = "application/x-www-form-urlencoded" }
            $response.StatusCode | Should -Be 403 -Because "the plugin must forward the POST body to AppSec so CRS can inspect it"
        }

        It "Should still apply a LAPI ban on the AppSec-enabled none-mode route" {
            Add-TestDecision -IP $script:ClientIP -Type "ban"

            $response = Test-HttpRequest -Endpoint "/appsec" -IP $script:ClientIP -TraefikUrl $script:TraefikUrl
            $response.StatusCode | Should -BeIn @(403, 429) -Because "AppSec enabled does not skip LAPI decisions in none mode"
        }

        It "Should ignore a LAPI ban when LAPI is disabled" {
            Add-TestDecision -IP $script:ClientIP -Type "ban"

            $response = Test-HttpRequest -Endpoint "/waf-only" -IP $script:ClientIP -TraefikUrl $script:TraefikUrl
            $response.StatusCode | Should -Be 200 -Because "AppSec-only has no LAPI client and must not remediate IP bans"
            $response.Content | Should -Match "Hostname:"
        }

        It "Should still block SQLi when LAPI is disabled" {
            $response = Test-HttpRequest -Endpoint "/waf-only?id=1%27%20OR%20%271%27%3D%271" -IP $script:ClientIP -TraefikUrl $script:TraefikUrl
            $response.StatusCode | Should -Be 403
        }
    }

    # CrowdSec AppSec RateLimit() (config/appsec-configs/e2e-rate-limit.yaml, 2/m per client IP).
    # Upstream maxlerebourg/crowdsec-bouncer-traefik-plugin#421: the client must see 429, not 403.
    Context "AppSec RateLimit()" -Tag "appsec" {
        BeforeEach {
            Clear-TraefikAccessLogs
            Remove-AllTestDecisions
        }

        It "Should answer the request over the limit with 429 and the ban page" {
            # The bucket lives in CrowdSec memory per client IP; a fresh IP per run starts full.
            $rateLimitIP = "172.19.$(Get-Random -Minimum 100 -Maximum 250).$(Get-Random -Minimum 1 -Maximum 250)"

            # Requests under the limit reach the origin.
            foreach ($attempt in 1..2) {
                $allowed = Test-HttpRequest -Endpoint "/ratelimit" -IP $rateLimitIP -TraefikUrl $script:TraefikUrl
                $allowed.StatusCode | Should -Be 200 -Because "request $attempt of 2 is under the 2/m budget"
                $allowed.Content | Should -Match "Hostname:"
            }

            # The next request is over the limit: the bouncer keeps AppSec's 429 on the operator ban page.
            $blocked = Test-HttpRequest -Endpoint "/ratelimit" -IP $rateLimitIP -TraefikUrl $script:TraefikUrl
            $blocked.StatusCode | Should -Be 429 -Because "AppSec RateLimit() bans carry http_status 429; content=$($blocked.Content)"
            $blocked.Content | Should -Match "E2E_CUSTOM_BAN_PAGE_MARKER"
            [string]$blocked.Headers["X-Crowdsec-Remediation"] | Should -Be "ban:appsec"
        }

        It "Should keep bouncerRemediationStatusCode for a CRS ban on the same listener" {
            $response = Test-HttpRequest -Endpoint "/ratelimit?id=1%27%20OR%20%271%27%3D%271" -IP $script:ClientIP -TraefikUrl $script:TraefikUrl
            $response.StatusCode | Should -Be 403 -Because "only an AppSec ban with http_status 429 changes the status"
        }
    }
}
