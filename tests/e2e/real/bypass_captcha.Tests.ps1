#!/usr/bin/env pwsh

# bypassCaptcha action rule against real Traefik, LAPI, and AppSec.
# Under <prefix>/api/ a captcha is never served: the request continues. Bans still apply.
# /bypass-captcha runs LAPI and AppSec. /bypass-captcha-paths runs LAPI only, so the path
# the rule sees is decided by Traefik alone (config/dynamic/bypass-captcha.yml).
#
# Upstream covers the LAPI part of this with a per-middleware switch
# (maxlerebourg/crowdsec-bouncer-traefik-plugin#432, remediationCaptchaContinue).

BeforeAll {
    . "$PSScriptRoot/TestUtils.ps1"

    $script:TraefikUrl = "http://localhost:8000"
    $script:CaptchaMarker = "E2E captcha challenge"
    $script:SqlInjection = "id=1%27%20OR%20%271%27%3D%271"

    foreach ($route in @("/bypass-captcha", "/bypass-captcha-paths")) {
        $ready = Wait-ForHttpStatus -Url "$($script:TraefikUrl)$route" -Headers @{ "X-Forwarded-For" = "172.19.0.69" } -ExpectedStatusCodes @(200) -TimeoutSeconds 60
        if (-not $ready.Success) {
            throw "$route did not become ready"
        }
    }
}

Describe "bypassCaptcha action rule" {
    BeforeEach {
        Remove-AllTestDecisions
    }

    AfterAll {
        Remove-AllTestDecisions
    }

    Context "CrowdSec captcha decision" -Tag "captcha", "appsec" {
        It "Should serve the captcha on a web path and let the API path through when the decision covers <Name>" -ForEach @(
            @{ Name = "the client IP"; IP = "172.19.0.60"; Range = "" }
            @{ Name = "the client network"; IP = "172.19.60.7"; Range = "172.19.60.0/24" }
        ) {
            if ($Range) {
                Add-TestRangeDecision -Range $Range -Type "captcha"
            }
            else {
                Add-TestDecision -IP $IP -Type "captcha"
            }

            $web = Test-HttpRequest -Endpoint "/bypass-captcha/web" -IP $IP -TraefikUrl $script:TraefikUrl
            $web.StatusCode | Should -Be 200
            $web.Content | Should -Match $script:CaptchaMarker -Because "a path the rule does not match still gets the captcha"
            [string]$web.Headers["X-Crowdsec-Remediation"] | Should -Be "captcha:lapi:cscli"

            $api = Test-HttpRequest -Endpoint "/bypass-captcha/api/items" -IP $IP -TraefikUrl $script:TraefikUrl
            $api.StatusCode | Should -Be 200
            $api.Content | Should -Match "Hostname:" -Because "an API client cannot solve a captcha, so the rule sends the request to the application"
            $api.Content | Should -Not -Match $script:CaptchaMarker
            [string]$api.Headers["X-Crowdsec-Remediation"] | Should -BeNullOrEmpty -Because "a bypassed captcha is not a remediation"
        }

        It "Should still block an attack on the API path with AppSec" {
            $ip = "172.19.0.61"
            Add-TestDecision -IP $ip -Type "captcha"

            $attack = Test-HttpRequest -Endpoint "/bypass-captcha/api/items?$($script:SqlInjection)" -IP $ip -TraefikUrl $script:TraefikUrl
            $attack.StatusCode | Should -Be 403 -Because "the rule skips no check: AppSec inspects the request that got no captcha"
            [string]$attack.Headers["X-Crowdsec-Remediation"] | Should -Be "ban:appsec"
        }

        It "Should still ban on the API path and on a web path for a ban decision" {
            $ip = "172.19.0.62"
            Add-TestDecision -IP $ip -Type "ban"

            foreach ($endpoint in @("/bypass-captcha/api/items", "/bypass-captcha/web")) {
                $response = Test-HttpRequest -Endpoint $endpoint -IP $ip -TraefikUrl $script:TraefikUrl
                $response.StatusCode | Should -Be 403 -Because "bypassCaptcha weakens only the captcha; $endpoint must stay banned"
                [string]$response.Headers["X-Crowdsec-Remediation"] | Should -Be "ban:lapi:cscli"
            }
        }

        It "Should count the served captcha as dropped and not the bypassed API requests" -Tag "metrics" {
            $ip = "172.19.0.63"
            # An origin no other test uses, so drops of earlier tests still waiting to be reported do not count.
            $origin = "lists:e2e_bypass_captcha"
            Add-TestOriginDecision -IP $ip -Origin "lists" -Scenario "e2e_bypass_captcha" -Type "captcha"
            $before = Get-CscliBouncerMetricValue -Origin $origin -Name "dropped" -Unit "request"

            foreach ($attempt in 1..3) {
                $api = Test-HttpRequest -Endpoint "/bypass-captcha/api/items" -IP $ip -TraefikUrl $script:TraefikUrl
                $api.Content | Should -Match "Hostname:"
            }
            # Sent last: once this drop shows in cscli, the three API requests before it were reported too.
            $web = Test-HttpRequest -Endpoint "/bypass-captcha/web" -IP $ip -TraefikUrl $script:TraefikUrl
            $web.Content | Should -Match $script:CaptchaMarker

            $reported = Wait-ForCondition -Description "the served captcha in cscli metrics" -TimeoutSeconds 30 -RetryIntervalSeconds 1 -Condition {
                $after = Get-CscliBouncerMetricValue -Origin $origin -Name "dropped" -Unit "request"
                return ($after -gt $before)
            }
            $reported.Success | Should -Be $true -Because "the captcha page served on /web is a drop"
            $after = Get-CscliBouncerMetricValue -Origin $origin -Name "dropped" -Unit "request"
            ($after - $before) | Should -Be 1 -Because "only the captcha page is a drop; the three bypassed API requests are not"
        }
    }

    # CrowdSec answers these paths with the AppSec captcha verdict (config/appsec-configs/e2e-captcha-verdict.yaml).
    # Upstream's remediationCaptchaContinue does not reach this captcha: it only reads LAPI decisions.
    Context "AppSec captcha verdict" -Tag "captcha", "appsec" {
        It "Should serve the AppSec captcha on a web path and let the API path through" {
            $ip = "172.19.0.64"

            $web = Test-HttpRequest -Endpoint "/bypass-captcha/captcha-verdict" -IP $ip -TraefikUrl $script:TraefikUrl
            $web.StatusCode | Should -Be 200
            $web.Content | Should -Match $script:CaptchaMarker
            [string]$web.Headers["X-Crowdsec-Remediation"] | Should -Be "captcha:appsec"

            $api = Test-HttpRequest -Endpoint "/bypass-captcha/api/captcha-verdict" -IP $ip -TraefikUrl $script:TraefikUrl
            $api.StatusCode | Should -Be 200
            $api.Content | Should -Match "Hostname:" -Because "the rule also covers a captcha that AppSec asks for"
            $api.Content | Should -Not -Match $script:CaptchaMarker
        }
    }

    # The rule matches the path as the plugin receives it and relies on Traefik having cleaned it.
    # These rows are the README table "How the path is matched", measured on the Traefik version
    # this stack pins. A Traefik upgrade that changes a row changes who skips the captcha:
    # update the README table with the test.
    Context "Path handling by Traefik" -Tag "captcha" {
        BeforeEach {
            $script:PathIP = "172.19.0.65"
            Add-TestDecision -IP $script:PathIP -Type "captcha"
        }

        It "Should serve the captcha for <Target>, which Traefik resolves out of the API prefix" -ForEach @(
            @{ Target = "/bypass-captcha-paths/api/../admin" }
            @{ Target = "/bypass-captcha-paths/api/%2e%2e/admin" }
            # Resolved from Traefik v3.7.18. Earlier versions forward it unchanged and the captcha is bypassed.
            @{ Target = "/bypass-captcha-paths/api/..;/admin" }
        ) {
            $response = Invoke-RawHttpGet -RequestTarget $Target -IP $script:PathIP
            $response.StatusCode | Should -Be 200
            $response.Content | Should -Match $script:CaptchaMarker -Because "the plugin receives /bypass-captcha-paths/admin, which the rule does not match"
            $response.Content | Should -Not -Match "Hostname:"
        }

        It "Should bypass the captcha for <Target>, which Traefik forwards as <Forwarded>" -ForEach @(
            @{ Target = "/bypass-captcha-paths/api/items"; Forwarded = "/bypass-captcha-paths/api/items" }
            @{ Target = "/bypass-captcha-paths/api/items%20x"; Forwarded = "/bypass-captcha-paths/api/items%20x" }
            @{ Target = "/bypass-captcha-paths/api/..%2Fadmin"; Forwarded = "/bypass-captcha-paths/api/..%2Fadmin" }
            @{ Target = "/bypass-captcha-paths/api/..%5Cadmin"; Forwarded = "/bypass-captcha-paths/api/..%5Cadmin" }
            @{ Target = "/bypass-captcha-paths/api/..%3B/admin"; Forwarded = "/bypass-captcha-paths/api/..%3B/admin" }
            @{ Target = "/bypass-captcha-paths/api/%252e%252e/admin"; Forwarded = "/bypass-captcha-paths/api/%252e%252e/admin" }
            @{ Target = "/bypass-captcha-paths/api/..\admin"; Forwarded = "/bypass-captcha-paths/api/..%5Cadmin" }
        ) {
            $response = Invoke-RawHttpGet -RequestTarget $Target -IP $script:PathIP
            $response.StatusCode | Should -Be 200
            $response.Content | Should -Not -Match $script:CaptchaMarker -Because "Traefik leaves the path under /api/, so the rule matches"
            $response.Content | Should -Match ("(?m)^GET " + [regex]::Escape($Forwarded) + " HTTP") -Because "the application receives the path Traefik forwarded"
        }

        It "Should block <Target> with AppSec on the router that runs it" -ForEach @(
            @{ Target = "/bypass-captcha/api/..%2Fadmin" }
            @{ Target = "/bypass-captcha/api/..%5Cadmin" }
            @{ Target = "/bypass-captcha/api/%252e%252e/admin" }
        ) {
            $response = Invoke-RawHttpGet -RequestTarget $Target -IP $script:PathIP
            $response.StatusCode | Should -Be 403 -Because "the captcha is bypassed, and AppSec then bans the encoded traversal"
            [string]$response.Headers["X-Crowdsec-Remediation"] | Should -Be "ban:appsec"
        }
    }
}
