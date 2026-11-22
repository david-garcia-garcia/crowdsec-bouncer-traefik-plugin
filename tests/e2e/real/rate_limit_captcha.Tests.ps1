#!/usr/bin/env pwsh

# Captcha buckets against real Traefik, Dragonfly, and the stack's custom-provider test captcha
# (config/dynamic/rate-limit-captcha.yml). Policy: captcha bucket per-ip-soft (2 per hour) listed before
# ratelimit bucket per-ip-hard (5 per hour), both keyed on the client address.
# Counters live in Dragonfly for two windows and survive between runs, so every case takes a client
# address no other case and no recent run uses: one random /24 per run, one host per case.

BeforeAll {
    . "$PSScriptRoot/TestUtils.ps1"

    $script:TraefikUrl = "http://localhost:8000"
    $script:RunPrefix = "10.$(Get-Random -Minimum 1 -Maximum 255).$(Get-Random -Minimum 0 -Maximum 255)"
    $script:CaptchaMarker = "E2E captcha challenge"
    $script:FormHeaders = @{ "Content-Type" = "application/x-www-form-urlencoded" }
    # The stack's challenge page posts the marker and the dummy provider's answer.
    $script:ChallengeForm = "crowdsec_captcha_challenge=v1&dummy-captcha-response=ok"

    # Client address number $HostNumber of this run, inside the random /24 of this run.
    function Get-CaptchaBucketClientIP {
        param([int]$HostNumber)
        return "$($script:RunPrefix).$HostNumber"
    }

    # Sends $Count GET requests to $Endpoint from $IP and returns the responses in order.
    function Send-CaptchaBucketRequests {
        param([string]$Endpoint, [string]$IP, [int]$Count, [hashtable]$ExtraHeaders = @{})
        return @(foreach ($attempt in 1..$Count) {
                Test-HttpRequest -Endpoint $Endpoint -IP $IP -TraefikUrl $script:TraefikUrl -ExtraHeaders $ExtraHeaders
            })
    }

    # Lines Traefik logged for middleware $TraefikName that contain every string in $Contains.
    function Get-RouterLogLines {
        param([string]$TraefikName, [string[]]$Contains)
        $lines = (docker logs traefik-test 2>&1 | Out-String) -split "`r?`n"
        $pattern = '"traefikName":"' + [regex]::Escape($TraefikName) + '(@file)?"'
        return @($lines | Where-Object {
                $line = $_
                $line -match $pattern -and @($Contains | Where-Object { -not $line.Contains($_) }).Count -eq 0
            })
    }

    # The routers are up once the shared policy answers: a fresh address on the router without a captcha
    # gets the ratelimit answer of per-ip-soft on its third request.
    $bound = Wait-ForHttpStatus -Url "$($script:TraefikUrl)/rl-captcha-nocaptcha/ready" -Headers @{ "X-Forwarded-For" = (Get-CaptchaBucketClientIP -HostNumber 250) } -ExpectedStatusCodes @(429) -TimeoutSeconds 60
    if (-not $bound.Success) {
        throw "/rl-captcha-nocaptcha/ did not bind the rl-captcha policy"
    }
    $ready = Wait-ForHttpStatus -Url "$($script:TraefikUrl)/rl-captcha/ready" -Headers @{ "X-Forwarded-For" = (Get-CaptchaBucketClientIP -HostNumber 249) } -ExpectedStatusCodes @(200) -TimeoutSeconds 60
    if (-not $ready.Success) {
        throw "/rl-captcha/ did not become ready"
    }
}

Describe "Rate-limit captcha buckets" {
    Context "router with a captcha" -Tag "ratelimit", "captcha" {
        It "Should challenge over the captcha bucket and answer the ratelimit bucket after that, in list order captcha first" {
            $ip = Get-CaptchaBucketClientIP -HostNumber 1
            $responses = Send-CaptchaBucketRequests -Endpoint "/rl-captcha/page" -IP $ip -Count 6

            foreach ($attempt in 0..1) {
                $responses[$attempt].StatusCode | Should -Be 200
                $responses[$attempt].Content | Should -Match "Hostname:" -Because "request $($attempt + 1) is within both buckets"
                [string]$responses[$attempt].Headers["X-Crowdsec-Remediation"] | Should -BeNullOrEmpty
            }
            foreach ($attempt in 2..4) {
                $responses[$attempt].StatusCode | Should -Be 200
                $responses[$attempt].Content | Should -Match $script:CaptchaMarker -Because "request $($attempt + 1) is over per-ip-soft only"
                [string]$responses[$attempt].Headers["X-Crowdsec-Remediation"] | Should -Be "captcha:ratelimit:per-ip-soft"
                [string]$responses[$attempt].Headers["Retry-After"] | Should -BeNullOrEmpty -Because "a challenge page is not a rate-limit answer"
            }
            $responses[5].StatusCode | Should -Be 429 -Because "request 6 is over per-ip-hard, which wins over the captcha bucket listed before it"
            [string]$responses[5].Headers["X-Crowdsec-Remediation"] | Should -Be "ban:ratelimit:per-ip-hard"
            [int]([string]$responses[5].Headers["Retry-After"]) | Should -BeGreaterThan 0
        }

        It "Should let a solved client skip the captcha bucket until the ratelimit bucket answers" {
            $ip = Get-CaptchaBucketClientIP -HostNumber 2
            $responses = Send-CaptchaBucketRequests -Endpoint "/rl-captcha/page" -IP $ip -Count 3
            [string]$responses[2].Headers["X-Crowdsec-Remediation"] | Should -Be "captcha:ratelimit:per-ip-soft"

            # The challenge page's form: marker plus the dummy provider's answer. Not charged.
            $solve = Test-HttpRequest -Endpoint "/rl-captcha/page" -IP $ip -TraefikUrl $script:TraefikUrl `
                -Method POST -Body $script:ChallengeForm -ExtraHeaders $script:FormHeaders -MaximumRedirection 0
            $solve.StatusCode | Should -Be 302 -Because "the gate validates the challenge form; status=$($solve.StatusCode) content=$($solve.Content)"
            $setCookie = [string]$solve.Headers["Set-Cookie"]
            $setCookie | Should -Match "crowdsec_captcha_gate="
            $cookieHeaders = @{ Cookie = ($setCookie -split ';')[0].Trim() }

            # per-ip-hard counted the 3 GETs; with the gate, requests 4 and 5 reach the backend, 6 is over.
            $solved = Send-CaptchaBucketRequests -Endpoint "/rl-captcha/page" -IP $ip -Count 3 -ExtraHeaders $cookieHeaders
            foreach ($attempt in 0..1) {
                $solved[$attempt].StatusCode | Should -Be 200
                $solved[$attempt].Content | Should -Match "Hostname:" -Because "a solved client is not counted by per-ip-soft"
                [string]$solved[$attempt].Headers["X-Crowdsec-Remediation"] | Should -BeNullOrEmpty
            }
            $solved[2].StatusCode | Should -Be 429 -Because "the gate does not exempt the client from per-ip-hard"
            [string]$solved[2].Headers["X-Crowdsec-Remediation"] | Should -Be "ban:ratelimit:per-ip-hard"
        }

        It "Should not charge the challenge-form POST or the widget asset of a client over both buckets" {
            $ip = Get-CaptchaBucketClientIP -HostNumber 3
            $responses = Send-CaptchaBucketRequests -Endpoint "/rl-captcha/page" -IP $ip -Count 6
            $responses[5].StatusCode | Should -Be 429

            $widget = Test-HttpRequest -Endpoint "/rl-captcha/widget.js" -IP $ip -TraefikUrl $script:TraefikUrl
            $widget.StatusCode | Should -Be 200 -Because "the captcha page's widget asset is not charged"
            $widget.Content | Should -Match "Hostname:"
            [string]$widget.Headers["X-Crowdsec-Remediation"] | Should -BeNullOrEmpty

            $post = Test-HttpRequest -Endpoint "/rl-captcha/page" -IP $ip -TraefikUrl $script:TraefikUrl `
                -Method POST -Body $script:ChallengeForm -ExtraHeaders $script:FormHeaders -MaximumRedirection 0
            $post.StatusCode | Should -Be 302 -Because "the challenge-form POST is not charged; the captcha gate answers it"
            [string]$post.Headers["X-Crowdsec-Remediation"] | Should -Be "captcha:solved"
            $post.Content | Should -Not -Match "Hostname:" -Because "the form never reaches the application"
        }

        It "Should challenge again a challenge-form POST with a wrong answer and not charge it" {
            $ip = Get-CaptchaBucketClientIP -HostNumber 5
            $responses = Send-CaptchaBucketRequests -Endpoint "/rl-captcha/page" -IP $ip -Count 5
            [string]$responses[4].Headers["X-Crowdsec-Remediation"] | Should -Be "captcha:ratelimit:per-ip-soft"

            # per-ip-hard is now at its limit of 5: a charged POST would be the 429.
            $wrong = Test-HttpRequest -Endpoint "/rl-captcha/page" -IP $ip -TraefikUrl $script:TraefikUrl `
                -Method POST -Body "crowdsec_captcha_challenge=v1&dummy-captcha-response=" -ExtraHeaders $script:FormHeaders -MaximumRedirection 0
            $wrong.StatusCode | Should -Be 200
            $wrong.Content | Should -Match $script:CaptchaMarker -Because "a wrong answer gets the challenge page again"
            [string]$wrong.Headers["X-Crowdsec-Remediation"] | Should -Be "captcha:ratelimit" -Because "no bucket answered the form"
            [string]$wrong.Headers["Set-Cookie"] | Should -Not -Match "crowdsec_captcha_gate="
        }

        It "Should answer a bypassCaptcha path over the captcha bucket with the ratelimit answer" {
            $ip = Get-CaptchaBucketClientIP -HostNumber 4
            $responses = Send-CaptchaBucketRequests -Endpoint "/rl-captcha/api/items" -IP $ip -Count 3

            foreach ($attempt in 0..1) {
                $responses[$attempt].StatusCode | Should -Be 200
                $responses[$attempt].Content | Should -Match "Hostname:"
            }
            $responses[2].StatusCode | Should -Be 429 -Because "bypassCaptcha turns the captcha bucket into its ratelimit answer, not into no limit"
            [string]$responses[2].Headers["X-Crowdsec-Remediation"] | Should -Be "ban:ratelimit:per-ip-soft"
            [int]([string]$responses[2].Headers["Retry-After"]) | Should -BeGreaterThan 0
            $responses[2].Content | Should -Not -Match $script:CaptchaMarker
        }

        It "Should charge a challenge-form POST on a bypassCaptcha path, where no captcha gate answers it" {
            $ip = Get-CaptchaBucketClientIP -HostNumber 6
            # The marker does not exempt a POST the gate will not answer: each one counts like any request.
            $responses = @(foreach ($attempt in 1..3) {
                    Test-HttpRequest -Endpoint "/rl-captcha/api/items" -IP $ip -TraefikUrl $script:TraefikUrl `
                        -Method POST -Body $script:ChallengeForm -ExtraHeaders $script:FormHeaders -MaximumRedirection 0
                })

            foreach ($attempt in 0..1) {
                $responses[$attempt].StatusCode | Should -Be 200 -Because "POST $($attempt + 1) is within per-ip-soft and reaches the application"
                $responses[$attempt].Content | Should -Match "Hostname:"
            }
            $responses[2].StatusCode | Should -Be 429 -Because "the marker POSTs were charged: the third is over per-ip-soft, answered as ratelimit on a bypassCaptcha path"
            [string]$responses[2].Headers["X-Crowdsec-Remediation"] | Should -Be "ban:ratelimit:per-ip-soft"
            $responses[2].Content | Should -Not -Match "Hostname:"
        }
    }

    Context "router without a captcha" -Tag "ratelimit" {
        It "Should answer the captcha bucket with 429 and log the missing captcha once per bind, not per request" {
            $ip = Get-CaptchaBucketClientIP -HostNumber 10
            $router = "rl-captcha-nocaptcha"
            $bindErrorsBefore = @(Get-RouterLogLines -TraefikName $router -Contains @("crowdsec bouncer rate limit captcha unavailable", '"reason":"unsubscribed"'))
            $binds = @(Get-RouterLogLines -TraefikName $router -Contains @("crowdsec bouncer bound", '"leg":"ratelimit"'))
            $since = Get-LogSince

            $responses = Send-CaptchaBucketRequests -Endpoint "/rl-captcha-nocaptcha/page" -IP $ip -Count 4
            foreach ($attempt in 0..1) {
                $responses[$attempt].StatusCode | Should -Be 200
            }
            foreach ($attempt in 2..3) {
                $responses[$attempt].StatusCode | Should -Be 429 -Because "no captcha: the captcha bucket answers as ratelimit"
                [string]$responses[$attempt].Headers["X-Crowdsec-Remediation"] | Should -Be "ban:ratelimit:per-ip-soft"
                $responses[$attempt].Content | Should -Not -Match $script:CaptchaMarker
            }

            $bindErrorsBefore.Count | Should -BeGreaterThan 0 -Because "the bind of a policy with a captcha bucket logs the missing captcha"
            $bindErrorsBefore.Count | Should -Be $binds.Count -Because "one ERROR per bind of the rate-limit client"
            $bindErrorsAfter = @(Get-RouterLogLines -TraefikName $router -Contains @("crowdsec bouncer rate limit captcha unavailable"))
            $bindErrorsAfter.Count | Should -Be $bindErrorsBefore.Count -Because "the downgraded requests add no ERROR"
            $warns = @(Get-ContainerLogLines -Container "traefik-test" -Since $since -Contains @("crowdsec bouncer captcha unsubscribed"))
            $warns.Count | Should -Be 0 -Because "a rate-limit captcha downgrade never warns per request"
            $downgrades = @(Get-ContainerLogLines -Container "traefik-test" -Since $since -Contains @("rateLimitCaptchaDowngrade", $ip))
            $downgrades.Count | Should -Be 2 -Because "each downgraded request logs DEBUG"
        }
    }
}
