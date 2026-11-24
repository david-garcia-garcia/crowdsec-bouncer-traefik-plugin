#!/usr/bin/env pwsh

# Redis rate limit against real Traefik, Dragonfly, and LAPI (config/dynamic/rate-limit.yml).
# Counters live in Dragonfly for two windows and survive between runs, so every case takes a
# client address no other case and no recent run uses: one random /24 per run, one host per case.

BeforeAll {
    . "$PSScriptRoot/TestUtils.ps1"

    $script:TraefikUrl = "http://localhost:8000"
    $script:RunPrefix = "10.$(Get-Random -Minimum 1 -Maximum 255).$(Get-Random -Minimum 0 -Maximum 255)"

    # Client address number $HostNumber of this run, inside the random /24 of this run.
    function Get-RateLimitClientIP {
        param([int]$HostNumber)
        return "$($script:RunPrefix).$HostNumber"
    }

    foreach ($route in @(
            @{ Path = "/rate-limit/ready"; Status = 200 }
            @{ Path = "/rate-limit-log/ready"; Status = 200 }
            @{ Path = "/rate-limit-down-pass/ready"; Status = 200 }
            @{ Path = "/rate-limit-down-ban/ready"; Status = 403 }
            @{ Path = "/rate-limit-down-backoff/ready"; Status = 403 }
            @{ Path = "/rate-limit-down-local/ready"; Status = @(200, 429) }
            @{ Path = "/rate-limit-token-bucket/ready"; Status = @(200, 429) }
        )) {
        $ready = Wait-ForHttpStatus -Url "$($script:TraefikUrl)$($route.Path)" -Headers @{ "X-Forwarded-For" = (Get-RateLimitClientIP -HostNumber 250) } -ExpectedStatusCodes @($route.Status) -TimeoutSeconds 60
        if (-not $ready.Success) {
            throw "$($route.Path) did not become ready"
        }
    }
}

Describe "Redis rate limit" {
    Context "ratelimit bucket" -Tag "ratelimit" {
        It "Should answer 429 with the counter's Retry-After and ban:ratelimit:login after the limit" {
            $ip = Get-RateLimitClientIP -HostNumber 1
            # Keep the four hits in one 1m window: wait out its last 5 seconds.
            $secondsToWindowEnd = 60 - ([DateTimeOffset]::UtcNow.ToUnixTimeSeconds() % 60)
            if ($secondsToWindowEnd -lt 5) {
                Start-Sleep -Seconds ($secondsToWindowEnd + 1)
            }

            foreach ($attempt in 1..3) {
                $allowed = Test-HttpRequest -Endpoint "/rate-limit/login" -IP $ip -TraefikUrl $script:TraefikUrl
                $allowed.StatusCode | Should -Be 200 -Because "request $attempt of 3 is within the limit"
                [string]$allowed.Headers["X-Crowdsec-Remediation"] | Should -BeNullOrEmpty
            }
            $limited = Test-HttpRequest -Endpoint "/rate-limit/login" -IP $ip -TraefikUrl $script:TraefikUrl
            $limited.StatusCode | Should -Be 429
            [string]$limited.Headers["X-Crowdsec-Remediation"] | Should -Be "ban:ratelimit:login"
            $secondsToWindowEnd = 60 - ([DateTimeOffset]::UtcNow.ToUnixTimeSeconds() % 60)
            $retryAfter = [int]([string]$limited.Headers["Retry-After"])
            # 4 hits on a limit of 3: no admit in this window (no previous count to wait out). In the next one the
            # 4 weigh 4 x (1 - t/60), and 1 + that fits in 3 from t = 30s: Retry-After = time to window end + 30s.
            $retryAfter | Should -BeGreaterOrEqual ($secondsToWindowEnd + 29) -Because "the next admit is 30s into the next window"
            $retryAfter | Should -BeLessOrEqual ($secondsToWindowEnd + 31) -Because "the next admit is 30s into the next window"
        }

        It "Should not limit another client address with that counter" {
            $limited = Get-RateLimitClientIP -HostNumber 2
            $other = Get-RateLimitClientIP -HostNumber 3

            foreach ($attempt in 1..4) {
                $null = Test-HttpRequest -Endpoint "/rate-limit/login" -IP $limited -TraefikUrl $script:TraefikUrl
            }
            (Test-HttpRequest -Endpoint "/rate-limit/login" -IP $limited -TraefikUrl $script:TraefikUrl).StatusCode | Should -Be 429
            $response = Test-HttpRequest -Endpoint "/rate-limit/login" -IP $other -TraefikUrl $script:TraefikUrl
            $response.StatusCode | Should -Be 200 -Because "the bucket keys on the client address"
        }

        It "Should let a bypassRateLimit path through for a client over the limit" {
            $ip = Get-RateLimitClientIP -HostNumber 4

            foreach ($attempt in 1..4) {
                $null = Test-HttpRequest -Endpoint "/rate-limit/login" -IP $ip -TraefikUrl $script:TraefikUrl
            }
            (Test-HttpRequest -Endpoint "/rate-limit/login" -IP $ip -TraefikUrl $script:TraefikUrl).StatusCode | Should -Be 429
            foreach ($attempt in 1..2) {
                $health = Test-HttpRequest -Endpoint "/rate-limit/health" -IP $ip -TraefikUrl $script:TraefikUrl
                $health.StatusCode | Should -Be 200 -Because "the health rule skips the rate limit"
                $health.Content | Should -Match "Hostname:"
            }
        }

        It "Should count a ratelimit answer as a drop under plugin:ratelimit:login in cscli" -Tag "metrics" {
            $ip = Get-RateLimitClientIP -HostNumber 5
            $origin = "plugin:ratelimit:login"
            $before = Get-CscliBouncerMetricValue -Origin $origin -Name "dropped" -Unit "request"

            foreach ($attempt in 1..3) {
                $null = Test-HttpRequest -Endpoint "/rate-limit/login" -IP $ip -TraefikUrl $script:TraefikUrl
            }
            (Test-HttpRequest -Endpoint "/rate-limit/login" -IP $ip -TraefikUrl $script:TraefikUrl).StatusCode | Should -Be 429

            $reported = Wait-ForCondition -Description "the rate-limit drop in cscli metrics" -TimeoutSeconds 45 -RetryIntervalSeconds 1 -Condition {
                $after = Get-CscliBouncerMetricValue -Origin $origin -Name "dropped" -Unit "request"
                return ($after -gt $before)
            }
            $reported.Success | Should -Be $true -Because "a ratelimit answer is a drop with the bucket origin"
        }
    }

    Context "log bucket" -Tag "ratelimit" {
        It "Should never answer and set no remediation header" {
            $ip = Get-RateLimitClientIP -HostNumber 10

            foreach ($attempt in 1..3) {
                $response = Test-HttpRequest -Endpoint "/rate-limit-log/page" -IP $ip -TraefikUrl $script:TraefikUrl
                $response.StatusCode | Should -Be 200 -Because "a log bucket over its limit only logs"
                [string]$response.Headers["X-Crowdsec-Remediation"] | Should -BeNullOrEmpty
            }
        }
    }

    Context "Redis unreachable" -Tag "ratelimit" {
        It "Should let the request through with failure action passthrough" {
            $ip = Get-RateLimitClientIP -HostNumber 20

            foreach ($attempt in 1..2) {
                $response = Test-HttpRequest -Endpoint "/rate-limit-down-pass/page" -IP $ip -TraefikUrl $script:TraefikUrl
                $response.StatusCode | Should -Be 200
                $response.Content | Should -Match "Hostname:"
                [string]$response.Headers["X-Crowdsec-Remediation"] | Should -BeNullOrEmpty
            }
        }

        It "Should answer ban:ratelimit-failure with failure action ban" {
            $ip = Get-RateLimitClientIP -HostNumber 21

            $response = Test-HttpRequest -Endpoint "/rate-limit-down-ban/page" -IP $ip -TraefikUrl $script:TraefikUrl
            $response.StatusCode | Should -Be 403 -Because "the failure action ban uses bouncerRemediationStatusCode"
            [string]$response.Headers["X-Crowdsec-Remediation"] | Should -Be "ban:ratelimit-failure"
        }

        It "Should stop calling Redis after 5 failures and answer the backoff action" {
            $ip = Get-RateLimitClientIP -HostNumber 23

            # The readiness probe (or an earlier run on the same stack) may already have spent part of the
            # budget or tripped the gate, so count the failures before the first backoff answer instead of
            # expecting exactly 5. Requests are fast (connection refused), well inside the 10s cooldown.
            $answers = @()
            foreach ($attempt in 1..8) {
                $response = Test-HttpRequest -Endpoint "/rate-limit-down-backoff/page" -IP $ip -TraefikUrl $script:TraefikUrl
                $response.StatusCode | Should -Be 403 -Because "both the failure action and the backoff action are ban"
                $answers += [string]$response.Headers["X-Crowdsec-Remediation"]
            }
            $firstBackoff = [array]::IndexOf($answers, "ban:ratelimit-backoff")
            $firstBackoff | Should -BeGreaterOrEqual 0 -Because "the gate trips after 5 failures in a row (answers: $($answers -join ', '))"
            $firstBackoff | Should -BeLessOrEqual 5 -Because "at most 5 failures reach the failure action before the gate skips Redis (answers: $($answers -join ', '))"
            @($answers[0..($firstBackoff)] | Select-Object -SkipLast 1 | Where-Object { $_ -ne "ban:ratelimit-failure" }).Count | Should -Be 0 -Because "every answer before the trip is the failure action"
            @($answers[$firstBackoff..($answers.Count - 1)] | Where-Object { $_ -ne "ban:ratelimit-backoff" }).Count | Should -Be 0 -Because "inside the cooldown every request is skipped (answers: $($answers -join ', '))"

            $lines = (docker logs traefik-test 2>&1 | Out-String) -split "`r?`n"
            $started = @($lines | Where-Object { $_ -match '"traefikName":"bouncer-rate-limit-down-backoff(@file)?"' -and $_.Contains('"msg":"crowdsec ratelimit backoff started"') })
            $started.Count | Should -BeGreaterOrEqual 1 -Because "the gate logs WARN crowdsec ratelimit backoff started when it trips"
        }

        It "Should keep the replica's local limit in buffered mode instead of the failure action" {
            $ip = Get-RateLimitClientIP -HostNumber 22

            $allowed = Test-HttpRequest -Endpoint "/rate-limit-down-local/page" -IP $ip -TraefikUrl $script:TraefikUrl
            $allowed.StatusCode | Should -Be 200 -Because "the first request is within the local limit of 1"
            [string]$allowed.Headers["X-Crowdsec-Remediation"] | Should -BeNullOrEmpty

            $limited = Test-HttpRequest -Endpoint "/rate-limit-down-local/page" -IP $ip -TraefikUrl $script:TraefikUrl
            $limited.StatusCode | Should -Be 429 -Because "a buffered outage keeps counting locally, so failure action ban never applies"
            [string]$limited.Headers["X-Crowdsec-Remediation"] | Should -Be "ban:ratelimit:per-ip"
        }
    }
}

Describe "Redis rate limit with rateLimitAlgorithm tokenBucket" {
    Context "token bucket" -Tag "ratelimit" {
        It "Should admit the burst at once, answer the next with the refill time, and admit again after it" {
            $ip = Get-RateLimitClientIP -HostNumber 30

            foreach ($attempt in 1..3) {
                $allowed = Test-HttpRequest -Endpoint "/rate-limit-token-bucket/page" -IP $ip -TraefikUrl $script:TraefikUrl
                $allowed.StatusCode | Should -Be 200 -Because "request $attempt of a burst of 3"
                [string]$allowed.Headers["X-Crowdsec-Remediation"] | Should -BeNullOrEmpty
            }
            $limited = Test-HttpRequest -Endpoint "/rate-limit-token-bucket/page" -IP $ip -TraefikUrl $script:TraefikUrl
            $limited.StatusCode | Should -Be 429 -Because "the burst of 3 is spent"
            [string]$limited.Headers["X-Crowdsec-Remediation"] | Should -Be "ban:ratelimit:burst"
            $retryAfter = [int]([string]$limited.Headers["Retry-After"])
            # One token per 5s from an empty bucket, rounded up: 5 (4 only if the three requests took over 1s).
            $retryAfter | Should -BeGreaterOrEqual 4
            $retryAfter | Should -BeLessOrEqual 5 -Because "one token comes back every 5 seconds"

            # An answered request takes no token, so the client gets in again once Retry-After has passed.
            $again = Test-HttpRequest -Endpoint "/rate-limit-token-bucket/page" -IP $ip -TraefikUrl $script:TraefikUrl
            $again.StatusCode | Should -Be 429 -Because "no token is back yet"
            Start-Sleep -Milliseconds ($retryAfter * 1000 + 300)
            $refilled = Test-HttpRequest -Endpoint "/rate-limit-token-bucket/page" -IP $ip -TraefikUrl $script:TraefikUrl
            $refilled.StatusCode | Should -Be 200 -Because "one token refilled after Retry-After, and the answered requests took none"
            $refilled.Content | Should -Match "Hostname:"
            (Test-HttpRequest -Endpoint "/rate-limit-token-bucket/page" -IP $ip -TraefikUrl $script:TraefikUrl).StatusCode | Should -Be 429 -Because "only one token refilled"
        }

        It "Should not serve a router whose bucket sets algorithm, and log why" {
            $response = Test-HttpRequest -Endpoint "/rate-limit-bad-row/page" -IP (Get-RateLimitClientIP -HostNumber 31) -TraefikUrl $script:TraefikUrl
            $response.StatusCode | Should -Be 404 -Because "the middleware fails at startup, so Traefik does not serve the router"
            $logged = @(Get-ContainerLogLines -Container "traefik-test" -Since "1970-01-01T00:00:00Z" -Contains @('"routerName":"rate-limit-bad-row@file"', "RateLimitBuckets: bucket 0: algorithm: is not a bucket setting; set rateLimitAlgorithm"))
            $logged.Count | Should -BeGreaterThan 0 -Because "Traefik logs the plugin's startup error, which points at rateLimitAlgorithm"
        }
    }
}
