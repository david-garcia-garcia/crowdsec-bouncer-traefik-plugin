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
            @{ Path = "/rate-limit-down-local/ready"; Status = @(200, 429) }
        )) {
        $ready = Wait-ForHttpStatus -Url "$($script:TraefikUrl)$($route.Path)" -Headers @{ "X-Forwarded-For" = (Get-RateLimitClientIP -HostNumber 250) } -ExpectedStatusCodes @($route.Status) -TimeoutSeconds 60
        if (-not $ready.Success) {
            throw "$($route.Path) did not become ready"
        }
    }
}

Describe "Redis rate limit" {
    Context "deny bucket" -Tag "ratelimit" {
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
            $denied = Test-HttpRequest -Endpoint "/rate-limit/login" -IP $ip -TraefikUrl $script:TraefikUrl
            $denied.StatusCode | Should -Be 429
            [string]$denied.Headers["X-Crowdsec-Remediation"] | Should -Be "ban:ratelimit:login"
            $secondsToWindowEnd = 60 - ([DateTimeOffset]::UtcNow.ToUnixTimeSeconds() % 60)
            $retryAfter = [int]([string]$denied.Headers["Retry-After"])
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

        It "Should count a deny as a drop under plugin:ratelimit:login in cscli" -Tag "metrics" {
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
            $reported.Success | Should -Be $true -Because "a rate-limit deny is a drop with the bucket origin"
        }
    }

    Context "log bucket" -Tag "ratelimit" {
        It "Should never deny and set no remediation header" {
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

        It "Should keep the replica's local limit in buffered mode instead of the failure action" {
            $ip = Get-RateLimitClientIP -HostNumber 22

            $allowed = Test-HttpRequest -Endpoint "/rate-limit-down-local/page" -IP $ip -TraefikUrl $script:TraefikUrl
            $allowed.StatusCode | Should -Be 200 -Because "the first request is within the local limit of 1"
            [string]$allowed.Headers["X-Crowdsec-Remediation"] | Should -BeNullOrEmpty

            $denied = Test-HttpRequest -Endpoint "/rate-limit-down-local/page" -IP $ip -TraefikUrl $script:TraefikUrl
            $denied.StatusCode | Should -Be 429 -Because "a buffered outage keeps counting locally, so failure action ban never applies"
            [string]$denied.Headers["X-Crowdsec-Remediation"] | Should -Be "ban:ratelimit:per-ip"
        }
    }
}
