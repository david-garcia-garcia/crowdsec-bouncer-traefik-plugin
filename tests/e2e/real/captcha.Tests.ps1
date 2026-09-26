#!/usr/bin/env pwsh

# Captcha Remediation Tests for CrowdSec Bouncer Traefik Plugin
# Tests bouncer behavior when applying captcha remediation

BeforeAll {
    # Import shared test utilities
    . "$PSScriptRoot/TestUtils.ps1"
    
    # Test configuration
    $script:TraefikUrl = "http://localhost:8000"
    $script:CrowdSecApiUrl = "http://localhost:8081"
    $script:ApiKey = "40796d93c2958f9e58345514e67740e5"
    $script:HttpTimeoutSeconds = [int]($env:HTTP_TIMEOUT_SECONDS ?? 30)
    
    # Test IP addresses - using Docker network IPs that the bouncer actually sees
        $script:TestIPs = @{
        BannedIP       = "172.19.0.1"
        CaptchaIP      = "172.19.0.2"
        CleanIP        = "172.19.0.3"
        CaptchaOtherIP = "172.19.0.4"
    }
    
    # Wait for CrowdSec LAPI to be ready
    $result = Wait-ForCondition -Description "CrowdSec LAPI to be ready" -TimeoutSeconds 60 -RetryIntervalSeconds 2 -Condition {
        Invoke-CrowdSecAPI -Endpoint "/v1/decisions?limit=1" -TimeoutSec 5 -ApiKey $script:ApiKey -CrowdSecApiUrl $script:CrowdSecApiUrl
        return $true
    }
    
    if (-not $result.Success) {
        throw "❌ CrowdSec LAPI failed to become ready"
    }
}

Describe "CrowdSec Bouncer Captcha Remediation Tests" {
    
    Context "Captcha Remediation Tests" -Tag "captcha" {
        
        BeforeEach {
            Clear-TraefikAccessLogs
            Remove-AllTestDecisions
        }
        
        It "Should show captcha remediation for captcha decision" {
            # Add captcha decision for the IP we'll test with
            Add-TestDecision -IP $script:TestIPs.CaptchaIP -Type "captcha"
            
            # Test captcha endpoint with the same IP
            $response = Test-HttpRequest -Endpoint "/captcha" -IP $script:TestIPs.CaptchaIP -TraefikUrl $script:TraefikUrl
            $response.StatusCode | Should -Be 200
            $response.Content | Should -Match "captcha|challenge"
            
            # Verify custom remediation header in Traefik access logs
            $logResult = Get-TraefikAccessLogs
            $logResult.Success | Should -Be $true -Because "Should be able to read Traefik access logs"
            
            # Find log entry for captcha endpoint with remediation header
            $result = Find-TraefikLogEntry -LogEntries $logResult.LogEntries -Description "captcha log entry with remediation header" -Condition {
                param($logEntry)
                return ($logEntry.RequestPath -eq "/captcha" -and $logEntry.'downstream_X-Crowdsec-Remediation' -eq "captcha:lapi:cscli")
            }
            
            $result.Found | Should -Be $true -Because "Custom remediation header should appear in Traefik access logs for captcha decisions"
            
            if ($result.Found) {
                $remediationHeader = $result.LogEntry.'downstream_X-Crowdsec-Remediation'
                Write-Host "  Header value: $remediationHeader" -ForegroundColor Green
                Write-Host "  Status code: $($result.LogEntry.DownstreamStatus)" -ForegroundColor Green
            }
        }
        
        It "Should fallback to ban when captcha is not configured" {
            # Add captcha decision for the IP we'll test with
            Add-TestDecision -IP $script:TestIPs.CaptchaIP -Type "captcha"
            
            # Test an endpoint without captcha configuration (should fallback to ban)
            $response = Test-HttpRequest -Endpoint "/whoami" -IP $script:TestIPs.CaptchaIP -TraefikUrl $script:TraefikUrl
            $response.StatusCode | Should -BeIn @(403, 429) -Because "Should fallback to ban when captcha is not configured"
            
            # Verify custom remediation header shows 'ban' fallback
            $logResult = Get-TraefikAccessLogs
            $logResult.Success | Should -Be $true -Because "Should be able to read Traefik access logs"
            
            # Find log entry for whoami endpoint with ban remediation header (fallback)
            $result = Find-TraefikLogEntry -LogEntries $logResult.LogEntries -Description "whoami log entry with ban fallback header" -Condition {
                param($logEntry)
                return ($logEntry.RequestPath -eq "/whoami" -and $logEntry.'downstream_X-Crowdsec-Remediation' -eq "ban:captcha-downgrade")
            }
            
            $result.Found | Should -Be $true -Because "Should fallback to ban remediation when captcha is not configured"
            
            if ($result.Found) {
                $remediationHeader = $result.LogEntry.'downstream_X-Crowdsec-Remediation'
                Write-Host "  Fallback header value: $remediationHeader" -ForegroundColor Green
                Write-Host "  Status code: $($result.LogEntry.DownstreamStatus)" -ForegroundColor Green
            }
        }
        
        It "Should show ban remediation for ban decision even on captcha endpoint" {
            # Add ban decision (not captcha) for the IP we'll test with
            Add-TestDecision -IP $script:TestIPs.CaptchaIP -Type "ban"
            
            # Test captcha endpoint with ban decision (should show ban, not captcha)
            $response = Test-HttpRequest -Endpoint "/captcha" -IP $script:TestIPs.CaptchaIP -TraefikUrl $script:TraefikUrl
            $response.StatusCode | Should -BeIn @(403, 429) -Because "Ban decision should block request even on captcha endpoint"
            
            # Verify custom remediation header shows 'ban' (decision type overrides endpoint config)
            $logResult = Get-TraefikAccessLogs
            $logResult.Success | Should -Be $true -Because "Should be able to read Traefik access logs"
            
            # Find log entry for captcha endpoint with ban remediation header
            $result = Find-TraefikLogEntry -LogEntries $logResult.LogEntries -Description "captcha endpoint log entry with ban header" -Condition {
                param($logEntry)
                return ($logEntry.RequestPath -eq "/captcha" -and $logEntry.'downstream_X-Crowdsec-Remediation' -eq "ban:lapi:cscli")
            }
            
            $result.Found | Should -Be $true -Because "Ban decision should result in ban remediation even on captcha-configured endpoint"
            
            if ($result.Found) {
                $remediationHeader = $result.LogEntry.'downstream_X-Crowdsec-Remediation'
                Write-Host "  Ban header value: $remediationHeader" -ForegroundColor Green
                Write-Host "  Status code: $($result.LogEntry.DownstreamStatus)" -ForegroundColor Green
            }
        }

        It "Should issue a gate cookie on dummy solve and pass the next GET" {
            Add-TestDecision -IP $script:TestIPs.CaptchaIP -Type "captcha"
            Add-TestDecision -IP $script:TestIPs.CaptchaOtherIP -Type "captcha"

            $formHeaders = @{ "Content-Type" = "application/x-www-form-urlencoded" }

            $page = Test-HttpRequest -Endpoint "/captcha" -IP $script:TestIPs.CaptchaIP -TraefikUrl $script:TraefikUrl
            $page.StatusCode | Should -Be 200
            $page.Content | Should -Match "captcha|challenge"

            $emptyPost = Test-HttpRequest -Endpoint "/captcha" -IP $script:TestIPs.CaptchaIP -TraefikUrl $script:TraefikUrl `
                -Method POST
            $emptyPost.StatusCode | Should -Be 200
            $emptyPost.Content | Should -Match "captcha|challenge"

            $solve = Test-HttpRequest -Endpoint "/captcha?dummy-captcha-response=ok" -IP $script:TestIPs.CaptchaIP -TraefikUrl $script:TraefikUrl `
                -Method POST -Body "dummy-captcha-response=ok" -ExtraHeaders $formHeaders `
                -MaximumRedirection 0
            $solve.StatusCode | Should -Be 302 -Because "solve status=$($solve.StatusCode) error=$($solve.Error) content=$($solve.Content)"
            $setCookie = [string]$solve.Headers["Set-Cookie"]
            $setCookie | Should -Match "crowdsec_captcha_gate=" -Because "headers=$($solve.Headers | Out-String)"
            $cookiePair = ($setCookie -split ';')[0].Trim()
            $cookieHeaders = @{ Cookie = $cookiePair }

            $passed = Test-HttpRequest -Endpoint "/captcha" -IP $script:TestIPs.CaptchaIP -TraefikUrl $script:TraefikUrl `
                -ExtraHeaders $cookieHeaders
            $passed.StatusCode | Should -Be 200
            $passed.Content | Should -Match "Hostname:"
            $passed.Content | Should -Not -Match "E2E captcha challenge"

            $noCookie = Test-HttpRequest -Endpoint "/captcha" -IP $script:TestIPs.CaptchaIP -TraefikUrl $script:TraefikUrl
            $noCookie.StatusCode | Should -Be 200
            $noCookie.Content | Should -Match "captcha|challenge"

            $otherIP = Test-HttpRequest -Endpoint "/captcha" -IP $script:TestIPs.CaptchaOtherIP -TraefikUrl $script:TraefikUrl `
                -ExtraHeaders $cookieHeaders
            $otherIP.StatusCode | Should -Be 200
            $otherIP.Content | Should -Match "captcha|challenge"
        }

        It "Should solve from the POST body without a query-string token" {
            Add-TestDecision -IP $script:TestIPs.CaptchaIP -Type "captcha"

            $formHeaders = @{ "Content-Type" = "application/x-www-form-urlencoded" }
            $solve = Test-HttpRequest -Endpoint "/captcha" -IP $script:TestIPs.CaptchaIP -TraefikUrl $script:TraefikUrl `
                -Method POST -Body "dummy-captcha-response=ok" -ExtraHeaders $formHeaders `
                -MaximumRedirection 0
            $solve.StatusCode | Should -Be 302 -Because "Yaegi FormValue misses POST bodies; the plugin must peek the form itself (status=$($solve.StatusCode) content=$($solve.Content))"
            $setCookie = [string]$solve.Headers["Set-Cookie"]
            $setCookie | Should -Match "crowdsec_captcha_gate="
            $cookieHeaders = @{ Cookie = ($setCookie -split ';')[0].Trim() }

            $passed = Test-HttpRequest -Endpoint "/captcha" -IP $script:TestIPs.CaptchaIP -TraefikUrl $script:TraefikUrl `
                -ExtraHeaders $cookieHeaders
            $passed.StatusCode | Should -Be 200
            $passed.Content | Should -Match "Hostname:"
        }

        It "Should challenge again after captchaGracePeriodSeconds expires" {
            Add-TestDecision -IP $script:TestIPs.CaptchaIP -Type "captcha"

            $formHeaders = @{ "Content-Type" = "application/x-www-form-urlencoded" }
            $solve = Test-HttpRequest -Endpoint "/short-captcha?dummy-captcha-response=ok" -IP $script:TestIPs.CaptchaIP -TraefikUrl $script:TraefikUrl `
                -Method POST -Body "dummy-captcha-response=ok" -ExtraHeaders $formHeaders `
                -MaximumRedirection 0
            $solve.StatusCode | Should -Be 302
            $setCookie = [string]$solve.Headers["Set-Cookie"]
            $setCookie | Should -Match "crowdsec_captcha_gate="
            $cookieHeaders = @{ Cookie = ($setCookie -split ';')[0].Trim() }

            $passed = Test-HttpRequest -Endpoint "/short-captcha" -IP $script:TestIPs.CaptchaIP -TraefikUrl $script:TraefikUrl `
                -ExtraHeaders $cookieHeaders
            $passed.Content | Should -Match "Hostname:"

            Start-Sleep -Seconds 5

            $expired = Test-HttpRequest -Endpoint "/short-captcha" -IP $script:TestIPs.CaptchaIP -TraefikUrl $script:TraefikUrl `
                -ExtraHeaders $cookieHeaders
            $expired.StatusCode | Should -Be 200
            $expired.Content | Should -Match "captcha|challenge" -Because "grace is 3s on /short-captcha; the gate cookie must not outlive it"
        }

        It "Should honour captcha gate bind across IPv6 spellings" {
            $stored = "2001:0db8:0000:0000:0000:0000:00c1:0001"
            $request = "2001:db8::c1:1"
            Add-TestDecision -IP $stored -Type "captcha"

            $formHeaders = @{ "Content-Type" = "application/x-www-form-urlencoded" }
            $solve = Test-HttpRequest -Endpoint "/captcha?dummy-captcha-response=ok" -IP $request -TraefikUrl $script:TraefikUrl `
                -Method POST -Body "dummy-captcha-response=ok" -ExtraHeaders $formHeaders `
                -MaximumRedirection 0
            $solve.StatusCode | Should -Be 302 -Because "compressed request spelling must match the expanded captcha decision"
            $setCookie = [string]$solve.Headers["Set-Cookie"]
            $setCookie | Should -Match "crowdsec_captcha_gate="
            $cookieHeaders = @{ Cookie = ($setCookie -split ';')[0].Trim() }

            $passed = Test-HttpRequest -Endpoint "/captcha" -IP $stored -TraefikUrl $script:TraefikUrl `
                -ExtraHeaders $cookieHeaders
            $passed.StatusCode | Should -Be 200
            $passed.Content | Should -Match "Hostname:" -Because "gate bind compares canonical remoteIP"
        }

        # Stock captcha.html. Dummy keys only; the vendor is not called.
        It "Should serve the <Name> challenge page" -TestCases @(
            @{ Name = "hcaptcha"; Endpoint = "/provider-hcaptcha"; Script = "https://hcaptcha.com/1/api.js"; Marker = 'class="h-captcha"' }
            @{ Name = "recaptcha"; Endpoint = "/provider-recaptcha"; Script = "https://www.google.com/recaptcha/api.js"; Marker = 'class="g-recaptcha"' }
            @{ Name = "turnstile"; Endpoint = "/provider-turnstile"; Script = "https://challenges.cloudflare.com/turnstile/v0/api.js"; Marker = 'class="cf-turnstile"' }
            @{ Name = "eucaptcha"; Endpoint = "/provider-eucaptcha"; Script = "https://cdn.eu-captcha.eu/verify.js"; Marker = 'class="eu-captcha"' }
            @{ Name = "recaptcha-enterprise checkbox"; Endpoint = "/provider-enterprise"; Script = "https://www.google.com/recaptcha/enterprise.js"; Marker = 'class="g-recaptcha"' }
            @{ Name = "recaptcha-enterprise score"; Endpoint = "/provider-enterprise-score"; Script = "https://www.google.com/recaptcha/enterprise.js?render=e2e-dummy-site"; Marker = "grecaptcha.enterprise.execute" }
        ) {
            Add-TestDecision -IP $script:TestIPs.CaptchaIP -Type "captcha"

            $response = Test-HttpRequest -Endpoint $Endpoint -IP $script:TestIPs.CaptchaIP -TraefikUrl $script:TraefikUrl
            $response.StatusCode | Should -Be 200
            $response.Content | Should -Match "needs to review the security of your connection"
            $response.Content | Should -Match ([regex]::Escape($Script))
            $response.Content | Should -Match "e2e-dummy-site"
            $response.Content | Should -Match ([regex]::Escape($Marker))
        }
    }
}

