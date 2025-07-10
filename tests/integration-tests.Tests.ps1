#!/usr/bin/env pwsh

# Integration tests for CrowdSec Bouncer Traefik Plugin
# Tests bouncer behavior by directly managing decisions via LAPI

BeforeAll {
    # Test configuration
    $script:TraefikUrl = "http://localhost:8000"
    $script:CrowdSecApiUrl = "http://localhost:8081"
    $script:ApiKey = "40796d93c2958f9e58345514e67740e5"
    $script:HttpTimeoutSeconds = [int]($env:HTTP_TIMEOUT_SECONDS ?? 30)
    
    # Test IP addresses
    $script:TestIPs = @{
        BannedIP = "192.168.1.100"
        CaptchaIP = "192.168.1.101"
        CleanIP = "192.168.1.200"
    }
    
    # Helper function to call CrowdSec LAPI
    function Invoke-CrowdSecAPI {
        param(
            [string]$Endpoint,
            [string]$Method = "GET",
            [object]$Body = $null,
            [int]$TimeoutSec = 10
        )
        
        $headers = @{
            "X-Api-Key" = $script:ApiKey
            "Content-Type" = "application/json"
        }
        
        $uri = "$script:CrowdSecApiUrl$Endpoint"
        
        try {
            if ($Body) {
                $jsonBody = $Body | ConvertTo-Json -Depth 10
                return Invoke-RestMethod -Uri $uri -Method $Method -Headers $headers -Body $jsonBody -TimeoutSec $TimeoutSec
            } else {
                return Invoke-RestMethod -Uri $uri -Method $Method -Headers $headers -TimeoutSec $TimeoutSec
            }
        }
        catch {
            Write-Host "❌ LAPI call failed: $($_.Exception.Message)" -ForegroundColor Red
            throw
        }
    }
    
    # Helper function to create a decision
    function Add-TestDecision {
        param(
            [string]$IP,
            [string]$Type = "ban",
            [string]$Duration = "1h",
            [string]$Scenario = "integration-test",
            [string]$Reason = "Integration test decision"
        )
        
        $decision = @{
            capacity = 1
            decisions = @(
                @{
                    duration = $Duration
                    origin = "cscli"
                    scenario = $Scenario
                    scope = "Ip"
                    type = $Type
                    value = $IP
                }
            )
            events = @(
                @{
                    timestamp = (Get-Date).ToString("yyyy-MM-ddTHH:mm:ss.fffZ")
                    meta = @{
                        source_ip = $IP
                        log_type = "integration-test"
                    }
                }
            )
            events_count = 1
            leakspeed = "10s"
            message = $Reason
            scenario = $Scenario
            scenario_hash = ""
            scenario_version = ""
            simulated = $false
            source = @{
                ip = $IP
                range = ""
                as_number = ""
                as_name = ""
                cn = ""
                latitude = 0
                longitude = 0
                scope = "Ip"
                value = $IP
            }
            start_at = (Get-Date).ToString("yyyy-MM-ddTHH:mm:ss.fffZ")
            stop_at = (Get-Date).AddHours(1).ToString("yyyy-MM-ddTHH:mm:ss.fffZ")
        }
        
        Write-Host "➕ Adding $Type decision for $IP" -ForegroundColor Yellow
        return Invoke-CrowdSecAPI -Endpoint "/v1/alerts" -Method "POST" -Body @($decision)
    }
    
    # Helper function to remove decisions for an IP
    function Remove-TestDecision {
        param(
            [string]$IP
        )
        
        Write-Host "➖ Removing decisions for $IP" -ForegroundColor Yellow
        return Invoke-CrowdSecAPI -Endpoint "/v1/decisions?ip=$IP" -Method "DELETE"
    }
    
    # Helper function to test HTTP request
    function Test-HttpRequest {
        param(
            [string]$Endpoint,
            [string]$IP,
            [int]$ExpectedStatusCode = 200,
            [string]$ExpectedContent = $null,
            [int]$TimeoutSec = 10
        )
        
        $headers = @{
            "X-Forwarded-For" = $IP
            "User-Agent" = "Integration-Test-Client"
        }
        
        try {
            $response = Invoke-WebRequest -Uri "$script:TraefikUrl$Endpoint" -Headers $headers -TimeoutSec $TimeoutSec -UseBasicParsing
            
            return @{
                StatusCode = $response.StatusCode
                Content = $response.Content
                Success = $true
            }
        }
        catch {
            $statusCode = 0
            $content = ""
            
            if ($_.Exception.Response) {
                $statusCode = [int]$_.Exception.Response.StatusCode
                $content = $_.Exception.Response.Content ?? ""
            }
            
            return @{
                StatusCode = $statusCode
                Content = $content
                Success = $false
                Error = $_.Exception.Message
            }
        }
    }
    
    # Wait for services to be ready
    Write-Host "🔄 Waiting for services to be ready..." -ForegroundColor Cyan
    
    $maxRetries = 30
    $retryCount = 0
    
    do {
        try {
            $decisions = Invoke-CrowdSecAPI -Endpoint "/v1/decisions?limit=1" -TimeoutSec 5
            Write-Host "✅ CrowdSec LAPI is ready" -ForegroundColor Green
            break
        }
        catch {
            $retryCount++
            if ($retryCount -ge $maxRetries) {
                throw "❌ CrowdSec LAPI failed to become ready after $maxRetries attempts"
            }
            Write-Host "⏳ Waiting for CrowdSec... ($retryCount/$maxRetries)" -ForegroundColor Gray
            Start-Sleep 2
        }
    } while ($true)
}

Describe "CrowdSec Bouncer Integration Tests" {
    
    Context "Service Health Checks" {
        It "CrowdSec LAPI should be accessible" {
            $response = Invoke-CrowdSecAPI -Endpoint "/v1/decisions?limit=1"
            $response | Should -Not -BeNullOrEmpty
        }
        
        It "Traefik should be accessible" {
            $response = Test-HttpRequest -Endpoint "/whoami" -IP $script:TestIPs.CleanIP
            $response.Success | Should -Be $true
            $response.StatusCode | Should -Be 200
        }
    }
    
    Context "Basic Bouncer Functionality" -Tag "basic" {
        
        BeforeEach {
            # Clean up any existing decisions
            foreach ($ip in $script:TestIPs.Values) {
                try { Remove-TestDecision -IP $ip } catch { }
            }
            Start-Sleep 2
        }
        
        It "Should allow clean IP through" {
            $response = Test-HttpRequest -Endpoint "/whoami" -IP $script:TestIPs.CleanIP
            $response.Success | Should -Be $true
            $response.StatusCode | Should -Be 200
            $response.Content | Should -Match "Hostname"
        }
        
        It "Should block banned IP" {
            # Add ban decision
            Add-TestDecision -IP $script:TestIPs.BannedIP -Type "ban"
            
            # Wait for bouncer to update
            Start-Sleep 2
            
            # Test that IP is blocked
            $response = Test-HttpRequest -Endpoint "/whoami" -IP $script:TestIPs.BannedIP
            $response.StatusCode | Should -BeIn @(403, 429)
        }
        
        It "Should unblock IP after decision removal" {
            # Add ban decision
            Add-TestDecision -IP $script:TestIPs.BannedIP -Type "ban"
            Start-Sleep 2
            
            # Verify it's blocked
            $response = Test-HttpRequest -Endpoint "/whoami" -IP $script:TestIPs.BannedIP
            $response.StatusCode | Should -BeIn @(403, 429)
            
            # Remove decision
            Remove-TestDecision -IP $script:TestIPs.BannedIP
            Start-Sleep 7
            
            # Verify it's now allowed
            $response = Test-HttpRequest -Endpoint "/whoami" -IP $script:TestIPs.BannedIP
            $response.Success | Should -Be $true
            $response.StatusCode | Should -Be 200
        }
    }
    
    Context "Stream Mode Tests" -Tag "stream" {
        
        BeforeEach {
            # Clean up any existing decisions
            foreach ($ip in $script:TestIPs.Values) {
                try { Remove-TestDecision -IP $ip } catch { }
            }
            Start-Sleep 2
        }
        
        It "Should handle multiple decisions efficiently" {
            $testIPs = @("192.168.1.110", "192.168.1.111", "192.168.1.112")
            
            # Add multiple decisions
            foreach ($ip in $testIPs) {
                Add-TestDecision -IP $ip -Type "ban"
            }
            
            # Wait for bouncer to process
            Start-Sleep 3
            
            # Test all IPs are blocked
            foreach ($ip in $testIPs) {
                $response = Test-HttpRequest -Endpoint "/whoami" -IP $ip
                $response.StatusCode | Should -BeIn @(403, 429)
            }
            
            # Clean up
            foreach ($ip in $testIPs) {
                Remove-TestDecision -IP $ip
            }
        }
        
        It "Should handle decision updates within timeout" {
            # This test ensures the bouncer can handle updates within the configured timeout
            $measureTime = Measure-Command {
                Add-TestDecision -IP $script:TestIPs.BannedIP -Type "ban"
                Start-Sleep 3
                $response = Test-HttpRequest -Endpoint "/whoami" -IP $script:TestIPs.BannedIP
                $response.StatusCode | Should -BeIn @(403, 429)
                Remove-TestDecision -IP $script:TestIPs.BannedIP
            }
            
            $measureTime.TotalSeconds | Should -BeLessThan $script:HttpTimeoutSeconds
        }
    }
    
    Context "Captcha Mode Tests" -Tag "captcha" {
        
        BeforeEach {
            # Clean up any existing decisions
            foreach ($ip in $script:TestIPs.Values) {
                try { Remove-TestDecision -IP $ip } catch { }
            }
            Start-Sleep 2
        }
        
        It "Should show captcha for captcha decision" {
            # Add captcha decision
            Add-TestDecision -IP $script:TestIPs.CaptchaIP -Type "captcha"
            
            # Wait for bouncer to update
            Start-Sleep 2
            
            # Test captcha endpoint
            $response = Test-HttpRequest -Endpoint "/captcha" -IP $script:TestIPs.CaptchaIP
            $response.StatusCode | Should -BeIn @(200, 429)
            
            # If captcha is working, response should contain captcha content
            if ($response.StatusCode -eq 200) {
                $response.Content | Should -Match "captcha|challenge"
            }
        }
    }
    
    Context "Disabled Bouncer Tests" -Tag "disabled" {
        
        It "Should allow all traffic when bouncer is disabled" {
            # Test disabled endpoint should always allow traffic
            $response = Test-HttpRequest -Endpoint "/disabled" -IP $script:TestIPs.BannedIP
            $response.Success | Should -Be $true
            $response.StatusCode | Should -Be 200
        }
    }
    
    Context "Performance Tests" -Tag "performance" {
        
        BeforeEach {
            # Clean up any existing decisions
            foreach ($ip in $script:TestIPs.Values) {
                try { Remove-TestDecision -IP $ip } catch { }
            }
            Start-Sleep 2
        }
        
        It "Should handle requests within reasonable time" {
            $measureTime = Measure-Command {
                $response = Test-HttpRequest -Endpoint "/whoami" -IP $script:TestIPs.CleanIP
                $response.Success | Should -Be $true
            }
            
            # Request should complete within 5 seconds
            $measureTime.TotalSeconds | Should -BeLessThan 5
        }
        
        It "Should handle blocked requests efficiently" {
            # Add ban decision
            Add-TestDecision -IP $script:TestIPs.BannedIP -Type "ban"
            Start-Sleep 3
            
            $measureTime = Measure-Command {
                $response = Test-HttpRequest -Endpoint "/whoami" -IP $script:TestIPs.BannedIP
                $response.StatusCode | Should -BeIn @(403, 429)
            }
            
            # Blocked request should be fast (no backend processing)
            $measureTime.TotalSeconds | Should -BeLessThan 2
        }
    }
    
    Context "Error Handling Tests" -Tag "error" {
        
        It "Should handle invalid decisions gracefully" {
            # Try to add decision with invalid IP
            { Add-TestDecision -IP "invalid.ip" -Type "ban" } | Should -Throw
        }
        
        It "Should handle LAPI connectivity issues" {
            # Test with wrong API key
            $oldApiKey = $script:ApiKey
            $script:ApiKey = "invalid-key"
            
            { Invoke-CrowdSecAPI -Endpoint "/v1/decisions?limit=1" } | Should -Throw
            
            # Restore original API key
            $script:ApiKey = $oldApiKey
        }
    }
}

AfterAll {
    # Clean up all test decisions
    Write-Host "🧹 Cleaning up test decisions..." -ForegroundColor Yellow
    
    foreach ($ip in $script:TestIPs.Values) {
        try { 
            Remove-TestDecision -IP $ip 
            Write-Host "✅ Cleaned up decisions for $ip" -ForegroundColor Green
        } 
        catch { 
            Write-Host "⚠️ Could not clean up decisions for $ip" -ForegroundColor Yellow
        }
    }
    
    # Clean up additional test IPs
    $additionalIPs = @("192.168.1.110", "192.168.1.111", "192.168.1.112")
    foreach ($ip in $additionalIPs) {
        try { Remove-TestDecision -IP $ip } catch { }
    }
    
    Write-Host "✅ Integration test cleanup complete" -ForegroundColor Green
} 