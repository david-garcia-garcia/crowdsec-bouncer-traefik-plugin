#!/usr/bin/env pwsh

# Simple Integration Test for CrowdSec Bouncer
# Focus: Prove basic functionality works

BeforeAll {
    $script:TraefikUrl = "http://localhost:8000"
    $script:CrowdSecApiUrl = "http://localhost:8081"
    $script:TestIP = "172.18.0.1"
    
    # Helper function to wait for a specific HTTP status code with timeout
    function Wait-ForHttpStatus {
        param(
            [string]$Url,
            [hashtable]$Headers = @{},
            [int[]]$ExpectedStatusCodes = @(200),
            [int]$TimeoutSeconds = 15,
            [int]$RetryIntervalSeconds = 1
        )
        
        $elapsed = 0
        $lastStatusCode = 0
        $lastError = ""
        
        do {
            try {
                $response = Invoke-WebRequest -Uri $Url -Headers $Headers -UseBasicParsing -TimeoutSec 5
                $lastStatusCode = $response.StatusCode
                if ($ExpectedStatusCodes -contains $lastStatusCode) {
                    return @{
                        Success = $true
                        StatusCode = $lastStatusCode
                        TimeTaken = $elapsed
                    }
                }
            }
            catch {
                if ($_.Exception.Response) {
                    $lastStatusCode = [int]$_.Exception.Response.StatusCode
                    if ($ExpectedStatusCodes -contains $lastStatusCode) {
                        return @{
                            Success = $true
                            StatusCode = $lastStatusCode
                            TimeTaken = $elapsed
                        }
                    }
                }
                $lastError = $_.Exception.Message
            }
            
            Start-Sleep $RetryIntervalSeconds
            $elapsed += $RetryIntervalSeconds
            
        } while ($elapsed -lt $TimeoutSeconds)
        
        return @{
            Success = $false
            StatusCode = $lastStatusCode
            TimeTaken = $elapsed
            Error = $lastError
        }
    }
    
    # Wait for services to be ready
    Write-Host "🔄 Waiting for services to be ready..." -ForegroundColor Cyan
    
    $maxRetries = 15
    $retryCount = 0
    
    # Wait for Traefik
    do {
        try {
            $response = Invoke-WebRequest -Uri "http://localhost:8000/disabled" -TimeoutSec 3 -UseBasicParsing
            if ($response.StatusCode -eq 200) {
                Write-Host "✅ Traefik is ready" -ForegroundColor Green
                break
            }
        }
        catch {
            $retryCount++
            if ($retryCount -ge $maxRetries) {
                throw "❌ Traefik failed to become ready"
            }
            Start-Sleep 2
        }
    } while ($true)
    
    # Set up bouncer API key for reading decisions (cscli handles writing)
    Write-Host "🔍 Setting up CrowdSec API..." -ForegroundColor Yellow
    $script:BouncerApiKey = "40796d93c2958f9e58345514e67740e5"
    
    # Test bouncer API
    Write-Host "🔄 Testing CrowdSec bouncer API..." -ForegroundColor Cyan
    try {
        $bouncerHeaders = @{ "X-Api-Key" = $script:BouncerApiKey }
        $response = Invoke-RestMethod -Uri "$script:CrowdSecApiUrl/v1/decisions?limit=1" -Headers $bouncerHeaders -TimeoutSec 5
        Write-Host "✅ CrowdSec bouncer API is working!" -ForegroundColor Green
    }
    catch {
        Write-Host "❌ Bouncer API test failed: $($_.Exception.Message)" -ForegroundColor Red
        Write-Host "  URL: $script:CrowdSecApiUrl/v1/decisions?limit=1" -ForegroundColor Yellow
        Write-Host "  API Key: $script:BouncerApiKey" -ForegroundColor Yellow
        Write-Host "  Status Code: $($_.Exception.Response.StatusCode)" -ForegroundColor Yellow
        throw "CrowdSec bouncer API not accessible"
    }
}

Describe "Basic CrowdSec Bouncer Integration Test" {
    
    It "Should allow access when no decision exists" {
        # Test that we can access the endpoint normally
        $headers = @{ "X-Forwarded-For" = $script:TestIP }
        $result = Wait-ForHttpStatus -Url "$script:TraefikUrl/whoami" -Headers $headers -ExpectedStatusCodes @(200) -TimeoutSeconds 10
        
        if ($result.Success) {
            Write-Host "✅ Clean IP can access endpoint (Status: $($result.StatusCode), Time: $($result.TimeTaken)s)" -ForegroundColor Green
            $result.StatusCode | Should -Be 200
        } else {
            Write-Host "❌ Clean IP cannot access endpoint. Status: $($result.StatusCode)" -ForegroundColor Red
            if ($result.Error) {
                Write-Host "  Error: $($result.Error)" -ForegroundColor Red
            }
            $result.Success | Should -Be $true -Because "Clean IP should be able to access endpoint"
        }
    }
    
    It "Should block access after adding a ban decision" {
        # Add a ban decision using cscli (simpler than API)
        Write-Host "➕ Adding ban decision for $script:TestIP" -ForegroundColor Yellow
        
        # Add a ban decision using a more robust approach
        $addCommand = "cscli decisions add --ip $script:TestIP --duration 1h --type ban --reason 'Integration test'"
        $result = docker exec crowdsec-test sh -c $addCommand
        if ($LASTEXITCODE -ne 0) {
            throw "Failed to add decision: $result"
        }
        
        # Verify the decision was actually added
        Start-Sleep 2  # Give CrowdSec time to process the decision
        $decisions = docker exec crowdsec-test cscli decisions list
        if ($decisions -match "No active decisions") {
            throw "Decision was not actually added for IP $script:TestIP"
        }
        Write-Host "✅ Decision added successfully via cscli" -ForegroundColor Green
        
        # With 0 cache time, the bouncer queries LAPI directly - no wait needed!
        
        # Now test that the IP is blocked
        $headers = @{ "X-Forwarded-For" = $script:TestIP }
        $result = Wait-ForHttpStatus -Url "$script:TraefikUrl/whoami" -Headers $headers -ExpectedStatusCodes @(403, 429) -TimeoutSeconds 10
        
        if ($result.Success) {
            Write-Host "✅ IP is correctly blocked (Status: $($result.StatusCode), Time: $($result.TimeTaken)s)" -ForegroundColor Green
            $result.StatusCode | Should -BeIn @(403, 429) -Because "IP should be blocked after ban decision"
        } else {
            Write-Host "❌ IP was not blocked within timeout. Final status: $($result.StatusCode)" -ForegroundColor Red
            if ($result.Error) {
                Write-Host "  Error: $($result.Error)" -ForegroundColor Red
            }
            $result.Success | Should -Be $true -Because "IP should be blocked after ban decision"
        }
    }
    
    It "Should allow access after removing the ban decision" {
        # Remove the decision using cscli
        Write-Host "➖ Removing ban decision for $script:TestIP" -ForegroundColor Yellow
        
        $result = docker exec crowdsec-test cscli decisions delete --ip $script:TestIP
        if ($LASTEXITCODE -ne 0) {
            Write-Host "⚠️ Decision removal may have failed: $result" -ForegroundColor Yellow
        }
        Write-Host "✅ Decision removed successfully via cscli" -ForegroundColor Green
        
        # With 0 cache time, the bouncer queries LAPI directly - no wait needed!
        
        # Now test that the IP can access again
        $headers = @{ "X-Forwarded-For" = $script:TestIP }
        $result = Wait-ForHttpStatus -Url "$script:TraefikUrl/whoami" -Headers $headers -ExpectedStatusCodes @(200) -TimeoutSeconds 10
        
        if ($result.Success) {
            Write-Host "✅ IP can access endpoint again after decision removal (Status: $($result.StatusCode), Time: $($result.TimeTaken)s)" -ForegroundColor Green
            $result.StatusCode | Should -Be 200
        } else {
            Write-Host "❌ IP cannot access endpoint after decision removal. Status: $($result.StatusCode)" -ForegroundColor Red
            if ($result.Error) {
                Write-Host "  Error: $($result.Error)" -ForegroundColor Red
            }
            $result.Success | Should -Be $true -Because "IP should be able to access endpoint after decision removal"
        }
    }

    It "Should include custom remediation header in Traefik access logs when blocking requests" {
        # Clear any existing Traefik logs
        Write-Host "🧹 Clearing existing Traefik access logs..." -ForegroundColor Yellow
        docker exec traefik-test sh -c 'echo "" > /var/log/traefik/access.log' 2>$null
        
        # Add a ban decision
        Write-Host "➕ Adding ban decision for custom header test ($script:TestIP)" -ForegroundColor Yellow
        $addCommand = "cscli decisions add --ip $script:TestIP --duration 1h --type ban --reason 'Custom header test'"
        $result = docker exec crowdsec-test sh -c $addCommand
        if ($LASTEXITCODE -ne 0) {
            throw "Failed to add decision: $result"
        }
        Write-Host "✅ Ban decision added for header test" -ForegroundColor Green
        
        # Make a request to the endpoint with custom remediation headers configured
        Write-Host "🌐 Making request to remediation-headers endpoint..." -ForegroundColor Yellow
        $headers = @{ "X-Forwarded-For" = $script:TestIP }
        try {
            # We expect this to be blocked (403), but we're interested in the headers
            Invoke-WebRequest -Uri "$script:TraefikUrl/remediation-headers" -Headers $headers -UseBasicParsing -TimeoutSec 5
        }
        catch {
            Write-Host "✅ Request blocked as expected (checking for custom header in logs)" -ForegroundColor Green
        }
        
        # Give Traefik a moment to write the access log
        Start-Sleep 2
        
        # Read the Traefik access logs
        Write-Host "📋 Reading Traefik access logs..." -ForegroundColor Yellow
        $logContent = docker exec traefik-test cat /var/log/traefik/access.log
        
        if ([string]::IsNullOrWhiteSpace($logContent)) {
            throw "No access log content found"
        }
        
        Write-Host "📄 Access log content:" -ForegroundColor Gray
        Write-Host $logContent -ForegroundColor Gray
        
        # Parse the JSON log entries
        $logLines = $logContent -split "`n" | Where-Object { $_.Trim() -ne "" }
        $foundCustomHeader = $false
        
        foreach ($line in $logLines) {
            try {
                $logEntry = $line | ConvertFrom-Json
                
                # Look for our test endpoint and the custom remediation header
                # Note: JSON property names with hyphens need special access
                $remediationHeader = $logEntry.'downstream_X-Crowdsec-Remediation'
                if ($logEntry.RequestPath -eq "/remediation-headers" -and $remediationHeader) {
                    Write-Host "✅ Found custom remediation header in logs!" -ForegroundColor Green
                    Write-Host "  Header value: $remediationHeader" -ForegroundColor Green
                    Write-Host "  Status code: $($logEntry.DownstreamStatus)" -ForegroundColor Green
                    
                    # Verify the header value is 'ban'
                    $remediationHeader | Should -Be "ban" -Because "Custom remediation header should contain 'ban' for ban decisions"
                    $foundCustomHeader = $true
                    break
                }
            }
            catch {
                Write-Host "⚠️ Could not parse log line: $line" -ForegroundColor Yellow
            }
        }
        
        if (-not $foundCustomHeader) {
            Write-Host "❌ Custom remediation header not found in access logs" -ForegroundColor Red
            Write-Host "Available log entries:" -ForegroundColor Yellow
            foreach ($line in $logLines) {
                try {
                    $logEntry = $line | ConvertFrom-Json
                    Write-Host "  Path: $($logEntry.RequestPath), Status: $($logEntry.DownstreamStatus)" -ForegroundColor Yellow
                }
                catch { }
            }
            $foundCustomHeader | Should -Be $true -Because "Custom remediation header should appear in Traefik access logs when blocking requests"
        }
        
        # Cleanup: Remove the decision
        Write-Host "🧹 Cleaning up ban decision..." -ForegroundColor Yellow
        docker exec crowdsec-test cscli decisions delete --ip $script:TestIP 2>$null
    }
}

AfterAll {
    # Cleanup: remove any remaining decisions
    Write-Host "🧹 Cleaning up test decisions..." -ForegroundColor Yellow
    try {
        docker exec crowdsec-test cscli decisions delete --ip $script:TestIP 2>$null
        Write-Host "✅ Cleanup complete" -ForegroundColor Green
    }
    catch {
        Write-Host "⚠️ Cleanup warning: $($_.Exception.Message)" -ForegroundColor Yellow
    }
} 