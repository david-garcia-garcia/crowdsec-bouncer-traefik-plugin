#!/usr/bin/env pwsh

# Shared utility functions for CrowdSec Bouncer integration tests
# This file contains reusable helper functions for all test suites

# Helper function to call CrowdSec LAPI
function Invoke-CrowdSecAPI {
    param(
        [string]$Endpoint,
        [string]$Method = "GET",
        [object]$Body = $null,
        [int]$TimeoutSec = 10,
        [string]$ApiKey = "40796d93c2958f9e58345514e67740e5",
        [string]$CrowdSecApiUrl = "http://localhost:8081"
    )
    
    $headers = @{
        "X-Api-Key" = $ApiKey
        "Content-Type" = "application/json"
    }
    
    $uri = "$CrowdSecApiUrl$Endpoint"
    
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

# Helper function to create a decision using cscli
function Add-TestDecision {
    param(
        [string]$IP,
        [string]$Type = "ban",
        [string]$Duration = "1h",
        [string]$Scenario = "integration-test",
        [string]$Reason = "Integration test decision"
    )
    
    Write-Host "➕ Adding $Type decision for $IP" -ForegroundColor Yellow
    
    $addCommand = "cscli decisions add --ip $IP --duration $Duration --type $Type --reason '$Reason'"
    $result = docker exec crowdsec-test sh -c $addCommand
    if ($LASTEXITCODE -ne 0) {
        throw "Failed to add decision: $result"
    }
    
    Write-Host "✅ Decision added successfully via cscli" -ForegroundColor Green
    return $true
}

# Helper function to create a Range decision using cscli --range
function Add-TestRangeDecision {
    param(
        [string]$Range,
        [string]$Type = "ban",
        [string]$Duration = "1h",
        [string]$Reason = "Integration test range decision"
    )

    Write-Host "➕ Adding $Type Range decision for $Range" -ForegroundColor Yellow

    $addCommand = "cscli decisions add --range $Range --duration $Duration --type $Type --reason '$Reason'"
    $result = docker exec crowdsec-test sh -c $addCommand
    if ($LASTEXITCODE -ne 0) {
        throw "Failed to add range decision: $result"
    }

    Write-Host "✅ Range decision added successfully via cscli" -ForegroundColor Green
    return $true
}

# Helper function to create a named-scope decision using cscli --scope/--value
function Add-TestScopeDecision {
    param(
        [string]$Scope,
        [string]$Value,
        [string]$Type = "ban",
        [string]$Duration = "1h",
        [string]$Reason = "Integration test scope decision"
    )

    Write-Host "➕ Adding $Type $Scope decision for $Value" -ForegroundColor Yellow

    $addCommand = "cscli decisions add --scope $Scope --value $Value --duration $Duration --type $Type --reason '$Reason'"
    $result = docker exec crowdsec-test sh -c $addCommand
    if ($LASTEXITCODE -ne 0) {
        throw "Failed to add scope decision: $result"
    }

    Write-Host "✅ Scope decision added successfully via cscli" -ForegroundColor Green
    return $true
}

# Helper function to remove decisions for an IP using cscli
function Remove-TestDecision {
    param(
        [string]$IP
    )
    
    $result = docker exec crowdsec-test cscli decisions delete --ip $IP 2>$null
    if ($LASTEXITCODE -ne 0) {
        Write-Host "⚠️ Failed to remove decisions for $IP" -ForegroundColor Yellow
    } else {
        Write-Host "✅ Removed decisions for $IP" -ForegroundColor Green
    }
    return $true
}

# Helper function to remove a Range decision using cscli --range
function Remove-TestRangeDecision {
    param(
        [string]$Range
    )

    $result = docker exec crowdsec-test cscli decisions delete --range $Range 2>$null
    if ($LASTEXITCODE -ne 0) {
        Write-Host "⚠️ Failed to remove Range decision for $Range" -ForegroundColor Yellow
    } else {
        Write-Host "✅ Removed Range decision for $Range" -ForegroundColor Green
    }
    return $true
}

# Helper function to remove a named-scope decision using cscli --scope/--value
function Remove-TestScopeDecision {
    param(
        [string]$Scope,
        [string]$Value
    )

    $result = docker exec crowdsec-test cscli decisions delete --scope $Scope --value $Value 2>$null
    if ($LASTEXITCODE -ne 0) {
        Write-Host "⚠️ Failed to remove $Scope decision for $Value" -ForegroundColor Yellow
    } else {
        Write-Host "✅ Removed $Scope decision for $Value" -ForegroundColor Green
    }
    return $true
}

# Helper function to test HTTP request
function Test-HttpRequest {
    param(
        [string]$Endpoint,
        [string]$IP,
        [int]$ExpectedStatusCode = 200,
        [string]$ExpectedContent = $null,
        [int]$TimeoutSec = 10,
        [string]$TraefikUrl = "http://localhost:8000",
        [hashtable]$ExtraHeaders = @{}
    )
    
    $headers = @{
        "X-Forwarded-For" = $IP
        "User-Agent" = "Integration-Test-Client"
    }
    foreach ($headerName in $ExtraHeaders.Keys) {
        $headers[$headerName] = $ExtraHeaders[$headerName]
    }
    
    try {
        $response = Invoke-WebRequest -Uri "$TraefikUrl$Endpoint" -Headers $headers -TimeoutSec $TimeoutSec -UseBasicParsing -SkipHttpErrorCheck
        $contentType = $response.Headers["Content-Type"]
        if ($contentType -is [System.Array]) {
            $contentType = $contentType[0]
        }

        return @{
            StatusCode = [int]$response.StatusCode
            Content = $response.Content
            ContentType = "$contentType"
            Headers = $response.Headers
            Success = ($response.StatusCode -ge 200 -and $response.StatusCode -lt 300)
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
            Headers = @{}
            Success = $false
            Error = $_.Exception.Message
        }
    }
}

# Parse the ISO country code geoblock wrote onto a whoami response body.
function Get-WhoamiCountryCode {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Content
    )

    $match = [regex]::Match($Content, '(?im)X-Ipcountry:\s*([A-Za-z]{2})\b')
    if ($match.Success) {
        return $match.Groups[1].Value.ToUpperInvariant()
    }
    return $null
}

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

# Helper function to wait for a condition to be met with retry logic
function Wait-ForCondition {
    param(
        [scriptblock]$Condition,
        [string]$Description = "Condition",
        [int]$TimeoutSeconds = 30,
        [int]$RetryIntervalSeconds = 1,
        [switch]$Silent
    )
    
    $elapsed = 0
    $lastError = ""
    
    if (-not $Silent) {
        Write-Host "🔄 Waiting for $Description..." -ForegroundColor Cyan
    }
    
    do {
        try {
            $result = & $Condition
            if ($result) {
                if (-not $Silent) {
                    Write-Host "✅ $Description met after $elapsed seconds" -ForegroundColor Green
                }
                return @{
                    Success = $true
                    TimeTaken = $elapsed
                }
            }
        }
        catch {
            $lastError = $_.Exception.Message
        }
        
        Start-Sleep $RetryIntervalSeconds
        $elapsed += $RetryIntervalSeconds
        
        if ($elapsed % 10 -eq 0 -and -not $Silent) {
            Write-Host "  Still waiting for $Description... ($elapsed/$TimeoutSeconds seconds)" -ForegroundColor Gray
        }
        
    } while ($elapsed -lt $TimeoutSeconds)
    
    if (-not $Silent) {
        Write-Host "❌ $Description not met within $TimeoutSeconds seconds" -ForegroundColor Red
        if ($lastError) {
            Write-Host "  Last error: $lastError" -ForegroundColor Yellow
        }
    }
    
    return @{
        Success = $false
        TimeTaken = $elapsed
        Error = $lastError
    }
}

# Helper function to read and parse Traefik access logs
function Get-TraefikAccessLogs {
    param(
        [string]$ContainerName = "traefik-test",
        [string]$LogPath = "/var/log/traefik/access.log"
    )
    
    # Read the access logs
    Write-Host "📋 Reading Traefik access logs..." -ForegroundColor Yellow
    $logContent = docker exec $ContainerName cat $LogPath
    
    if ([string]::IsNullOrWhiteSpace($logContent)) {
        Write-Host "⚠️ No access log content found" -ForegroundColor Yellow
        return @{
            Success = $false
            RawContent = ""
            LogEntries = @()
            Error = "No access log content found"
        }
    }
    
    Write-Host "📄 Access log content:" -ForegroundColor Gray
    Write-Host $logContent -ForegroundColor Gray
    
    # Parse the JSON log entries
    $logLines = $logContent -split "`n" | Where-Object { $_.Trim() -ne "" }
    $parsedEntries = @()
    
    foreach ($line in $logLines) {
        try {
            $logEntry = $line | ConvertFrom-Json
            $parsedEntries += $logEntry
        }
        catch {
            Write-Host "⚠️ Could not parse log line: $line" -ForegroundColor Yellow
        }
    }
    
    return @{
        Success = $true
        RawContent = $logContent
        LogEntries = $parsedEntries
        Count = $parsedEntries.Count
    }
}

# Helper function to clear Traefik access logs (with backup for CI debugging)
function Clear-TraefikAccessLogs {
    param(
        [string]$ContainerName = "traefik-test",
        [string]$LogPath = "/var/log/traefik/access.log"
    )
    
    Write-Host "🧹 Clearing Traefik access logs..." -ForegroundColor Yellow
    
    # Append current log contents to backup for CI debugging before clearing
    docker exec $ContainerName sh -c "cat $LogPath >> ${LogPath}.bak 2>/dev/null || touch ${LogPath}.bak" 2>$null
    
    # Clear the main log file
    docker exec $ContainerName sh -c "echo '' > $LogPath" 2>$null
}

# Helper function to find specific log entries using a condition callback
function Find-TraefikLogEntry {
    param(
        [object[]]$LogEntries,
        [scriptblock]$Condition,
        [string]$Description = "matching log entry"
    )
    
    foreach ($logEntry in $LogEntries) {
        try {
            # Execute the condition callback with the log entry
            $matches = & $Condition $logEntry
            if ($matches) {
                Write-Host "✅ Found $Description" -ForegroundColor Green
                return @{
                    Found = $true
                    LogEntry = $logEntry
                }
            }
        }
        catch {
            # Skip invalid log entries or condition errors
            Write-Host "⚠️ Error evaluating condition for log entry" -ForegroundColor Yellow
        }
    }
    
    Write-Host "❌ No $Description found in access logs" -ForegroundColor Red
    Write-Host "Available log entries:" -ForegroundColor Yellow
    foreach ($logEntry in $LogEntries) {
        try {
            Write-Host "  Path: $($logEntry.RequestPath), Status: $($logEntry.DownstreamStatus)" -ForegroundColor Yellow
        }
        catch { }
    }
    
    return @{
        Found = $false
        LogEntry = $null
    }
}

# Helper function to remove all decisions using cscli
function Remove-AllTestDecisions {
    docker exec crowdsec-test cscli decisions delete --all 2>$null
    if ($LASTEXITCODE -ne 0) {
        Write-Host "⚠️ Failed to remove all decisions" -ForegroundColor Yellow
    } else {
        Write-Host "✅ Removed all decisions" -ForegroundColor Green
    }
    return $true
}

# cscli metrics show bouncers -o json is [bouncer][origin][name][unit] = value.
# Empty origin holds processed. Human table hides empty origin from body rows.
function Get-CscliBouncerMetrics {
    $raw = docker exec crowdsec-test cscli metrics show bouncers -o json --color no 2>$null
    if ($LASTEXITCODE -ne 0 -or [string]::IsNullOrWhiteSpace($raw)) {
        return $null
    }
    try {
        return $raw | ConvertFrom-Json
    }
    catch {
        Write-Host "⚠️ cscli metrics JSON parse failed: $raw" -ForegroundColor Yellow
        return $null
    }
}

function Get-CscliBouncerMetricValue {
    param(
        [AllowEmptyString()]
        [string]$Origin,
        [string]$Name,
        [string]$Unit
    )

    $metrics = Get-CscliBouncerMetrics
    if ($null -eq $metrics) {
        return [int64]0
    }

    $total = [int64]0
    foreach ($bouncer in $metrics.PSObject.Properties) {
        $origins = $bouncer.Value
        if ($null -eq $origins) {
            continue
        }
        foreach ($originNode in $origins.PSObject.Properties) {
            if ($originNode.Name -ne $Origin) {
                continue
            }
            $names = $originNode.Value
            $nameProp = $names.PSObject.Properties[$Name]
            if ($null -eq $nameProp) {
                continue
            }
            $units = $nameProp.Value
            $unitProp = $units.PSObject.Properties[$Unit]
            if ($null -ne $unitProp) {
                $total += [int64]$unitProp.Value
            }
        }
    }
    return $total
}

