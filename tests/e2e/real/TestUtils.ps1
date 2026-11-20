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
    
    $addCommand = "cscli decisions add --ip '$IP' --duration '$Duration' --type '$Type' --reason '$Reason'"
    $result = docker exec crowdsec-test sh -c $addCommand
    if ($LASTEXITCODE -ne 0) {
        throw "Failed to add decision: $result"
    }
    
    Write-Host "✅ Decision added successfully via cscli" -ForegroundColor Green
    return $true
}

# Helper function to create an Ip decision with a chosen decision origin (lists, CAPI, ...).
# cscli can only write the cscli and cscli-import origins, so this posts an alert to LAPI
# as a machine, which is how the CrowdSec engine stores blocklist and community decisions.
function Add-TestOriginDecision {
    param(
        [string]$IP,
        [string]$Origin,
        [string]$Scenario,
        [string]$Type = "ban",
        [string]$Duration = "1h",
        [string]$CrowdSecApiUrl = "http://localhost:8081"
    )

    Write-Host "➕ Adding $Type decision for $IP with origin $Origin ($Scenario)" -ForegroundColor Yellow

    $machine = "e2e-origin-injector"
    $password = "e2e-origin-injector-password"
    $result = docker exec crowdsec-test sh -c "cscli machines add $machine --password $password -f /dev/null --force 2>&1"
    if ($LASTEXITCODE -ne 0) {
        throw "Failed to register the test machine: $result"
    }

    # LAPI rejects a machine login whose User-Agent is not "<name>/<version>".
    $userAgent = "e2e-origin-injector/1.0"
    $login = @{ machine_id = $machine; password = $password; scenarios = @() } | ConvertTo-Json
    $auth = Invoke-RestMethod -Uri "$CrowdSecApiUrl/v1/watchers/login" -Method Post -ContentType "application/json" -UserAgent $userAgent -Body $login -TimeoutSec 10

    $now = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")
    $alerts = @(
        @{
            scenario         = $Scenario
            scenario_hash    = ""
            scenario_version = ""
            message          = "Integration test $Origin decision"
            events_count     = 1
            start_at         = $now
            stop_at          = $now
            capacity         = 0
            leakspeed        = "0"
            simulated        = $false
            events           = @()
            source           = @{ scope = "Ip"; value = $IP }
            decisions        = @(
                @{ origin = $Origin; scenario = $Scenario; scope = "Ip"; value = $IP; type = $Type; duration = $Duration }
            )
        }
    )
    $body = ConvertTo-Json -InputObject $alerts -Depth 10
    $null = Invoke-RestMethod -Uri "$CrowdSecApiUrl/v1/alerts" -Method Post -ContentType "application/json" -UserAgent $userAgent -Headers @{ Authorization = "Bearer $($auth.token)" } -Body $body -TimeoutSec 10

    Write-Host "✅ Decision added successfully via LAPI alert" -ForegroundColor Green
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

    $addCommand = "cscli decisions add --scope '$Scope' --value '$Value' --duration '$Duration' --type '$Type' --reason '$Reason'"
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

# GET/POST without following redirects. Used for captcha solve (302 + Set-Cookie).
function Invoke-HttpNoRedirect {
    param(
        [string]$Uri,
        [string]$Method,
        [hashtable]$Headers,
        [string]$Body,
        [int]$TimeoutSec
    )

    $handler = [System.Net.Http.HttpClientHandler]::new()
    $handler.AllowAutoRedirect = $false
    $handler.UseCookies = $false
    $client = [System.Net.Http.HttpClient]::new($handler)
    $client.Timeout = [TimeSpan]::FromSeconds($TimeoutSec)
    try {
        $httpMethod = [System.Net.Http.HttpMethod]::new($Method)
        $request = [System.Net.Http.HttpRequestMessage]::new($httpMethod, $Uri)
        foreach ($headerName in $Headers.Keys) {
            if ($headerName -eq "Content-Type") {
                continue
            }
            [void]$request.Headers.TryAddWithoutValidation($headerName, [string]$Headers[$headerName])
        }
        if ($null -ne $Body) {
            $request.Content = [System.Net.Http.StringContent]::new(
                $Body,
                [System.Text.Encoding]::UTF8,
                "application/x-www-form-urlencoded"
            )
        }
        $response = $client.Send($request)
        $content = $response.Content.ReadAsStringAsync().GetAwaiter().GetResult()
        $headerMap = @{}
        foreach ($header in $response.Headers) {
            $headerMap[$header.Key] = ($header.Value -join ", ")
        }
        if ($null -ne $response.Content -and $null -ne $response.Content.Headers) {
            foreach ($header in $response.Content.Headers) {
                $headerMap[$header.Key] = ($header.Value -join ", ")
            }
        }
        $contentType = ""
        if ($headerMap.ContainsKey("Content-Type")) {
            $contentType = [string]$headerMap["Content-Type"]
        }
        return @{
            StatusCode  = [int]$response.StatusCode
            Content     = $content
            ContentType = $contentType
            Headers     = $headerMap
            Success     = ([int]$response.StatusCode -ge 200 -and [int]$response.StatusCode -lt 300)
        }
    }
    finally {
        $client.Dispose()
        $handler.Dispose()
    }
}

# GET with the request target written on the wire exactly as given.
# Invoke-WebRequest and HttpClient resolve dot segments and re-encode the path before
# sending, so a path such as /api/../admin or /api/%2e%2e/admin never reaches Traefik.
function Invoke-RawHttpGet {
    param(
        [string]$RequestTarget,
        [string]$IP,
        [string]$TraefikHost = "localhost",
        [int]$Port = 8000,
        [int]$TimeoutSec = 10
    )

    $client = [System.Net.Sockets.TcpClient]::new()
    $client.ReceiveTimeout = $TimeoutSec * 1000
    $client.SendTimeout = $TimeoutSec * 1000
    try {
        $client.Connect($TraefikHost, $Port)
        $stream = $client.GetStream()
        $requestText = "GET $RequestTarget HTTP/1.1`r`nHost: ${TraefikHost}:$Port`r`nX-Forwarded-For: $IP`r`nUser-Agent: Integration-Test-Client`r`nConnection: close`r`n`r`n"
        $requestBytes = [System.Text.Encoding]::ASCII.GetBytes($requestText)
        $stream.Write($requestBytes, 0, $requestBytes.Length)

        $reader = [System.IO.StreamReader]::new($stream, [System.Text.Encoding]::UTF8)
        $raw = $reader.ReadToEnd()
    }
    finally {
        $client.Dispose()
    }

    $headerEnd = $raw.IndexOf("`r`n`r`n")
    if ($headerEnd -lt 0) {
        return @{ StatusCode = 0; Headers = @{}; Content = $raw }
    }
    $headerLines = $raw.Substring(0, $headerEnd) -split "`r`n"
    $statusCode = 0
    if ($headerLines[0] -match '^HTTP/\d\.\d (\d{3})') {
        $statusCode = [int]$Matches[1]
    }
    $headerMap = @{}
    foreach ($line in ($headerLines | Select-Object -Skip 1)) {
        $name, $value = $line -split ':\s*', 2
        $headerMap[$name] = $value
    }
    # Content keeps any chunked framing; callers only search it for markers.
    return @{
        StatusCode = $statusCode
        Headers    = $headerMap
        Content    = $raw.Substring($headerEnd + 4)
    }
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
        [hashtable]$ExtraHeaders = @{},
        [string]$Method = "GET",
        [string]$Body = $null,
        [int]$MaximumRedirection = 5,
        [Microsoft.PowerShell.Commands.WebRequestSession]$Session = $null
    )
    
    $headers = @{
        "X-Forwarded-For" = $IP
        "User-Agent" = "Integration-Test-Client"
    }
    foreach ($headerName in $ExtraHeaders.Keys) {
        $headers[$headerName] = $ExtraHeaders[$headerName]
    }

    # Invoke-WebRequest follows 302 or throws on MaximumRedirection 0; the
    # captcha solve must keep the 302 + Set-Cookie, so that path uses HttpClient.
    if ($MaximumRedirection -eq 0) {
        try {
            return Invoke-HttpNoRedirect -Uri "$TraefikUrl$Endpoint" -Method $Method -Headers $headers -Body $Body -TimeoutSec $TimeoutSec
        }
        catch {
            return @{
                StatusCode  = 0
                Content     = ""
                ContentType = ""
                Headers     = @{}
                Success     = $false
                Error       = $_.Exception.Message
            }
        }
    }

    $invoke = @{
        Uri                 = "$TraefikUrl$Endpoint"
        Headers             = $headers
        TimeoutSec          = $TimeoutSec
        UseBasicParsing     = $true
        SkipHttpErrorCheck  = $true
        Method              = $Method
        MaximumRedirection  = $MaximumRedirection
    }
    if ($headers.ContainsKey("Content-Type")) {
        $invoke.ContentType = [string]$headers["Content-Type"]
        $headers.Remove("Content-Type")
    }
    if ($null -ne $Body) {
        $invoke.Body = $Body
    }
    if ($null -ne $Session) {
        $invoke.WebSession = $Session
    }
    
    try {
        $response = Invoke-WebRequest @invoke
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
        [double]$RetryIntervalSeconds = 0.2
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
        [double]$RetryIntervalSeconds = 0.2,
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

# cscli metrics show bouncers -o json (CrowdSec 1.8) is
# { bouncers: { "NAME@ip": { "<origin>": { "<name>": { "<unit>": n } } } } }.
# Processed lives under origin "". ConvertFrom-Json to PSObject rejects that key.
function Get-CscliBouncerMetrics {
    $raw = docker exec crowdsec-test cscli metrics show bouncers -o json --color no 2>$null
    if ($LASTEXITCODE -ne 0 -or [string]::IsNullOrWhiteSpace($raw)) {
        return $null
    }
    try {
        return $raw | ConvertFrom-Json -AsHashtable
    }
    catch {
        Write-Host "⚠️ cscli metrics JSON parse failed: $raw" -ForegroundColor Yellow
        return $null
    }
}

# Sum one cscli bouncer metric over every bouncer, or only $Bouncer (the cscli bouncer name) when set.
function Get-CscliBouncerMetricValue {
    param(
        [AllowEmptyString()]
        [string]$Origin,
        [string]$Name,
        [string]$Unit,
        [string]$Bouncer = ""
    )

    $metrics = Get-CscliBouncerMetrics
    if ($null -eq $metrics) {
        return [int64]0
    }

    $bouncers = $metrics['bouncers']
    if ($null -eq $bouncers) {
        return [int64]0
    }

    $total = [int64]0
    foreach ($bouncerName in @($bouncers.Keys)) {
        if ($Bouncer -and $bouncerName -ne $Bouncer) {
            continue
        }
        $origins = $bouncers[$bouncerName]
        if ($null -eq $origins -or -not $origins.ContainsKey($Origin)) {
            continue
        }
        $names = $origins[$Origin]
        if ($null -eq $names -or -not $names.ContainsKey($Name)) {
            continue
        }
        $units = $names[$Name]
        if ($null -eq $units -or -not $units.ContainsKey($Unit)) {
            continue
        }
        $total += [int64]$units[$Unit]
    }
    return $total
}

