#!/usr/bin/env pwsh

<#
.SYNOPSIS
    Runs integration tests for the CrowdSec Bouncer Traefik Plugin

.DESCRIPTION
    This script starts the Docker Compose services, waits for them to be ready,
    runs the Pester integration tests covering different bouncer modes and scenarios,
    and then cleans up the services.

.PARAMETER SkipDockerCleanup
    Skip stopping Docker services after tests complete (useful for debugging and CI log collection)

.PARAMETER SkipWait
    Skip waiting for services to be ready (assumes they're already running)

.PARAMETER TestPath
    Path to the Pester test files (defaults to this suite folder so tests/e2e/mock is not included)


.PARAMETER HttpTimeoutSeconds
    HTTP timeout for bouncer testing (defaults to 30)

.EXAMPLE
    ./tests/e2e/real/Test-Integration.ps1
    Runs the full integration test suite

.EXAMPLE
    ./tests/e2e/real/Test-Integration.ps1 -TestPath "./tests/e2e/real/mode_stream.Tests.ps1" -HttpTimeoutSeconds 60
    Tests only stream mode with 60 second timeout

.EXAMPLE
    ./tests/e2e/real/Test-Integration.ps1 -SkipDockerCleanup
    Runs tests but leaves Docker services running for debugging
#>

[CmdletBinding()]
param(
    [switch]$SkipDockerCleanup,
    [switch]$SkipWait,
    [string]$TestPath = "$PSScriptRoot/*.Tests.ps1",
    [int]$HttpTimeoutSeconds = 30
)

$ErrorActionPreference = "Stop"
$ComposeFile = Join-Path $PSScriptRoot "docker-compose.test.yml"
. "$PSScriptRoot/TestUtils.ps1"

# Colors for output
$Colors = @{
    Info = "Cyan"
    Success = "Green"
    Warning = "Yellow"
    Error = "Red"
}

# Print a numbered runner step to the console.
function Write-Step {
    param([string]$Message, [string]$Color = "Cyan")
    Write-Host "🔄 $Message" -ForegroundColor $Color
}

# Print a success line to the console.
function Write-Success {
    param([string]$Message)
    Write-Host "✅ $Message" -ForegroundColor $Colors.Success
}

# Print a warning line to the console.
function Write-ConsoleWarning {
    param([string]$Message)
    Write-Host "⚠️  $Message" -ForegroundColor $Colors.Warning
}

# Print a failure line to the console without calling the Write-Error cmdlet.
function Write-StepError {
    param([string]$Message)
    Write-Host "❌ $Message" -ForegroundColor $Colors.Error
}

# Main execution
try {
    Write-Host ""
    Write-Host "🚀 CrowdSec Bouncer Traefik Plugin Integration Test Runner" -ForegroundColor $Colors.Info
    Write-Host "=========================================================" -ForegroundColor $Colors.Info
    Write-Host "Test Path: $TestPath" -ForegroundColor $Colors.Info
    Write-Host "HTTP Timeout: $HttpTimeoutSeconds seconds" -ForegroundColor $Colors.Info
    Write-Host ""

    # Check if Pester is available
    Write-Step "Checking Pester availability..."
    try {
        Import-Module Pester -Force -ErrorAction Stop
        $pesterVersion = (Get-Module Pester).Version
        if ($pesterVersion.Major -lt 5) {
            Write-ConsoleWarning "Pester version $pesterVersion detected. Upgrading to v5+..."
            Install-Module -Name Pester -Force -Scope CurrentUser -SkipPublisherCheck
            Import-Module Pester -Force
        }
        Write-Success "Pester $pesterVersion is available"
    }
    catch {
        Write-StepError "Pester module not found. Installing Pester..."
        try {
            Install-Module -Name Pester -Force -Scope CurrentUser -SkipPublisherCheck
            Import-Module Pester -Force
            Write-Success "Pester installed and imported successfully"
        }
        catch {
            Write-StepError "Failed to install Pester: $($_.Exception.Message)"
            exit 1
        }
    }

    # Ensure we are using Linux containers
    Write-Step "Ensuring Linux containers are enabled..."
    try {
        $dockerInfo = docker info --format "{{.OSType}}" 2>$null
        if ($dockerInfo -eq "linux") {
            Write-Success "Docker is using Linux containers"
        } else {
            Write-ConsoleWarning "Docker may not be using Linux containers. Some tests may fail."
        }
    }
    catch {
        Write-ConsoleWarning "Could not verify Docker container type"
    }

    # Check if Docker Compose is available
    Write-Step "Checking Docker Compose availability..."
    try {
        $dockerComposeVersion = docker compose version 2>$null
        if ($LASTEXITCODE -eq 0) {
            Write-Success "Docker Compose is available"
        } else {
            throw "Docker Compose not found"
        }
    }
    catch {
        Write-StepError "Docker Compose is not available. Please install Docker Desktop or Docker Compose."
        exit 1
    }

    # Set environment variables for testing
    $env:HTTP_TIMEOUT_SECONDS = $HttpTimeoutSeconds
    $env:BOUNCER_API_KEY = "40796d93c2958f9e58345514e67740e5"

    # Clean up any existing services
    Write-Step "Cleaning up any existing services..."
    docker compose -f $ComposeFile down -v --remove-orphans 2>$null

    # Start Docker services
    Write-Step "Starting Docker Compose services for testing..."
    try {
        docker compose -f $ComposeFile up -d
        if ($LASTEXITCODE -ne 0) {
            throw "Failed to start Docker services"
        }
        Write-Success "Docker services started successfully"
    }
    catch {
        Write-StepError "Failed to start Docker services: $($_.Exception.Message)"
        exit 1
    }

    if (-not $SkipWait) {
        # Wait for services to be ready
        Write-Step "Waiting for services to become ready..."
        
        $servicesReady = @(
            (Wait-ForHttpStatus -Url "http://localhost:8080/api/rawdata" -ExpectedStatusCodes @(200) -TimeoutSeconds 60).Success,
            (Wait-ForHttpStatus -Url "http://localhost:8000/whoami" -ExpectedStatusCodes @(200) -TimeoutSeconds 60).Success,
            (Wait-ForHttpStatus -Url "http://localhost:8000/redis-cache" -ExpectedStatusCodes @(200) -TimeoutSeconds 60).Success,
            (Wait-ForCondition -Description "CrowdSec LAPI" -TimeoutSeconds 180 -RetryIntervalSeconds 3 -Condition {
                Invoke-CrowdSecAPI -Endpoint "/v1/decisions?limit=1" -TimeoutSec 5 -ApiKey $env:BOUNCER_API_KEY
                return $true
            }).Success,
            (Wait-ForHttpStatus -Url "http://localhost:8000/appsec" -ExpectedStatusCodes @(200) -TimeoutSeconds 180).Success
        )
        
        if ($servicesReady -contains $false) {
            Write-StepError "One or more services failed to start properly"
            if (-not $SkipDockerCleanup) {
                Write-Step "Cleaning up Docker services..."
                docker compose -f $ComposeFile down -v
            }
            exit 1
        }
        
        Write-Success "All services are ready!"
        
        # Give CrowdSec a moment to fully initialize
        Write-Step "Allowing CrowdSec to complete initialization..."
        Start-Sleep 10
        
    } else {
        Write-ConsoleWarning "Skipping service readiness check (assuming services are already running)"
    }

    # Run Pester tests
    Write-Step "Running Pester integration tests..."
    Write-Host ""
    
    if (-not (Test-Path $TestPath)) {
        Write-StepError "Test path not found: $TestPath"
        exit 1
    }

    try {
        $pesterConfig = New-PesterConfiguration
        $pesterConfig.Run.Path = $TestPath
        $pesterConfig.Output.Verbosity = 'Detailed'
        $pesterConfig.Run.Exit = $false
        $pesterConfig.Run.PassThru = $true
        $pesterConfig.TestResult.Enabled = $true
        $pesterConfig.TestResult.OutputPath = Join-Path $PSScriptRoot "test-results.xml"
        
        
        $result = Invoke-Pester -Configuration $pesterConfig
        
        Write-Host ""
        if ($result -and $result.FailedCount -eq 0) {
            Write-Success "All integration tests passed! 🎉"
            Write-Host "  Total: $($result.TotalCount)" -ForegroundColor Gray
            Write-Host "  Passed: $($result.PassedCount)" -ForegroundColor $Colors.Success
            Write-Host "  Duration: $($result.Duration)" -ForegroundColor Gray
            $exitCode = 0
        } elseif ($result) {
            Write-StepError "$($result.FailedCount) test(s) failed out of $($result.TotalCount) total tests"
            Write-Host "  Passed: $($result.PassedCount)" -ForegroundColor $Colors.Success
            Write-Host "  Failed: $($result.FailedCount)" -ForegroundColor $Colors.Error
            Write-Host "  Skipped: $($result.SkippedCount)" -ForegroundColor $Colors.Warning
            Write-Host "  Duration: $($result.Duration)" -ForegroundColor Gray
            $exitCode = 1
        } else {
            Write-ConsoleWarning "Could not determine test results"
            $exitCode = 1
        }
    }
    catch {
        Write-StepError "Failed to run Pester tests: $($_.Exception.Message)"
        $exitCode = 1
    }
}
catch {
    Write-StepError "Unexpected error: $($_.Exception.Message)"
    $exitCode = 1
}
finally {
    # Cleanup Docker services
    if (-not $SkipDockerCleanup) {
        Write-Step "Cleaning up Docker services..."
        try {
            docker compose -f $ComposeFile down -v --remove-orphans 2>$null
            Write-Success "Docker services stopped and cleaned up"
        }
        catch {
            Write-ConsoleWarning "Failed to clean up Docker services: $($_.Exception.Message)"
        }
    } else {
        Write-ConsoleWarning "Skipping Docker cleanup (services left running for debugging)"
        Write-Host "To manually stop services, run: docker compose -f tests/e2e/real/docker-compose.test.yml down -v" -ForegroundColor Gray
        Write-Host "Services available at:" -ForegroundColor Gray
        Write-Host "  - Traefik Dashboard: http://localhost:8080" -ForegroundColor Gray
        Write-Host "  - Test Service: http://localhost:8000/whoami" -ForegroundColor Gray
        Write-Host "  - CrowdSec LAPI: http://localhost:8081/v1/decisions" -ForegroundColor Gray
    }
    
    Write-Host ""
    Write-Host "=========================================================" -ForegroundColor $Colors.Info
    if ($exitCode -eq 0) {
        Write-Host "🏁 Integration tests completed successfully!" -ForegroundColor $Colors.Success
    } else {
        Write-Host "🏁 Integration tests completed with failures!" -ForegroundColor $Colors.Error
    }
    Write-Host ""
}

exit $exitCode 
