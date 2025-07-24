#!/usr/bin/env pwsh

<#
.SYNOPSIS
    Integration tests for Redis cache functionality in CrowdSec Bouncer Traefik Plugin

.DESCRIPTION
    These tests verify that Redis cache is working properly with DragonflyDB,
    testing both blocked and permissive modes when Redis is unreachable.
#>

BeforeAll {
    # Test configuration
    $script:BaseUrl = "http://localhost:8000"
    $script:RedisEndpoint = "$BaseUrl/redis-cache"
    $script:RedisPermissiveEndpoint = "$BaseUrl/redis-cache-permissive"
    $script:DragonFlyContainer = "dragonfly-test"
    
    # Helper function to check if container is running
    function Test-ContainerRunning {
        param([string]$ContainerName)
        try {
            $status = docker inspect $ContainerName --format "{{.State.Running}}" 2>$null
            return $status -eq "true"
        }
        catch {
            return $false
        }
    }

    # Helper function to stop/start DragonflyDB
    function Stop-DragonflyDB {
        Write-Host "Stopping DragonflyDB..." -ForegroundColor Yellow
        docker stop $script:DragonFlyContainer 2>$null | Out-Null
        Start-Sleep 2
    }

    function Start-DragonflyDB {
        Write-Host "Starting DragonflyDB..." -ForegroundColor Green
        docker start $script:DragonFlyContainer 2>$null | Out-Null
        Start-Sleep 5
        
        # Wait for DragonflyDB to be ready
        $retries = 0
        do {
            try {
                $result = docker exec $script:DragonFlyContainer redis-cli -a testpassword123 ping 2>$null
                if ($result -eq "PONG") {
                    Write-Host "DragonflyDB is ready!" -ForegroundColor Green
                    return $true
                }
            }
            catch {}
            Start-Sleep 2
            $retries++
        } while ($retries -lt 10)
        
        return $false
    }

    # Helper function to make HTTP request
    function Invoke-TestRequest {
        param(
            [string]$Url,
            [hashtable]$Headers = @{},
            [int]$TimeoutSec = 10
        )
        
        try {
            $response = Invoke-WebRequest -Uri $Url -Headers $Headers -TimeoutSec $TimeoutSec -UseBasicParsing
            return @{
                StatusCode = $response.StatusCode
                Content = $response.Content
                Headers = $response.Headers
                Success = $true
            }
        }
        catch {
            $statusCode = if ($_.Exception.Response) { 
                [int]$_.Exception.Response.StatusCode 
            } else { 
                0 
            }
            return @{
                StatusCode = $statusCode
                Content = $_.Exception.Message
                Headers = @{}
                Success = $false
                Exception = $_.Exception
            }
        }
    }

    # Helper function to test Redis connectivity
    function Test-RedisConnectivity {
        try {
            $result = docker exec $script:DragonFlyContainer redis-cli -a testpassword123 ping 2>$null
            return $result -eq "PONG"
        }
        catch {
            return $false
        }
    }

    Write-Host "🧪 Starting Redis Cache Integration Tests" -ForegroundColor Cyan
    Write-Host "Base URL: $script:BaseUrl" -ForegroundColor Gray
}

Describe "Redis Cache Integration Tests" {
    Context "Redis Cache with Strict Mode (redisCacheUnreachableBlock=true)" {
        
        It "Should allow traffic when Redis is available" {
            # Ensure DragonflyDB is running
            if (-not (Test-ContainerRunning $script:DragonFlyContainer)) {
                Start-DragonflyDB | Should -Be $true
            }
            
            Test-RedisConnectivity | Should -Be $true
            
            # Make request to Redis cache endpoint
            $response = Invoke-TestRequest -Url $script:RedisEndpoint
            
            $response.Success | Should -Be $true
            $response.StatusCode | Should -BeIn @(200, 404)  # 404 is OK if whoami returns it for the path
            Write-Host "✓ Traffic allowed when Redis is available (Status: $($response.StatusCode))" -ForegroundColor Green
        }
        
        It "Should block traffic when Redis is unreachable (strict mode)" {
            # Stop DragonflyDB to simulate Redis being unreachable
            Stop-DragonflyDB
            
            # Verify Redis is unreachable
            Test-RedisConnectivity | Should -Be $false
            
            # Wait a moment for the bouncer to detect Redis is down
            Start-Sleep 3
            
            # Make request to Redis cache endpoint - should be blocked
            $response = Invoke-TestRequest -Url $script:RedisEndpoint -TimeoutSec 15
            
            # Should be blocked (403 Forbidden or connection refused)
            $response.StatusCode | Should -BeIn @(403, 502, 503, 0)
            Write-Host "✓ Traffic blocked when Redis is unreachable (Status: $($response.StatusCode))" -ForegroundColor Green
            
            # Restart DragonflyDB for next tests
            Start-DragonflyDB | Should -Be $true
        }
    }
    
    Context "Redis Cache with Permissive Mode (redisCacheUnreachableBlock=false)" {
        
        It "Should allow traffic when Redis is available" {
            # Ensure DragonflyDB is running
            if (-not (Test-ContainerRunning $script:DragonFlyContainer)) {
                Start-DragonflyDB | Should -Be $true
            }
            
            Test-RedisConnectivity | Should -Be $true
            
            # Make request to Redis cache permissive endpoint
            $response = Invoke-TestRequest -Url $script:RedisPermissiveEndpoint
            
            $response.Success | Should -Be $true
            $response.StatusCode | Should -BeIn @(200, 404)  # 404 is OK if whoami returns it for the path
            Write-Host "✓ Traffic allowed when Redis is available (permissive mode, Status: $($response.StatusCode))" -ForegroundColor Green
        }
        
        It "Should allow traffic when Redis is unreachable (permissive mode)" {
            # Stop DragonflyDB to simulate Redis being unreachable
            Stop-DragonflyDB
            
            # Verify Redis is unreachable
            Test-RedisConnectivity | Should -Be $false
            
            # Wait a moment for the bouncer to detect Redis is down
            Start-Sleep 3
            
            # Make request to Redis cache permissive endpoint - should still be allowed
            $response = Invoke-TestRequest -Url $script:RedisPermissiveEndpoint -TimeoutSec 15
            
            # Should be allowed even though Redis is down
            $response.Success | Should -Be $true
            $response.StatusCode | Should -BeIn @(200, 404)  # 404 is OK if whoami returns it for the path
            Write-Host "✓ Traffic allowed when Redis is unreachable (permissive mode, Status: $($response.StatusCode))" -ForegroundColor Green
            
            # Restart DragonflyDB for next tests
            Start-DragonflyDB | Should -Be $true
        }
    }
    
    Context "Redis Cache Functionality" {
        
        It "Should successfully connect to DragonflyDB with authentication" {
            # Ensure DragonflyDB is running
            if (-not (Test-ContainerRunning $script:DragonFlyContainer)) {
                Start-DragonflyDB | Should -Be $true
            }
            
            # Test Redis connectivity with authentication
            Test-RedisConnectivity | Should -Be $true
            
            # Test setting and getting a value in Redis
            $setResult = docker exec $script:DragonFlyContainer redis-cli -a testpassword123 set testkey testvalue 2>$null
            $setResult | Should -Be "OK"
            
            $getValue = docker exec $script:DragonFlyContainer redis-cli -a testpassword123 get testkey 2>$null
            $getValue | Should -Be "testvalue"
            
            # Clean up test key
            docker exec $script:DragonFlyContainer redis-cli -a testpassword123 del testkey 2>$null
            
            Write-Host "✓ DragonflyDB authentication and basic operations working" -ForegroundColor Green
        }
        
        It "Should use different Redis databases for different middleware instances" {
            # The configuration uses database 0 for strict mode and database 1 for permissive mode
            # This test verifies they can operate independently
            
            # Ensure DragonflyDB is running
            if (-not (Test-ContainerRunning $script:DragonFlyContainer)) {
                Start-DragonflyDB | Should -Be $true
            }
            
            # Set different values in different databases
            $setDb0 = docker exec $script:DragonFlyContainer redis-cli -a testpassword123 -n 0 set testdb0 value0 2>$null
            $setDb1 = docker exec $script:DragonFlyContainer redis-cli -a testpassword123 -n 1 set testdb1 value1 2>$null
            
            $setDb0 | Should -Be "OK"
            $setDb1 | Should -Be "OK"
            
            # Verify values are in correct databases and isolated
            $getDb0 = docker exec $script:DragonFlyContainer redis-cli -a testpassword123 -n 0 get testdb0 2>$null
            $getDb1 = docker exec $script:DragonFlyContainer redis-cli -a testpassword123 -n 1 get testdb1 2>$null
            
            $getDb0 | Should -Be "value0"
            $getDb1 | Should -Be "value1"
            
            # Verify isolation - keys should not exist in other databases
            $getDb0FromDb1 = docker exec $script:DragonFlyContainer redis-cli -a testpassword123 -n 1 get testdb0 2>$null
            $getDb1FromDb0 = docker exec $script:DragonFlyContainer redis-cli -a testpassword123 -n 0 get testdb1 2>$null
            
            # Should be null (empty) since keys don't exist in other databases
            $getDb0FromDb1 | Should -BeNullOrEmpty
            $getDb1FromDb0 | Should -BeNullOrEmpty
            
            # Clean up test keys
            docker exec $script:DragonFlyContainer redis-cli -a testpassword123 -n 0 del testdb0 2>$null
            docker exec $script:DragonFlyContainer redis-cli -a testpassword123 -n 1 del testdb1 2>$null
            
            Write-Host "✓ Redis database isolation working correctly" -ForegroundColor Green
        }
    }
}

AfterAll {
    # Ensure DragonflyDB is running for other tests
    if (-not (Test-ContainerRunning $script:DragonFlyContainer)) {
        Write-Host "Restarting DragonflyDB for other tests..." -ForegroundColor Yellow
        Start-DragonflyDB | Out-Null
    }
    
    Write-Host "🏁 Redis Cache Integration Tests Complete" -ForegroundColor Cyan
} 