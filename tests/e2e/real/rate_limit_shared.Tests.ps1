#!/usr/bin/env pwsh

# The shared rate-limit leg against real Traefik and Dragonfly (config/dynamic/rate-limit-shared.yml):
# one owner (rl-shared-owner, no bouncing) publishes the policy under rl-shared, and two subscribers
# (rl-shared-a, rl-shared-b) charge it under their own names. Owner removal and the bucket edit rewrite
# that file through the file provider (the instance_severance harness) and write the committed file back.
# Counters live in Dragonfly for two windows, so every case takes a client address no other case and no
# recent run uses: one random /24 per run, one host per case.

BeforeAll {
    . "$PSScriptRoot/TestUtils.ps1"

    $script:TraefikUrl = "http://localhost:8000"
    $script:RunPrefix = "10.$(Get-Random -Minimum 1 -Maximum 255).$(Get-Random -Minimum 0 -Maximum 255)"
    $script:SharedFile = Join-Path $PSScriptRoot "config/dynamic/rate-limit-shared.yml"
    $script:SharedFileCommitted = [System.IO.File]::ReadAllBytes($script:SharedFile)
    $script:SharedRouters = @("rl-shared-owner", "rl-shared-a", "rl-shared-b")
    $script:GraceSeconds = 3

    # Client address number $HostNumber of this run, inside the random /24 of this run.
    function Get-SharedClientIP {
        param([int]$HostNumber)
        return "$($script:RunPrefix).$HostNumber"
    }

    # Sends $Count GET requests to $Endpoint from $IP and returns the responses in order.
    function Send-SharedRequests {
        param([string]$Endpoint, [string]$IP, [int]$Count)
        return @(foreach ($attempt in 1..$Count) {
                Test-HttpRequest -Endpoint $Endpoint -IP $IP -TraefikUrl $script:TraefikUrl
            })
    }

    # The shared fixture with the owner publishing a per-ip bucket of $Requests per hour, or, without
    # -OwnerEnabled, the owner router kept with a middleware that opens no leg (it stops publishing).
    function Get-SharedYaml {
        param([switch]$OwnerEnabled, [int]$Requests = 3)
        $owner = @"
    rl-shared-owner:
      plugin:
        bouncer:
          bouncerEnabled: "false"
          logFormat: json
          logLevel: DEBUG
          reclaimGraceSeconds: "2"
"@
        if ($OwnerEnabled) {
            $owner = @"
    rl-shared-owner:
      plugin:
        bouncer:
          bouncerEnabled: "false"
          logFormat: json
          logLevel: DEBUG
          rateLimitBuckets:
            - name: per-ip
              requests: "$Requests"
              window: 1h
              key:
                - from: ip
          rateLimitEnabled: "true"
          rateLimitInstanceName: rl-shared
          rateLimitRedisHost: dragonfly:6379
          rateLimitStatusCode: "503"
          rateLimitSyncRate: "0"
          reclaimGraceSeconds: "2"
"@
        }
        $subscribers = foreach ($name in @("rl-shared-a", "rl-shared-b")) {
            @"
    ${name}:
      plugin:
        bouncer:
          bouncerEnabled: "true"
          bouncerForwardedHeadersCustomName: X-Forwarded-For
          bouncerForwardedHeadersTrustedIps:
            - "172.28.0.1/32"
          bouncerRemediationHeadersCustomName: X-Crowdsec-Remediation
          logFormat: json
          logLevel: TRACE
          rateLimitInstanceName: rl-shared
          reclaimGraceSeconds: "2"
"@
        }
        $routers = foreach ($name in $script:SharedRouters) {
            @"
    ${name}:
      rule: PathPrefix(``/$name/``)
      entryPoints: [web]
      middlewares: [$name]
      service: whoami@docker
"@
        }
        return "http:`n  routers:`n$($routers -join "`n")`n  middlewares:`n$owner`n$($subscribers -join "`n")`n"
    }

    # Bind-mount overwrites often skip inotify: delete, write, docker cp, and touch, as
    # instance_severance does, then wait until Traefik lists the routers again.
    function Write-SharedFile {
        param([byte[]]$Content)
        $containerPath = "/etc/traefik/dynamic/rate-limit-shared.yml"
        docker exec traefik-test rm -f $containerPath | Out-Null
        [System.IO.File]::WriteAllBytes($script:SharedFile, $Content)
        docker cp $script:SharedFile "traefik-test:$containerPath"
        if ($LASTEXITCODE -ne 0) {
            throw "docker cp rate-limit-shared.yml failed"
        }
        docker exec traefik-test touch $containerPath | Out-Null
        $applied = Wait-ForCondition -Description "rl-shared routers" -TimeoutSeconds 15 -RetryIntervalSeconds 0.2 -Condition {
            try {
                $names = @(Invoke-RestMethod -Uri "http://localhost:8080/api/http/routers" -TimeoutSec 3 | ForEach-Object { $_.name })
            }
            catch {
                return $false
            }
            return @($script:SharedRouters | Where-Object { "$_@file" -notin $names }).Count -eq 0
        }
        if (-not $applied.Success) {
            throw "Traefik file provider did not apply rate-limit-shared.yml"
        }
    }

    function Write-SharedYaml {
        param([string]$Yaml)
        Write-SharedFile -Content ([System.Text.UTF8Encoding]::new($false).GetBytes($Yaml))
    }

    # Plugin lines Traefik logged since $Since that contain every string in $Contains.
    function Get-SharedLogLines {
        param([string]$Since, [string[]]$Contains)
        return @(Get-ContainerLogLines -Container "traefik-test" -Since $Since -Contains $Contains)
    }

    # Incarnation attr of a log line, or "".
    function Get-LogIncarnation {
        param([string]$Line)
        $found = [regex]::Match($Line, '"incarnation":"([^"]+)"')
        if ($found.Success) {
            return $found.Groups[1].Value
        }
        return ""
    }

    # Waits until both subscribers answer a fresh address with the owner's 503 on request requests + 1.
    function Wait-SharedPolicyAnswers {
        param([int]$HostNumber, [int]$TimeoutSeconds = 30)
        foreach ($subscriber in @("rl-shared-a", "rl-shared-b")) {
            $answered = Wait-ForHttpStatus -Url "$($script:TraefikUrl)/$subscriber/ready" -Headers @{ "X-Forwarded-For" = (Get-SharedClientIP -HostNumber $HostNumber) } -ExpectedStatusCodes @(503) -TimeoutSeconds $TimeoutSeconds
            if (-not $answered.Success) {
                throw "/$subscriber/ did not answer with the rl-shared policy (last=$($answered.StatusCode))"
            }
        }
    }

    Wait-SharedPolicyAnswers -HostNumber 250 -TimeoutSeconds 60
}

AfterAll {
    Write-SharedFile -Content $script:SharedFileCommitted
}

Describe "Shared rate-limit leg" {
    Context "owner and two subscribers" -Tag "ratelimit" {
        It "Should answer both subscribers with the owner's policy" {
            foreach ($case in @(
                    @{ Subscriber = "rl-shared-a"; HostNumber = 1 }
                    @{ Subscriber = "rl-shared-b"; HostNumber = 2 }
                )) {
                $responses = Send-SharedRequests -Endpoint "/$($case.Subscriber)/page" -IP (Get-SharedClientIP -HostNumber $case.HostNumber) -Count 4
                foreach ($attempt in 0..2) {
                    $responses[$attempt].StatusCode | Should -Be 200 -Because "request $($attempt + 1) of 3 through $($case.Subscriber) is within the owner's bucket"
                }
                $responses[3].StatusCode | Should -Be 503 -Because "the owner's rateLimitStatusCode answers on $($case.Subscriber)"
                [string]$responses[3].Headers["X-Crowdsec-Remediation"] | Should -Be "ban:ratelimit:per-ip"
                [int]([string]$responses[3].Headers["Retry-After"]) | Should -BeGreaterThan 0
            }
        }

        It "Should keep a separate budget per subscriber" {
            $ip = Get-SharedClientIP -HostNumber 3
            $exhausted = Send-SharedRequests -Endpoint "/rl-shared-a/page" -IP $ip -Count 4
            $exhausted[3].StatusCode | Should -Be 503

            $other = Send-SharedRequests -Endpoint "/rl-shared-b/page" -IP $ip -Count 3
            foreach ($attempt in 0..2) {
                $other[$attempt].StatusCode | Should -Be 200 -Because "rl-shared-b counts under its own name"
                $other[$attempt].Content | Should -Match "Hostname:"
                [string]$other[$attempt].Headers["X-Crowdsec-Remediation"] | Should -BeNullOrEmpty
            }
        }
    }

    Context "owner lifecycle" -Tag "ratelimit", "lifecycle" {
        AfterEach {
            Write-SharedFile -Content $script:SharedFileCommitted
        }

        It "Should pass subscribers through while the owner is gone and answer again when it returns" {
            $ip = Get-SharedClientIP -HostNumber 10
            $limited = Send-SharedRequests -Endpoint "/rl-shared-a/page" -IP $ip -Count 4
            $limited[3].StatusCode | Should -Be 503

            $since = Get-LogSince
            Write-SharedYaml (Get-SharedYaml)
            Start-Sleep -Seconds $script:GraceSeconds
            $passed = Wait-ForHttpStatus -Url "$($script:TraefikUrl)/rl-shared-a/page" -Headers @{ "X-Forwarded-For" = $ip } -ExpectedStatusCodes @(200) -TimeoutSeconds 15
            $passed.Success | Should -BeTrue -Because "a subscriber passes requests through while its owner is unpublished"
            foreach ($subscriber in @("rl-shared-a", "rl-shared-b")) {
                $response = Test-HttpRequest -Endpoint "/$subscriber/page" -IP $ip -TraefikUrl $script:TraefikUrl
                $response.StatusCode | Should -Be 200
                $response.Content | Should -Match "Hostname:"
                [string]$response.Headers["X-Crowdsec-Remediation"] | Should -BeNullOrEmpty -Because "an unpublished owner is not a remediation"
            }
            # Lifecycle lines reach `docker logs` asynchronously, and the file write (rm, cp, touch) can make
            # Traefik reload more than once; under Yaegi each rebuilt subscriber logs one WARN when it starts
            # without an owner. So poll with a deadline: the unbind and a WARN per subscriber must show up, and
            # the WARN counts must stop moving (3 equal reads 1s apart) before the per-request check.
            $ownerWarningCounts = {
                $counts = @{}
                foreach ($subscriber in @("rl-shared-a", "rl-shared-b")) {
                    $counts[$subscriber] = @(Get-SharedLogLines -Since $since -Contains @("crowdsec bouncer rate limit owner unavailable", '"level":"WARN"', "`"traefikName`":`"$subscriber", '"instanceName":"rl-shared"')).Count
                }
                return $counts
            }
            $script:WarnStable = 0
            $script:WarnLast = ""
            $settled = Wait-ForCondition -Description "owner-loss WARN per subscriber, settled" -TimeoutSeconds 30 -RetryIntervalSeconds 1 -Condition {
                $unbound = @(Get-SharedLogLines -Since $since -Contains @("crowdsec bouncer unbound", '"leg":"ratelimit"', '"instanceName":"rl-shared"'))
                $counts = & $ownerWarningCounts
                if ($unbound.Count -eq 0 -or $counts["rl-shared-a"] -eq 0 -or $counts["rl-shared-b"] -eq 0) {
                    $script:WarnStable = 0
                    return $false
                }
                $current = "$($counts['rl-shared-a'])/$($counts['rl-shared-b'])"
                if ($current -eq $script:WarnLast) {
                    $script:WarnStable++
                }
                else {
                    $script:WarnStable = 0
                    $script:WarnLast = $current
                }
                return $script:WarnStable -ge 2
            }
            $settled.Success | Should -BeTrue -Because "each subscriber logs the unbind and WARN when its rate-limit owner stops being published (last WARN counts a/b: $($script:WarnLast))"

            # Each subscriber warns once for the loss, not per request: 3 requests through each add no WARN.
            $ownerWarnings = & $ownerWarningCounts
            Send-SharedRequests -Endpoint "/rl-shared-a/page" -IP $ip -Count 3 | Out-Null
            Send-SharedRequests -Endpoint "/rl-shared-b/page" -IP $ip -Count 3 | Out-Null
            Start-Sleep -Seconds 2
            $afterRequests = & $ownerWarningCounts
            foreach ($subscriber in @("rl-shared-a", "rl-shared-b")) {
                $afterRequests[$subscriber] | Should -Be $ownerWarnings[$subscriber] -Because "requests through $subscriber while its owner is gone add no WARN"
            }

            $since = Get-LogSince
            Write-SharedFile -Content $script:SharedFileCommitted
            $back = Wait-ForHttpStatus -Url "$($script:TraefikUrl)/rl-shared-a/page" -Headers @{ "X-Forwarded-For" = $ip } -ExpectedStatusCodes @(503) -TimeoutSeconds 15
            $back.Success | Should -BeTrue -Because "the over-limit client is answered again once the owner publishes; last=$($back.StatusCode)"
            $backB = Wait-ForHttpStatus -Url "$($script:TraefikUrl)/rl-shared-b/page" -Headers @{ "X-Forwarded-For" = $ip } -ExpectedStatusCodes @(503) -TimeoutSeconds 15
            $backB.Success | Should -BeTrue -Because "both subscribers bind the republished client; last=$($backB.StatusCode)"
            # The reload that restores the owner rebuilds the subscribers too, in an order Traefik does not fix:
            # a subscriber built before the owner starts without one (one WARN under Yaegi) and must log INFO
            # when the owner binds; one built after it binds at once and logs neither. So every WARN since the
            # restore must be followed by an INFO of the same subscriber, and each subscriber logs a bind.
            $script:MissingReturnLines = @()
            $returned = Wait-ForCondition -Description "rate-limit bind per subscriber and INFO after every WARN" -TimeoutSeconds 20 -RetryIntervalSeconds 0.5 -Condition {
                $missing = @()
                foreach ($subscriber in @("rl-shared-a", "rl-shared-b")) {
                    if (@(Get-SharedLogLines -Since $since -Contains @("crowdsec bouncer bound", '"leg":"ratelimit"', "`"traefikName`":`"$subscriber", '"instanceName":"rl-shared"')).Count -eq 0) {
                        $missing += "bound $subscriber"
                    }
                    $warned = @(Get-SharedLogLines -Since $since -Contains @("crowdsec bouncer rate limit owner unavailable", '"level":"WARN"', "`"traefikName`":`"$subscriber", '"instanceName":"rl-shared"')).Count
                    $available = @(Get-SharedLogLines -Since $since -Contains @("crowdsec bouncer rate limit owner available", '"level":"INFO"', "`"traefikName`":`"$subscriber", '"instanceName":"rl-shared"')).Count
                    if ($available -lt $warned) {
                        $missing += "INFO $subscriber ($warned WARN, $available INFO)"
                    }
                }
                $script:MissingReturnLines = $missing
                return $missing.Count -eq 0
            }
            $returned.Success | Should -BeTrue -Because "each subscriber binds the republished client and logs INFO after any WARN of the restore (missing: $($script:MissingReturnLines -join ', '))"
        }

        It "Should open a new client on a bucket edit and keep the count" {
            $ip = Get-SharedClientIP -HostNumber 11
            $within = Send-SharedRequests -Endpoint "/rl-shared-a/page" -IP $ip -Count 3
            foreach ($attempt in 0..2) {
                $within[$attempt].StatusCode | Should -Be 200
            }
            $started = @(Get-ContainerLogLines -Container "traefik-test" -Since "1970-01-01T00:00:00Z" -Contains @("crowdsec ratelimit instance started", '"instanceName":"rl-shared"'))
            $previous = @($started | ForEach-Object { Get-LogIncarnation -Line $_ } | Where-Object { $_ })

            $since = Get-LogSince
            Write-SharedYaml (Get-SharedYaml -OwnerEnabled -Requests 5)
            $edited = Wait-ForCondition -Description "a new rl-shared incarnation bound on rl-shared-a" -TimeoutSeconds 15 -RetryIntervalSeconds 0.5 -Condition {
                $fresh = @(Get-SharedLogLines -Since $since -Contains @("crowdsec ratelimit instance started", '"instanceName":"rl-shared"') |
                        ForEach-Object { Get-LogIncarnation -Line $_ } | Where-Object { $_ -and $_ -notin $previous })
                if ($fresh.Count -eq 0) {
                    return $false
                }
                $bound = @(Get-SharedLogLines -Since $since -Contains @("crowdsec bouncer bound", '"leg":"ratelimit"', "rl-shared-a", "`"incarnation`":`"$($fresh[-1])`""))
                return $bound.Count -gt 0
            }
            $edited.Success | Should -BeTrue -Because "the bucket edit opens a new client and the subscriber binds it"

            $after = Send-SharedRequests -Endpoint "/rl-shared-a/page" -IP $ip -Count 3
            foreach ($attempt in 0..1) {
                $after[$attempt].StatusCode | Should -Be 200 -Because "requests 4 and 5 fit the raised bucket of 5"
            }
            $after[2].StatusCode | Should -Be 503 -Because "the 3 requests before the edit still count: request 6 is over 5"
            [string]$after[2].Headers["X-Crowdsec-Remediation"] | Should -Be "ban:ratelimit:per-ip"
        }
    }
}
