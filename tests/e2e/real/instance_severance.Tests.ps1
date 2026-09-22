#!/usr/bin/env pwsh

# Named LAPI/AppSec slots, late bind, file-provider reload, collision, leftover config.
# Drive routes through the writable file provider under tests/e2e/real/dynamic/.

BeforeAll {
    . "$PSScriptRoot/TestUtils.ps1"

    $script:TraefikUrl = "http://localhost:8000"
    $script:SevFile = Join-Path $PSScriptRoot "dynamic/instance-severance.yml"
    $script:OwnerKey = "c51a1c70000000000000000000000012"
    $script:KeyB = "c51a1c70000000000000000000000013"
    $script:AppsecKey = "c51a1c70000000000000000000000005"
    $script:GraceSeconds = 40
    $script:Whoami = "http://whoami-test:80"
    $script:Utf8 = New-Object System.Text.UTF8Encoding $false

    $ready = Wait-ForCondition -Description "Traefik whoami" -TimeoutSeconds 60 -RetryIntervalSeconds 2 -Condition {
        try {
            $response = Invoke-WebRequest -Uri "http://localhost:8000/disabled" -TimeoutSec 3 -UseBasicParsing
            return ($response.StatusCode -eq 200)
        }
        catch {
            return $false
        }
    }
    if (-not $ready.Success) {
        throw "Traefik failed to become ready for instance severance tests"
    }
}

AfterAll {
    if (Test-Path $script:SevFile) {
        Remove-Item -Force $script:SevFile
    }
}

function Write-SevYaml {
    param([string]$Yaml)
    [System.IO.File]::WriteAllText($script:SevFile, $Yaml.TrimStart(), $script:Utf8)
}

function Get-SevLogs {
    return (docker logs traefik-test 2>&1 | Out-String)
}

function Get-SevKnobs {
    return @"
          logLevel: DEBUG
          httpTimeoutSeconds: "10"
          updateIntervalSeconds: "2"
          forwardedHeadersTrustedIps:
            - "172.16.0.0/12"
            - "172.28.0.1/32"
          forwardedHeadersCustomName: X-Forwarded-For
"@
}

function Get-SevService {
    return @"
  services:
    sev-whoami:
      loadBalancer:
        servers:
          - url: "$script:Whoami"
"@
}

function Wait-SevCodes {
    param(
        [string]$Path,
        [string]$IP,
        [int[]]$Codes,
        [int]$TimeoutSeconds = 45
    )
    $result = Wait-ForHttpStatus -Url "$script:TraefikUrl$Path" -Headers @{ "X-Forwarded-For" = $IP } -ExpectedStatusCodes $Codes -TimeoutSeconds $TimeoutSeconds
    return $result
}

Describe "Instance severance topology" {
    BeforeEach {
        Remove-AllTestDecisions
    }

    AfterEach {
        if (Test-Path $script:SevFile) {
            Remove-Item -Force $script:SevFile
        }
        Remove-AllTestDecisions
    }

    It "T1 one middleware omitted names still bans" {
        $knobs = Get-SevKnobs
        $svc = Get-SevService
        Write-SevYaml @"
http:
  routers:
    sev-t1:
      rule: PathPrefix(`/sev-t1`)
      entryPoints: [web]
      middlewares: [sev-t1]
      service: sev-whoami
$svc
  middlewares:
    sev-t1:
      plugin:
        bouncer:
          enabled: "true"
          crowdsecMode: stream
          crowdsecLapiEnabled: "true"
          crowdsecAppsecEnabled: "true"
          crowdsecLapiKey: "$script:OwnerKey"
          crowdsecLapiHost: crowdsec:8080
          crowdsecAppsecHost: crowdsec:7422
$knobs
"@
        $ip = "172.19.0.51"
        $up = Wait-SevCodes -Path "/sev-t1" -IP $ip -Codes @(200) -TimeoutSeconds 45
        $up.Success | Should -BeTrue -Because "T1 route must come up"
        Add-TestDecision -IP $ip -Type "ban" -Reason "T1"
        $blocked = Wait-SevCodes -Path "/sev-t1" -IP $ip -Codes @(403, 429) -TimeoutSeconds 30
        $blocked.Success | Should -BeTrue -Because "T1 banned IP is 403"
    }

    It "T2 named share owner is a real route" {
        $knobs = Get-SevKnobs
        $svc = Get-SevService
        Write-SevYaml @"
http:
  routers:
    sev-t2-api:
      rule: PathPrefix(`/sev-t2-api`)
      entryPoints: [web]
      middlewares: [sev-t2-cs]
      service: sev-whoami
    sev-t2-admin:
      rule: PathPrefix(`/sev-t2-admin`)
      entryPoints: [web]
      middlewares: [sev-t2-admin]
      service: sev-whoami
$svc
  middlewares:
    sev-t2-cs:
      plugin:
        bouncer:
          enabled: "true"
          crowdsecMode: stream
          crowdsecLapiEnabled: "true"
          crowdsecAppsecEnabled: "true"
          crowdsecLapiInstanceName: shared
          crowdsecAppsecInstanceName: shared
          crowdsecLapiKey: "$script:OwnerKey"
          crowdsecLapiHost: crowdsec:8080
          crowdsecAppsecHost: crowdsec:7422
$knobs
    sev-t2-admin:
      plugin:
        bouncer:
          enabled: "true"
          crowdsecLapiInstanceName: shared
          crowdsecAppsecInstanceName: shared
          remediationHeadersCustomName: x-crowdsec
$knobs
"@
        $ip = "172.19.0.52"
        $apiUp = Wait-SevCodes -Path "/sev-t2-api" -IP $ip -Codes @(200) -TimeoutSeconds 45
        $apiUp.Success | Should -BeTrue
        Add-TestDecision -IP $ip -Type "ban" -Reason "T2"
        $apiBan = Wait-SevCodes -Path "/sev-t2-api" -IP $ip -Codes @(403, 429) -TimeoutSeconds 30
        $adminBan = Wait-SevCodes -Path "/sev-t2-admin" -IP $ip -Codes @(403, 429) -TimeoutSeconds 30
        $apiBan.Success | Should -BeTrue
        $adminBan.Success | Should -BeTrue
        $logs = Get-SevLogs
        $logs | Should -Not -Match "crowdsec instance name taken"
        $logs | Should -Match "crowdsec bouncer bound"
    }

    It "T3 optional placeholder enabled false still opens" {
        $knobs = Get-SevKnobs
        $svc = Get-SevService
        Write-SevYaml @"
http:
  routers:
    sev-t3-hold:
      rule: PathPrefix(`/sev-t3-hold`)
      entryPoints: [web]
      middlewares: [sev-t3-hold]
      service: sev-whoami
    sev-t3-app:
      rule: PathPrefix(`/sev-t3-app`)
      entryPoints: [web]
      middlewares: [sev-t3-app]
      service: sev-whoami
$svc
  middlewares:
    sev-t3-hold:
      plugin:
        bouncer:
          enabled: false
          crowdsecMode: stream
          crowdsecLapiEnabled: "true"
          crowdsecAppsecEnabled: "true"
          crowdsecLapiInstanceName: shared
          crowdsecAppsecInstanceName: shared
          crowdsecLapiKey: "$script:OwnerKey"
          crowdsecLapiHost: crowdsec:8080
          crowdsecAppsecHost: crowdsec:7422
$knobs
    sev-t3-app:
      plugin:
        bouncer:
          enabled: "true"
          crowdsecLapiInstanceName: shared
          crowdsecAppsecInstanceName: shared
$knobs
"@
        $ip = "172.19.0.53"
        $hold = Wait-SevCodes -Path "/sev-t3-hold" -IP $ip -Codes @(200) -TimeoutSeconds 45
        $hold.Success | Should -BeTrue -Because "placeholder calls next"
        Add-TestDecision -IP $ip -Type "ban" -Reason "T3"
        $app = Wait-SevCodes -Path "/sev-t3-app" -IP $ip -Codes @(403, 429) -TimeoutSeconds 30
        $app.Success | Should -BeTrue
    }

    It "T4 AppSec only has no LAPI 503" {
        $knobs = Get-SevKnobs
        $svc = Get-SevService
        Write-SevYaml @"
http:
  routers:
    sev-t4:
      rule: PathPrefix(`/sev-t4`)
      entryPoints: [web]
      middlewares: [sev-t4]
      service: sev-whoami
$svc
  middlewares:
    sev-t4:
      plugin:
        bouncer:
          enabled: "true"
          crowdsecLapiEnabled: "false"
          crowdsecAppsecEnabled: "true"
          crowdsecAppsecHost: crowdsec:7422
          crowdsecAppsecKey: "$script:AppsecKey"
$knobs
"@
        $ip = "172.19.0.54"
        $clean = Wait-SevCodes -Path "/sev-t4" -IP $ip -Codes @(200) -TimeoutSeconds 45
        $clean.Success | Should -BeTrue
        $sqli = Test-HttpRequest -Endpoint "/sev-t4?id=1%27%20OR%20%271%27%3D%271" -IP $ip -TraefikUrl $script:TraefikUrl
        $sqli.StatusCode | Should -Be 403
        Add-TestDecision -IP $ip -Type "ban" -Reason "T4"
        $afterBan = Test-HttpRequest -Endpoint "/sev-t4" -IP $ip -TraefikUrl $script:TraefikUrl
        $afterBan.StatusCode | Should -Be 200 -Because "AppSec-only does not remediate LAPI bans"
    }

    It "T5 per-route bounce knobs" {
        $knobs = Get-SevKnobs
        $svc = Get-SevService
        Write-SevYaml @"
http:
  routers:
    sev-t5-a:
      rule: PathPrefix(`/sev-t5-a`)
      entryPoints: [web]
      middlewares: [sev-t5-owner]
      service: sev-whoami
    sev-t5-b:
      rule: PathPrefix(`/sev-t5-b`)
      entryPoints: [web]
      middlewares: [sev-t5-sub]
      service: sev-whoami
$svc
  middlewares:
    sev-t5-owner:
      plugin:
        bouncer:
          enabled: "true"
          crowdsecMode: stream
          crowdsecLapiEnabled: "true"
          crowdsecLapiInstanceName: shared
          crowdsecLapiKey: "$script:OwnerKey"
          crowdsecLapiHost: crowdsec:8080
          remediationStatusCode: 403
$knobs
    sev-t5-sub:
      plugin:
        bouncer:
          enabled: "true"
          crowdsecLapiInstanceName: shared
          remediationStatusCode: 429
$knobs
"@
        $ip = "172.19.0.55"
        $up = Wait-SevCodes -Path "/sev-t5-a" -IP $ip -Codes @(200) -TimeoutSeconds 45
        $up.Success | Should -BeTrue
        Add-TestDecision -IP $ip -Type "ban" -Reason "T5"
        $a = Wait-SevCodes -Path "/sev-t5-a" -IP $ip -Codes @(403) -TimeoutSeconds 30
        $b = Wait-SevCodes -Path "/sev-t5-b" -IP $ip -Codes @(429) -TimeoutSeconds 30
        $a.Success | Should -BeTrue
        $b.Success | Should -BeTrue
    }
}

Describe "Instance severance late bind" {
    AfterEach {
        if (Test-Path $script:SevFile) {
            Remove-Item -Force $script:SevFile
        }
        Remove-AllTestDecisions
    }

    It "L1 subscriber-only first publish is 503 then 403" {
        $knobs = Get-SevKnobs
        $svc = Get-SevService
        $ip = "172.19.0.61"
        Write-SevYaml @"
http:
  routers:
    sev-l1:
      rule: PathPrefix(`/sev-l1`)
      entryPoints: [web]
      middlewares: [sev-l1]
      service: sev-whoami
$svc
  middlewares:
    sev-l1:
      plugin:
        bouncer:
          enabled: "true"
          streamStartupBlock: "true"
          crowdsecLapiInstanceName: shared
$knobs
"@
        $miss = Wait-SevCodes -Path "/sev-l1" -IP $ip -Codes @(503) -TimeoutSeconds 45
        $miss.Success | Should -BeTrue -Because "L1 before owner is 503"
        (Get-SevLogs) | Should -Match "crowdsec bouncer backend missing"
        Add-TestDecision -IP $ip -Type "ban" -Reason "L1"
        Write-SevYaml @"
http:
  routers:
    sev-l1:
      rule: PathPrefix(`/sev-l1`)
      entryPoints: [web]
      middlewares: [sev-l1]
      service: sev-whoami
    sev-l1-owner:
      rule: PathPrefix(`/sev-l1-owner`)
      entryPoints: [web]
      middlewares: [sev-l1-owner]
      service: sev-whoami
$svc
  middlewares:
    sev-l1:
      plugin:
        bouncer:
          enabled: "true"
          streamStartupBlock: "true"
          crowdsecLapiInstanceName: shared
$knobs
    sev-l1-owner:
      plugin:
        bouncer:
          enabled: false
          crowdsecMode: stream
          crowdsecLapiEnabled: "true"
          crowdsecLapiInstanceName: shared
          crowdsecLapiKey: "$script:OwnerKey"
          crowdsecLapiHost: crowdsec:8080
$knobs
"@
        $hit = Wait-SevCodes -Path "/sev-l1" -IP $ip -Codes @(403, 429) -TimeoutSeconds 45
        $hit.Success | Should -BeTrue -Because "L1 after owner uses the decision"
    }

    It "L1b startup block off uses failure action" {
        $knobs = Get-SevKnobs
        $svc = Get-SevService
        $ip = "172.19.0.62"
        Write-SevYaml @"
http:
  routers:
    sev-l1b-a:
      rule: PathPrefix(`/sev-l1b-a`)
      entryPoints: [web]
      middlewares: [sev-l1b-a]
      service: sev-whoami
    sev-l1b-b:
      rule: PathPrefix(`/sev-l1b-b`)
      entryPoints: [web]
      middlewares: [sev-l1b-b]
      service: sev-whoami
$svc
  middlewares:
    sev-l1b-a:
      plugin:
        bouncer:
          enabled: "true"
          streamStartupBlock: "false"
          crowdsecLapiFailureAction: passthrough
          crowdsecLapiInstanceName: shared
$knobs
    sev-l1b-b:
      plugin:
        bouncer:
          enabled: "true"
          streamStartupBlock: "false"
          crowdsecLapiFailureAction: ban
          crowdsecLapiInstanceName: shared
$knobs
"@
        $pass = Wait-SevCodes -Path "/sev-l1b-a" -IP $ip -Codes @(200) -TimeoutSeconds 45
        $ban = Wait-SevCodes -Path "/sev-l1b-b" -IP $ip -Codes @(403, 429) -TimeoutSeconds 45
        $pass.Success | Should -BeTrue
        $ban.Success | Should -BeTrue
    }

    It "L2 missing name stays 503 or failure action" {
        $knobs = Get-SevKnobs
        $svc = Get-SevService
        $ip = "172.19.0.63"
        Write-SevYaml @"
http:
  routers:
    sev-l2-block:
      rule: PathPrefix(`/sev-l2-block`)
      entryPoints: [web]
      middlewares: [sev-l2-block]
      service: sev-whoami
    sev-l2-fail:
      rule: PathPrefix(`/sev-l2-fail`)
      entryPoints: [web]
      middlewares: [sev-l2-fail]
      service: sev-whoami
$svc
  middlewares:
    sev-l2-block:
      plugin:
        bouncer:
          enabled: "true"
          streamStartupBlock: "true"
          crowdsecLapiInstanceName: missing
$knobs
    sev-l2-fail:
      plugin:
        bouncer:
          enabled: "true"
          streamStartupBlock: "false"
          crowdsecLapiFailureAction: ban
          crowdsecLapiInstanceName: missing
$knobs
"@
        $block = Wait-SevCodes -Path "/sev-l2-block" -IP $ip -Codes @(503) -TimeoutSeconds 45
        $fail = Wait-SevCodes -Path "/sev-l2-fail" -IP $ip -Codes @(403, 429) -TimeoutSeconds 45
        $block.Success | Should -BeTrue
        $fail.Success | Should -BeTrue
    }

    It "L3 two subscribed clients one missing is 503" {
        $knobs = Get-SevKnobs
        $svc = Get-SevService
        $ip = "172.19.0.64"
        Write-SevYaml @"
http:
  routers:
    sev-l3-owner:
      rule: PathPrefix(`/sev-l3-owner`)
      entryPoints: [web]
      middlewares: [sev-l3-owner]
      service: sev-whoami
    sev-l3:
      rule: PathPrefix(`/sev-l3`)
      entryPoints: [web]
      middlewares: [sev-l3]
      service: sev-whoami
$svc
  middlewares:
    sev-l3-owner:
      plugin:
        bouncer:
          enabled: false
          crowdsecMode: stream
          crowdsecLapiEnabled: "true"
          crowdsecLapiInstanceName: shared
          crowdsecLapiKey: "$script:OwnerKey"
          crowdsecLapiHost: crowdsec:8080
$knobs
    sev-l3:
      plugin:
        bouncer:
          enabled: "true"
          streamStartupBlock: "true"
          crowdsecLapiInstanceName: shared
          crowdsecAppsecInstanceName: missing-appsec
$knobs
"@
        Add-TestDecision -IP $ip -Type "ban" -Reason "L3"
        $block = Wait-SevCodes -Path "/sev-l3" -IP $ip -Codes @(503) -TimeoutSeconds 45
        $block.Success | Should -BeTrue
    }

    It "L4 AppSec opener added later" {
        $knobs = Get-SevKnobs
        $svc = Get-SevService
        $ip = "172.19.0.65"
        Write-SevYaml @"
http:
  routers:
    sev-l4:
      rule: PathPrefix(`/sev-l4`)
      entryPoints: [web]
      middlewares: [sev-l4]
      service: sev-whoami
    sev-l4-lapi:
      rule: PathPrefix(`/sev-l4-lapi`)
      entryPoints: [web]
      middlewares: [sev-l4-lapi]
      service: sev-whoami
$svc
  middlewares:
    sev-l4-lapi:
      plugin:
        bouncer:
          enabled: false
          crowdsecMode: stream
          crowdsecLapiEnabled: "true"
          crowdsecLapiInstanceName: shared
          crowdsecLapiKey: "$script:OwnerKey"
          crowdsecLapiHost: crowdsec:8080
$knobs
    sev-l4:
      plugin:
        bouncer:
          enabled: "true"
          streamStartupBlock: "false"
          crowdsecAppsecFailureAction: passthrough
          crowdsecLapiInstanceName: shared
          crowdsecAppsecInstanceName: waf
$knobs
"@
        Add-TestDecision -IP $ip -Type "ban" -Reason "L4"
        $ban = Wait-SevCodes -Path "/sev-l4" -IP $ip -Codes @(403, 429) -TimeoutSeconds 45
        $ban.Success | Should -BeTrue
        $sqli = Test-HttpRequest -Endpoint "/sev-l4?id=1%27%20OR%20%271%27%3D%271" -IP $ip -TraefikUrl $script:TraefikUrl
        $sqli.StatusCode | Should -BeIn @(403, 429) -Because "LAPI ban still applies while AppSec is missing"
    }
}

Describe "Instance severance reclaim and names" {
    AfterEach {
        if (Test-Path $script:SevFile) {
            Remove-Item -Force $script:SevFile
        }
        Remove-AllTestDecisions
    }

    It "R1 same YAML rewrite stays banned" {
        $knobs = Get-SevKnobs
        $svc = Get-SevService
        $ip = "172.19.0.71"
        $yaml = @"
http:
  routers:
    sev-r1:
      rule: PathPrefix(`/sev-r1`)
      entryPoints: [web]
      middlewares: [sev-r1]
      service: sev-whoami
$svc
  middlewares:
    sev-r1:
      plugin:
        bouncer:
          enabled: "true"
          crowdsecMode: stream
          crowdsecLapiEnabled: "true"
          crowdsecLapiInstanceName: shared
          crowdsecLapiKey: "$script:OwnerKey"
          crowdsecLapiHost: crowdsec:8080
$knobs
"@
        Write-SevYaml $yaml
        $up = Wait-SevCodes -Path "/sev-r1" -IP $ip -Codes @(200) -TimeoutSeconds 45
        $up.Success | Should -BeTrue
        Add-TestDecision -IP $ip -Type "ban" -Reason "R1"
        $first = Wait-SevCodes -Path "/sev-r1" -IP $ip -Codes @(403, 429) -TimeoutSeconds 30
        $first.Success | Should -BeTrue
        Write-SevYaml $yaml
        $again = Wait-SevCodes -Path "/sev-r1" -IP $ip -Codes @(403, 429) -TimeoutSeconds 30
        $again.Success | Should -BeTrue
    }

    It "R2 host change publishes a new empty client" {
        $knobs = Get-SevKnobs
        $svc = Get-SevService
        $ip = "172.19.0.72"
        Write-SevYaml @"
http:
  routers:
    sev-r2:
      rule: PathPrefix(`/sev-r2`)
      entryPoints: [web]
      middlewares: [sev-r2]
      service: sev-whoami
    sev-r2-sub:
      rule: PathPrefix(`/sev-r2-sub`)
      entryPoints: [web]
      middlewares: [sev-r2-sub]
      service: sev-whoami
$svc
  middlewares:
    sev-r2:
      plugin:
        bouncer:
          enabled: false
          crowdsecMode: stream
          crowdsecLapiEnabled: "true"
          crowdsecLapiInstanceName: shared
          crowdsecLapiKey: "$script:OwnerKey"
          crowdsecLapiHost: crowdsec:8080
$knobs
    sev-r2-sub:
      plugin:
        bouncer:
          enabled: "true"
          crowdsecLapiFailureAction: passthrough
          crowdsecLapiInstanceName: shared
$knobs
"@
        Add-TestDecision -IP $ip -Type "ban" -Reason "R2"
        $banned = Wait-SevCodes -Path "/sev-r2-sub" -IP $ip -Codes @(403, 429) -TimeoutSeconds 45
        $banned.Success | Should -BeTrue
        Write-SevYaml @"
http:
  routers:
    sev-r2:
      rule: PathPrefix(`/sev-r2`)
      entryPoints: [web]
      middlewares: [sev-r2]
      service: sev-whoami
    sev-r2-sub:
      rule: PathPrefix(`/sev-r2-sub`)
      entryPoints: [web]
      middlewares: [sev-r2-sub]
      service: sev-whoami
$svc
  middlewares:
    sev-r2:
      plugin:
        bouncer:
          enabled: false
          crowdsecMode: stream
          crowdsecLapiEnabled: "true"
          crowdsecLapiInstanceName: shared
          crowdsecLapiKey: "$script:OwnerKey"
          crowdsecLapiHost: crowdsec:9
          httpTimeoutSeconds: "2"
          logLevel: DEBUG
          updateIntervalSeconds: "2"
          forwardedHeadersTrustedIps:
            - "172.16.0.0/12"
            - "172.28.0.1/32"
          forwardedHeadersCustomName: X-Forwarded-For
    sev-r2-sub:
      plugin:
        bouncer:
          enabled: "true"
          crowdsecLapiFailureAction: passthrough
          crowdsecLapiInstanceName: shared
          logLevel: DEBUG
          forwardedHeadersTrustedIps:
            - "172.16.0.0/12"
            - "172.28.0.1/32"
          forwardedHeadersCustomName: X-Forwarded-For
"@
        $pass = Wait-SevCodes -Path "/sev-r2-sub" -IP $ip -Codes @(200) -TimeoutSeconds 45
        $pass.Success | Should -BeTrue -Because "new empty store plus passthrough is 200"
        Start-Sleep -Seconds $script:GraceSeconds
        $still = Test-HttpRequest -Endpoint "/sev-r2-sub" -IP $ip -TraefikUrl $script:TraefikUrl
        $still.StatusCode | Should -Be 200
    }

    It "R3 timeout change keeps the ban and starts a new incarnation" {
        $knobs = Get-SevKnobs
        $svc = Get-SevService
        $ip = "172.19.0.73"
        Write-SevYaml @"
http:
  routers:
    sev-r3:
      rule: PathPrefix(`/sev-r3`)
      entryPoints: [web]
      middlewares: [sev-r3]
      service: sev-whoami
$svc
  middlewares:
    sev-r3:
      plugin:
        bouncer:
          enabled: "true"
          crowdsecMode: stream
          crowdsecLapiEnabled: "true"
          crowdsecLapiInstanceName: shared
          crowdsecLapiKey: "$script:OwnerKey"
          crowdsecLapiHost: crowdsec:8080
          crowdsecLapiHttpTimeoutSeconds: 10
$knobs
"@
        $up = Wait-SevCodes -Path "/sev-r3" -IP $ip -Codes @(200) -TimeoutSeconds 45
        $up.Success | Should -BeTrue
        Add-TestDecision -IP $ip -Type "ban" -Reason "R3"
        $banned = Wait-SevCodes -Path "/sev-r3" -IP $ip -Codes @(403, 429) -TimeoutSeconds 30
        $banned.Success | Should -BeTrue
        $before = Get-SevLogs
        Write-SevYaml @"
http:
  routers:
    sev-r3:
      rule: PathPrefix(`/sev-r3`)
      entryPoints: [web]
      middlewares: [sev-r3]
      service: sev-whoami
$svc
  middlewares:
    sev-r3:
      plugin:
        bouncer:
          enabled: "true"
          crowdsecMode: stream
          crowdsecLapiEnabled: "true"
          crowdsecLapiInstanceName: shared
          crowdsecLapiKey: "$script:OwnerKey"
          crowdsecLapiHost: crowdsec:8080
          crowdsecLapiHttpTimeoutSeconds: 20
$knobs
"@
        $still = Wait-SevCodes -Path "/sev-r3" -IP $ip -Codes @(403, 429) -TimeoutSeconds 30
        $still.Success | Should -BeTrue
        Start-Sleep -Seconds 5
        $after = Get-SevLogs
        $delta = $after.Substring([Math]::Min($before.Length, $after.Length))
        $delta | Should -Match "crowdsec lapi instance started"
        $delta | Should -Match "crowdsec lapi instance sleeping"
    }

    It "R4 N1 slot rename unbinds the old subscriber" {
        $knobs = Get-SevKnobs
        $svc = Get-SevService
        $ip = "172.19.0.74"
        Write-SevYaml @"
http:
  routers:
    sev-r4-owner:
      rule: PathPrefix(`/sev-r4-owner`)
      entryPoints: [web]
      middlewares: [sev-r4-owner]
      service: sev-whoami
    sev-r4-admin:
      rule: PathPrefix(`/sev-r4-admin`)
      entryPoints: [web]
      middlewares: [sev-r4-admin]
      service: sev-whoami
$svc
  middlewares:
    sev-r4-owner:
      plugin:
        bouncer:
          enabled: false
          crowdsecMode: stream
          crowdsecLapiEnabled: "true"
          crowdsecLapiInstanceName: shared
          crowdsecLapiKey: "$script:OwnerKey"
          crowdsecLapiHost: crowdsec:8080
$knobs
    sev-r4-admin:
      plugin:
        bouncer:
          enabled: "true"
          streamStartupBlock: "true"
          crowdsecLapiInstanceName: shared
$knobs
"@
        Add-TestDecision -IP $ip -Type "ban" -Reason "R4"
        $banned = Wait-SevCodes -Path "/sev-r4-admin" -IP $ip -Codes @(403, 429) -TimeoutSeconds 45
        $banned.Success | Should -BeTrue
        $before = Get-SevLogs
        Write-SevYaml @"
http:
  routers:
    sev-r4-owner:
      rule: PathPrefix(`/sev-r4-owner`)
      entryPoints: [web]
      middlewares: [sev-r4-owner]
      service: sev-whoami
    sev-r4-admin:
      rule: PathPrefix(`/sev-r4-admin`)
      entryPoints: [web]
      middlewares: [sev-r4-admin]
      service: sev-whoami
    sev-r4-other:
      rule: PathPrefix(`/sev-r4-other`)
      entryPoints: [web]
      middlewares: [sev-r4-other]
      service: sev-whoami
$svc
  middlewares:
    sev-r4-owner:
      plugin:
        bouncer:
          enabled: false
          crowdsecMode: stream
          crowdsecLapiEnabled: "true"
          crowdsecLapiInstanceName: other
          crowdsecLapiKey: "$script:OwnerKey"
          crowdsecLapiHost: crowdsec:8080
$knobs
    sev-r4-admin:
      plugin:
        bouncer:
          enabled: "true"
          streamStartupBlock: "true"
          crowdsecLapiInstanceName: shared
$knobs
    sev-r4-other:
      plugin:
        bouncer:
          enabled: "true"
          crowdsecLapiInstanceName: other
$knobs
"@
        $admin503 = Wait-SevCodes -Path "/sev-r4-admin" -IP $ip -Codes @(503) -TimeoutSeconds 45
        $other403 = Wait-SevCodes -Path "/sev-r4-other" -IP $ip -Codes @(403, 429) -TimeoutSeconds 45
        $admin503.Success | Should -BeTrue
        $other403.Success | Should -BeTrue
        $after = Get-SevLogs
        $delta = $after.Substring([Math]::Min($before.Length, $after.Length))
        $delta | Should -Match "crowdsec lapi instance sleeping"
        $delta | Should -Match "crowdsec lapi instance waking"
        $delta | Should -Match "crowdsec bouncer unbound"
        $sleepAt = $delta.IndexOf("crowdsec lapi instance sleeping")
        $wakeAt = $delta.IndexOf("crowdsec lapi instance waking")
        $unboundAt = $delta.IndexOf("crowdsec bouncer unbound")
        $wakeAt | Should -BeGreaterThan $sleepAt
        $unboundAt | Should -BeGreaterThan $wakeAt
        $delta | Should -Not -Match "crowdsec lapi instance started"
    }

    It "R5 N2 deleting the opener unbinds after grace" {
        $knobs = Get-SevKnobs
        $svc = Get-SevService
        $ip = "172.19.0.75"
        Write-SevYaml @"
http:
  routers:
    sev-r5-owner:
      rule: PathPrefix(`/sev-r5-owner`)
      entryPoints: [web]
      middlewares: [sev-r5-owner]
      service: sev-whoami
    sev-r5-admin:
      rule: PathPrefix(`/sev-r5-admin`)
      entryPoints: [web]
      middlewares: [sev-r5-admin]
      service: sev-whoami
$svc
  middlewares:
    sev-r5-owner:
      plugin:
        bouncer:
          enabled: false
          crowdsecMode: stream
          crowdsecLapiEnabled: "true"
          crowdsecLapiInstanceName: shared
          crowdsecLapiKey: "$script:OwnerKey"
          crowdsecLapiHost: crowdsec:8080
$knobs
    sev-r5-admin:
      plugin:
        bouncer:
          enabled: "true"
          streamStartupBlock: "true"
          crowdsecLapiInstanceName: shared
$knobs
"@
        Add-TestDecision -IP $ip -Type "ban" -Reason "R5"
        $banned = Wait-SevCodes -Path "/sev-r5-admin" -IP $ip -Codes @(403, 429) -TimeoutSeconds 45
        $banned.Success | Should -BeTrue
        Write-SevYaml @"
http:
  routers:
    sev-r5-admin:
      rule: PathPrefix(`/sev-r5-admin`)
      entryPoints: [web]
      middlewares: [sev-r5-admin]
      service: sev-whoami
$svc
  middlewares:
    sev-r5-admin:
      plugin:
        bouncer:
          enabled: "true"
          streamStartupBlock: "true"
          crowdsecLapiInstanceName: shared
$knobs
"@
        Start-Sleep -Seconds $script:GraceSeconds
        $gone = Wait-SevCodes -Path "/sev-r5-admin" -IP $ip -Codes @(503) -TimeoutSeconds 20
        $gone.Success | Should -BeTrue
        (Get-SevLogs) | Should -Match "crowdsec lapi instance closed"
        (Get-SevLogs) | Should -Match "crowdsec bouncer unbound"
    }

    It "N2 new host and new slot name starts a second incarnation" {
        $knobs = Get-SevKnobs
        $svc = Get-SevService
        $ip = "172.19.0.76"
        Write-SevYaml @"
http:
  routers:
    sev-n2-owner:
      rule: PathPrefix(`/sev-n2-owner`)
      entryPoints: [web]
      middlewares: [sev-n2-owner]
      service: sev-whoami
    sev-n2-admin:
      rule: PathPrefix(`/sev-n2-admin`)
      entryPoints: [web]
      middlewares: [sev-n2-admin]
      service: sev-whoami
$svc
  middlewares:
    sev-n2-owner:
      plugin:
        bouncer:
          enabled: false
          crowdsecMode: stream
          crowdsecLapiEnabled: "true"
          crowdsecLapiInstanceName: shared
          crowdsecLapiKey: "$script:OwnerKey"
          crowdsecLapiHost: crowdsec:8080
$knobs
    sev-n2-admin:
      plugin:
        bouncer:
          enabled: "true"
          streamStartupBlock: "true"
          crowdsecLapiInstanceName: shared
$knobs
"@
        Add-TestDecision -IP $ip -Type "ban" -Reason "N2"
        $banned = Wait-SevCodes -Path "/sev-n2-admin" -IP $ip -Codes @(403, 429) -TimeoutSeconds 45
        $banned.Success | Should -BeTrue
        $before = Get-SevLogs
        Write-SevYaml @"
http:
  routers:
    sev-n2-owner:
      rule: PathPrefix(`/sev-n2-owner`)
      entryPoints: [web]
      middlewares: [sev-n2-owner]
      service: sev-whoami
    sev-n2-admin:
      rule: PathPrefix(`/sev-n2-admin`)
      entryPoints: [web]
      middlewares: [sev-n2-admin]
      service: sev-whoami
    sev-n2-other:
      rule: PathPrefix(`/sev-n2-other`)
      entryPoints: [web]
      middlewares: [sev-n2-other]
      service: sev-whoami
$svc
  middlewares:
    sev-n2-owner:
      plugin:
        bouncer:
          enabled: false
          crowdsecMode: stream
          crowdsecLapiEnabled: "true"
          crowdsecLapiInstanceName: other
          crowdsecLapiKey: "$script:OwnerKey"
          crowdsecLapiHost: crowdsec:9
          httpTimeoutSeconds: "2"
          logLevel: DEBUG
          updateIntervalSeconds: "2"
          forwardedHeadersTrustedIps:
            - "172.16.0.0/12"
            - "172.28.0.1/32"
          forwardedHeadersCustomName: X-Forwarded-For
    sev-n2-admin:
      plugin:
        bouncer:
          enabled: "true"
          streamStartupBlock: "true"
          crowdsecLapiInstanceName: shared
$knobs
    sev-n2-other:
      plugin:
        bouncer:
          enabled: "true"
          crowdsecLapiFailureAction: passthrough
          crowdsecLapiInstanceName: other
$knobs
"@
        Start-Sleep -Seconds 8
        $after = Get-SevLogs
        $delta = $after.Substring([Math]::Min($before.Length, $after.Length))
        $delta | Should -Match "crowdsec lapi instance sleeping"
        $delta | Should -Match "crowdsec lapi instance started"
        $delta | Should -Not -Match "crowdsec lapi instance waking"
        $admin = Test-HttpRequest -Endpoint "/sev-n2-admin" -IP $ip -TraefikUrl $script:TraefikUrl
        $admin.StatusCode | Should -BeIn @(403, 429, 503)
    }
}

Describe "Instance severance collision and config errors" {
    AfterEach {
        if (Test-Path $script:SevFile) {
            Remove-Item -Force $script:SevFile
        }
        Remove-AllTestDecisions
    }

    It "F1 second publisher is rejected" {
        $knobs = Get-SevKnobs
        $svc = Get-SevService
        $ip = "172.19.0.81"
        Write-SevYaml @"
http:
  routers:
    sev-f1-a:
      rule: PathPrefix(`/sev-f1-a`)
      entryPoints: [web]
      middlewares: [sev-f1-a]
      service: sev-whoami
    sev-f1-b:
      rule: PathPrefix(`/sev-f1-b`)
      entryPoints: [web]
      middlewares: [sev-f1-b]
      service: sev-whoami
    sev-f1-sub:
      rule: PathPrefix(`/sev-f1-sub`)
      entryPoints: [web]
      middlewares: [sev-f1-sub]
      service: sev-whoami
$svc
  middlewares:
    sev-f1-a:
      plugin:
        bouncer:
          enabled: false
          crowdsecMode: stream
          crowdsecLapiEnabled: "true"
          crowdsecLapiInstanceName: shared
          crowdsecLapiKey: "$script:OwnerKey"
          crowdsecLapiHost: crowdsec:8080
$knobs
    sev-f1-b:
      plugin:
        bouncer:
          enabled: false
          crowdsecMode: stream
          crowdsecLapiEnabled: "true"
          crowdsecLapiInstanceName: shared
          crowdsecLapiKey: "$script:KeyB"
          crowdsecLapiHost: crowdsec:8080
$knobs
    sev-f1-sub:
      plugin:
        bouncer:
          enabled: "true"
          crowdsecLapiInstanceName: shared
$knobs
"@
        Add-TestDecision -IP $ip -Type "ban" -Reason "F1"
        $sub = Wait-SevCodes -Path "/sev-f1-sub" -IP $ip -Codes @(403, 429) -TimeoutSeconds 45
        $sub.Success | Should -BeTrue
        $logs = Get-SevLogs
        $logs | Should -Match "crowdsec instance name taken"
        $logs | Should -Not -Match $script:OwnerKey
        $logs | Should -Not -Match $script:KeyB
        $b = Test-HttpRequest -Endpoint "/sev-f1-b" -IP $ip -TraefikUrl $script:TraefikUrl
        $b.StatusCode | Should -Not -Be 403
    }

    It "F2 AppSec name taken rolls back the free LAPI name" {
        $knobs = Get-SevKnobs
        $svc = Get-SevService
        $ip = "172.19.0.82"
        Write-SevYaml @"
http:
  routers:
    sev-f2-waf:
      rule: PathPrefix(`/sev-f2-waf`)
      entryPoints: [web]
      middlewares: [sev-f2-waf]
      service: sev-whoami
    sev-f2-cs:
      rule: PathPrefix(`/sev-f2-cs`)
      entryPoints: [web]
      middlewares: [sev-f2-cs]
      service: sev-whoami
    sev-f2-sub:
      rule: PathPrefix(`/sev-f2-sub`)
      entryPoints: [web]
      middlewares: [sev-f2-sub]
      service: sev-whoami
$svc
  middlewares:
    sev-f2-waf:
      plugin:
        bouncer:
          enabled: false
          crowdsecAppsecEnabled: "true"
          crowdsecAppsecInstanceName: waf
          crowdsecAppsecHost: crowdsec:7422
          crowdsecAppsecKey: "$script:AppsecKey"
$knobs
    sev-f2-cs:
      plugin:
        bouncer:
          enabled: false
          crowdsecMode: stream
          crowdsecLapiEnabled: "true"
          crowdsecAppsecEnabled: "true"
          crowdsecLapiInstanceName: api
          crowdsecAppsecInstanceName: waf
          crowdsecLapiKey: "$script:OwnerKey"
          crowdsecLapiHost: crowdsec:8080
          crowdsecAppsecHost: crowdsec:7422
          crowdsecAppsecKey: "$script:KeyB"
$knobs
    sev-f2-sub:
      plugin:
        bouncer:
          enabled: "true"
          streamStartupBlock: "true"
          crowdsecLapiInstanceName: api
$knobs
"@
        Start-Sleep -Seconds 5
        $logs = Get-SevLogs
        $logs | Should -Match "crowdsec instance name taken"
        $logs | Should -Match "leg=appsec"
        $cs = Test-HttpRequest -Endpoint "/sev-f2-cs" -IP $ip -TraefikUrl $script:TraefikUrl
        $cs.StatusCode | Should -Be 404
        $sub = Wait-SevCodes -Path "/sev-f2-sub" -IP $ip -Codes @(503) -TimeoutSeconds 20
        $sub.Success | Should -BeTrue
    }

    It "F3 subscribe-only with names and no keys binds" {
        $knobs = Get-SevKnobs
        $svc = Get-SevService
        $ip = "172.19.0.83"
        Write-SevYaml @"
http:
  routers:
    sev-f3-owner:
      rule: PathPrefix(`/sev-f3-owner`)
      entryPoints: [web]
      middlewares: [sev-f3-owner]
      service: sev-whoami
    sev-f3-admin:
      rule: PathPrefix(`/sev-f3-admin`)
      entryPoints: [web]
      middlewares: [sev-f3-admin]
      service: sev-whoami
$svc
  middlewares:
    sev-f3-owner:
      plugin:
        bouncer:
          enabled: "true"
          crowdsecMode: stream
          crowdsecLapiEnabled: "true"
          crowdsecAppsecEnabled: "true"
          crowdsecLapiInstanceName: shared
          crowdsecAppsecInstanceName: shared
          crowdsecLapiKey: "$script:OwnerKey"
          crowdsecLapiHost: crowdsec:8080
          crowdsecAppsecHost: crowdsec:7422
$knobs
    sev-f3-admin:
      plugin:
        bouncer:
          enabled: "true"
          crowdsecLapiInstanceName: shared
          crowdsecAppsecInstanceName: shared
$knobs
"@
        Add-TestDecision -IP $ip -Type "ban" -Reason "F3"
        $admin = Wait-SevCodes -Path "/sev-f3-admin" -IP $ip -Codes @(403, 429) -TimeoutSeconds 45
        $admin.Success | Should -BeTrue
        (Get-SevLogs) | Should -Not -Match "crowdsec instance name taken"
    }

    It "C1 colliding stream owners both answer" {
        $knobs = Get-SevKnobs
        $svc = Get-SevService
        $ip = "172.19.0.84"
        Write-SevYaml @"
http:
  routers:
    sev-c1-a:
      rule: PathPrefix(`/sev-c1-a`)
      entryPoints: [web]
      middlewares: [sev-c1-a]
      service: sev-whoami
    sev-c1-b:
      rule: PathPrefix(`/sev-c1-b`)
      entryPoints: [web]
      middlewares: [sev-c1-b]
      service: sev-whoami
$svc
  middlewares:
    sev-c1-a:
      plugin:
        bouncer:
          enabled: "true"
          crowdsecMode: stream
          crowdsecLapiEnabled: "true"
          crowdsecLapiKey: "$script:OwnerKey"
          crowdsecLapiHost: crowdsec:8080
$knobs
    sev-c1-b:
      plugin:
        bouncer:
          enabled: "true"
          crowdsecMode: stream
          crowdsecLapiEnabled: "true"
          crowdsecLapiKey: "$script:OwnerKey"
          crowdsecLapiHost: crowdsec:8080
$knobs
"@
        $a = Wait-SevCodes -Path "/sev-c1-a" -IP $ip -Codes @(200) -TimeoutSeconds 45
        $b = Wait-SevCodes -Path "/sev-c1-b" -IP $ip -Codes @(200) -TimeoutSeconds 45
        $a.Success | Should -BeTrue
        $b.Success | Should -BeTrue
        $logs = Get-SevLogs
        $logs | Should -Match "crowdsec lapi stream collision"
        $logs | Should -Not -Match $script:OwnerKey
    }

    It "E2 leftover instance name with bounce off fails New" {
        $knobs = Get-SevKnobs
        $svc = Get-SevService
        $ip = "172.19.0.85"
        Write-SevYaml @"
http:
  routers:
    sev-e2-good:
      rule: PathPrefix(`/sev-e2-good`)
      entryPoints: [web]
      middlewares: [sev-e2-good]
      service: sev-whoami
    sev-e2-bad:
      rule: PathPrefix(`/sev-e2-bad`)
      entryPoints: [web]
      middlewares: [sev-e2-bad]
      service: sev-whoami
$svc
  middlewares:
    sev-e2-good:
      plugin:
        bouncer:
          enabled: "true"
          crowdsecMode: none
          crowdsecLapiEnabled: "true"
          crowdsecLapiKey: "$script:OwnerKey"
          crowdsecLapiHost: crowdsec:8080
$knobs
    sev-e2-bad:
      plugin:
        bouncer:
          enabled: false
          crowdsecLapiInstanceName: shared
$knobs
"@
        $good = Wait-SevCodes -Path "/sev-e2-good" -IP $ip -Codes @(200) -TimeoutSeconds 45
        $good.Success | Should -BeTrue
        Start-Sleep -Seconds 3
        $bad = Test-HttpRequest -Endpoint "/sev-e2-bad" -IP $ip -TraefikUrl $script:TraefikUrl
        $bad.StatusCode | Should -Be 404
    }

    It "E3 bounce with omitted LAPI name does not subscribe" {
        $knobs = Get-SevKnobs
        $svc = Get-SevService
        $ip = "172.19.0.86"
        Write-SevYaml @"
http:
  routers:
    sev-e3:
      rule: PathPrefix(`/sev-e3`)
      entryPoints: [web]
      middlewares: [sev-e3]
      service: sev-whoami
$svc
  middlewares:
    sev-e3:
      plugin:
        bouncer:
          enabled: "true"
          crowdsecLapiEnabled: "false"
$knobs
"@
        $ok = Wait-SevCodes -Path "/sev-e3" -IP $ip -Codes @(200) -TimeoutSeconds 45
        $ok.Success | Should -BeTrue
        Add-TestDecision -IP $ip -Type "ban" -Reason "E3"
        $still = Test-HttpRequest -Endpoint "/sev-e3" -IP $ip -TraefikUrl $script:TraefikUrl
        $still.StatusCode | Should -Be 200
        (Get-SevLogs) | Should -Not -Match "crowdsec bouncer backend missing"
    }

    It "E4 crowdsecMode appsec fails New" {
        $knobs = Get-SevKnobs
        $svc = Get-SevService
        $ip = "172.19.0.87"
        Write-SevYaml @"
http:
  routers:
    sev-e4:
      rule: PathPrefix(`/sev-e4`)
      entryPoints: [web]
      middlewares: [sev-e4]
      service: sev-whoami
$svc
  middlewares:
    sev-e4:
      plugin:
        bouncer:
          enabled: "true"
          crowdsecMode: appsec
          crowdsecAppsecEnabled: "true"
          crowdsecAppsecHost: crowdsec:7422
          crowdsecAppsecKey: "$script:AppsecKey"
$knobs
"@
        Start-Sleep -Seconds 4
        $resp = Test-HttpRequest -Endpoint "/sev-e4" -IP $ip -TraefikUrl $script:TraefikUrl
        $resp.StatusCode | Should -Be 404
    }
}
