#!/usr/bin/env pwsh

# AppSec and ModSec on one router (dynamic/waf-dual.yml).
# AppSec is listener 7424: no CRS, drops any path containing "appsec-drop" (ban:appsec).
# ModSec is the CRS sidecar waf-modsec-test (ban:modsec). The origin echo-ws echoes the request.
# Order on the request path: LAPI -> AppSec -> ModSec -> origin. "The sidecar was not called" is
# proven by a CRS payload carrying a unique marker: CRS logs a rule for any request it sees.

BeforeAll {
    . "$PSScriptRoot/TestUtils.ps1"

    $script:TraefikUrl = "http://localhost:8000"
    $script:ClientIP = "172.19.0.60"
    $script:Sidecar = "waf-modsec-test"
    $script:Header = "X-Crowdsec-Remediation"

    $result = Wait-ForCondition -Description "dual AppSec + ModSec route" -TimeoutSeconds 120 -RetryIntervalSeconds 3 -Condition {
        $clean = Test-HttpRequest -Endpoint "/dual/ready" -IP $script:ClientIP -TraefikUrl $script:TraefikUrl
        $drop = Test-HttpRequest -Endpoint "/dual/appsec-drop" -IP $script:ClientIP -TraefikUrl $script:TraefikUrl
        return ($clean.StatusCode -eq 200 -and (Get-ResponseHeader $drop $script:Header) -eq "ban:appsec")
    }
    if (-not $result.Success) {
        throw "dual route (AppSec listener 7424 + CRS sidecar) failed to become ready"
    }

    # True once the CRS sidecar logged any line for a request whose URI contains $Marker.
    function script:Test-SidecarSaw {
        param([string]$Since, [string]$Marker)
        return (Get-ContainerLogLines -Container $script:Sidecar -Since $Since -Contains @($Marker)).Count -gt 0
    }
}

Describe "AppSec and ModSec on the same router" {
    Context "Verdicts and order" -Tag "modsec" {
        It "Should pass a clean request through both legs to the origin" {
            $response = Test-HttpRequest -Endpoint "/dual/clean" -IP $script:ClientIP -TraefikUrl $script:TraefikUrl
            $response.StatusCode | Should -Be 200
            $response.Content | Should -Match "GET /dual/clean"
            Get-ResponseHeader $response $script:Header | Should -BeNullOrEmpty
        }

        It "Should let ModSec block what AppSec allows" {
            $since = Get-LogSince
            $marker = "dual-modsec-$(Get-Random)"
            $response = Test-HttpRequest -Endpoint "/dual/$($marker)?test=../etc" -IP $script:ClientIP -TraefikUrl $script:TraefikUrl
            $response.StatusCode | Should -Be 403
            Get-ResponseHeader $response $script:Header | Should -Be "ban:modsec"
            (Wait-ForCondition -Description "sidecar log for $marker" -TimeoutSeconds 10 -Silent -Condition {
                Test-SidecarSaw -Since $since -Marker $marker
            }).Success | Should -Be $true
        }

        It "Should stop at an AppSec block without calling the sidecar" {
            # Positive control first: the same CRS payload on a path AppSec allows is logged by the sidecar.
            $since = Get-LogSince
            $control = "dual-control-$(Get-Random)"
            (Test-HttpRequest -Endpoint "/dual/$($control)?test=../etc" -IP $script:ClientIP -TraefikUrl $script:TraefikUrl).StatusCode | Should -Be 403
            (Wait-ForCondition -Description "sidecar log for $control" -TimeoutSeconds 10 -Silent -Condition {
                Test-SidecarSaw -Since $since -Marker $control
            }).Success | Should -Be $true -Because "the marker check must be able to see a sidecar call"

            $marker = "dual-appsec-$(Get-Random)"
            $response = Test-HttpRequest -Endpoint "/dual/appsec-drop/$($marker)?test=../etc" -IP $script:ClientIP -TraefikUrl $script:TraefikUrl
            $response.StatusCode | Should -Be 403
            Get-ResponseHeader $response $script:Header | Should -Be "ban:appsec" -Because "AppSec runs before ModSec and its verdict is final"
            Start-Sleep -Seconds 2
            Test-SidecarSaw -Since $since -Marker $marker | Should -Be $false -Because "a request AppSec blocked must never reach the sidecar"
        }

        It "Should skip only AppSec with bypassAppsec" {
            $appsecOnly = Test-HttpRequest -Endpoint "/dual/no-appsec/appsec-drop" -IP $script:ClientIP -TraefikUrl $script:TraefikUrl
            $appsecOnly.StatusCode | Should -Be 200 -Because "the AppSec drop path is not checked under bypassAppsec"
            $crs = Test-HttpRequest -Endpoint "/dual/no-appsec/x?test=../etc" -IP $script:ClientIP -TraefikUrl $script:TraefikUrl
            $crs.StatusCode | Should -Be 403
            Get-ResponseHeader $crs $script:Header | Should -Be "ban:modsec" -Because "ModSec still runs under bypassAppsec"
        }

        It "Should skip only ModSec with bypassModsec" {
            $crs = Test-HttpRequest -Endpoint "/dual/no-modsec/x?test=../etc" -IP $script:ClientIP -TraefikUrl $script:TraefikUrl
            $crs.StatusCode | Should -Be 200 -Because "listener 7424 has no CRS, and ModSec is bypassed"
            $drop = Test-HttpRequest -Endpoint "/dual/no-modsec/appsec-drop" -IP $script:ClientIP -TraefikUrl $script:TraefikUrl
            $drop.StatusCode | Should -Be 403
            Get-ResponseHeader $drop $script:Header | Should -Be "ban:appsec" -Because "AppSec still runs under bypassModsec"
        }
    }

    Context "Request body shared by both legs" -Tag "modsec" {
        It "Should give ModSec the body AppSec already read" {
            $since = Get-LogSince
            $marker = "dual-body-$(Get-Random)"
            $response = Test-HttpRequest -Endpoint "/dual/$marker" -IP $script:ClientIP -TraefikUrl $script:TraefikUrl `
                -Method POST -Body "q=%3Cscript%3Ealert(1)%3C%2Fscript%3E" `
                -ExtraHeaders @{ "Content-Type" = "application/x-www-form-urlencoded" }
            $response.StatusCode | Should -Be 403
            Get-ResponseHeader $response $script:Header | Should -Be "ban:modsec" -Because "the XSS is only in the body, so the sidecar got the body after AppSec"
            (Wait-ForCondition -Description "CRS XSS rule for $marker" -TimeoutSeconds 10 -Silent -Condition {
                $lines = Get-ContainerLogLines -Container $script:Sidecar -Since $since -Contains @($marker, 'attack-xss')
                return $lines.Count -gt 0
            }).Success | Should -Be $true
        }

        It "Should give the origin the body both legs read" {
            $marker = "dual-origin-body-$(Get-Random)"
            $response = Test-HttpRequest -Endpoint "/dual/echo" -IP $script:ClientIP -TraefikUrl $script:TraefikUrl `
                -Method POST -Body "payload=$marker" -ExtraHeaders @{ "Content-Type" = "application/x-www-form-urlencoded" }
            $response.StatusCode | Should -Be 200
            $response.Content | Should -Match $marker -Because "the buffered body must be replayed to the origin after AppSec and ModSec"
        }
    }
}
