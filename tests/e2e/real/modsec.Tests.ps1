#!/usr/bin/env pwsh

# ModSec leg alone (dynamic/modsec.yml): inspect-only Apache CRS sidecar waf-modsec-test.
# A CRS block is proven twice: the client sees ban:modsec, and the sidecar error log names the
# rule for a URI only this test sent. Client identity is X-Forwarded-For only.

BeforeAll {
    . "$PSScriptRoot/TestUtils.ps1"

    $script:TraefikUrl = "http://localhost:8000"
    $script:ClientIP = "172.19.0.50"
    $script:Sidecar = "waf-modsec-test"
    $script:Header = "X-Crowdsec-Remediation"

    $result = Wait-ForCondition -Description "ModSec allow route" -TimeoutSeconds 90 -RetryIntervalSeconds 3 -Condition {
        $response = Test-HttpRequest -Endpoint "/modsec-allow" -IP $script:ClientIP -TraefikUrl $script:TraefikUrl
        return ($response.StatusCode -eq 200)
    }
    if (-not $result.Success) {
        throw "ModSec allow route failed to become ready"
    }

    # CRS rule ids the sidecar logged for one URI.
    function script:Get-CrsRuleIds {
        param([string]$Since, [string]$Uri)
        $lines = Get-ContainerLogLines -Container $script:Sidecar -Since $Since -Contains @("[uri `"$Uri`"]")
        return @($lines | ForEach-Object { [regex]::Matches($_, '\[id "(\d+)"\]') | ForEach-Object { $_.Groups[1].Value } } | Sort-Object -Unique)
    }
}

Describe "CrowdSec Bouncer ModSec CRS sidecar" {
    Context "Inspect-only Apache CRS" -Tag "modsec" {
        It "Should allow a benign request without a remediation header" {
            $response = Test-HttpRequest -Endpoint "/modsec-allow" -IP $script:ClientIP -TraefikUrl $script:TraefikUrl
            $response.StatusCode | Should -Be 200
            $response.Content | Should -Match "Hostname:"
            Get-ResponseHeader $response $script:Header | Should -BeNullOrEmpty
        }

        It "Should relay the CRS 403 for a path traversal and log the rule on the sidecar" {
            $since = Get-LogSince
            $uri = "/modsec-crs/lfi-$(Get-Random)"
            $response = Test-HttpRequest -Endpoint "$($uri)?test=../etc" -IP $script:ClientIP -TraefikUrl $script:TraefikUrl
            $response.StatusCode | Should -Be 403
            Get-ResponseHeader $response $script:Header | Should -Be "ban:modsec"
            $response.Content | Should -Match "Forbidden" -Because "the visitor gets the page ModSecurity produced"
            $response.Content | Should -Not -Match "Hostname:" -Because "the origin must not be called"

            $wait = Wait-ForCondition -Description "CRS rule 930110 in the sidecar log" -TimeoutSeconds 10 -Silent -Condition {
                $script:Rules = Get-CrsRuleIds -Since $since -Uri $uri
                return ($script:Rules -contains "930110")
            }
            $wait.Success | Should -Be $true -Because "rule ids logged: $($script:Rules -join ',')"
        }

        It "Should send a GET body to CRS, which blocks it with rule 920170" {
            # The plugin has no method list of its own: CRS decides what a GET with a body means.
            $since = Get-LogSince
            $uri = "/modsec-allow/get-body-$(Get-Random)"
            $response = Test-HttpRequest -Endpoint $uri -IP $script:ClientIP -TraefikUrl $script:TraefikUrl `
                -Method GET -Body "x" -ExtraHeaders @{ "Content-Type" = "text/plain" }
            $response.StatusCode | Should -Be 403
            Get-ResponseHeader $response $script:Header | Should -Be "ban:modsec"
            $wait = Wait-ForCondition -Description "CRS rule 920170 in the sidecar log" -TimeoutSeconds 10 -Silent -Condition {
                $script:Rules = Get-CrsRuleIds -Since $since -Uri $uri
                return ($script:Rules -contains "920170")
            }
            $wait.Success | Should -Be $true -Because "rule ids logged: $($script:Rules -join ',')"
        }

        It "Should let an OPTIONS request with a clean body through" {
            $response = Test-HttpRequest -Endpoint "/modsec-allow/options-body" -IP $script:ClientIP -TraefikUrl $script:TraefikUrl `
                -Method OPTIONS -Body '{"probe":1}' -ExtraHeaders @{ "Content-Type" = "application/json" }
            $response.StatusCode | Should -Be 200 -Because "only CRS judges a body; the plugin does not reject by method"
        }

        It "Should block an XSS payload in a POST body" {
            $since = Get-LogSince
            $uri = "/modsec-allow/xss-body-$(Get-Random)"
            $response = Test-HttpRequest -Endpoint $uri -IP $script:ClientIP -TraefikUrl $script:TraefikUrl `
                -Method POST -Body "q=%3Cscript%3Ealert(1)%3C%2Fscript%3E" `
                -ExtraHeaders @{ "Content-Type" = "application/x-www-form-urlencoded" }
            $response.StatusCode | Should -Be 403
            Get-ResponseHeader $response $script:Header | Should -Be "ban:modsec"
            $wait = Wait-ForCondition -Description "CRS XSS rule in the sidecar log" -TimeoutSeconds 10 -Silent -Condition {
                $script:Rules = Get-CrsRuleIds -Since $since -Uri $uri
                return (@($script:Rules | Where-Object { $_ -like "941*" }).Count -gt 0)
            }
            $wait.Success | Should -Be $true -Because "the body must reach CRS; rule ids logged: $($script:Rules -join ',')"
        }

        It "Should hand the origin the same body the sidecar inspected" {
            $marker = "body-marker-$(Get-Random)"
            $response = Test-HttpRequest -Endpoint "/modsec-ws/echo" -IP $script:ClientIP -TraefikUrl $script:TraefikUrl `
                -Method POST -Body "payload=$marker" -ExtraHeaders @{ "Content-Type" = "application/x-www-form-urlencoded" }
            $response.StatusCode | Should -Be 200
            $response.Content | Should -Match $marker -Because "the buffered body must be replayed to the origin"
        }

        It "Should return 413 without calling the sidecar when the body exceeds modsecBodyLimit" {
            $since = Get-LogSince
            $uri = "/modsec-body/too-large-$(Get-Random)"
            # The body carries a CRS payload: if it reached the sidecar, the sidecar would log a rule.
            $body = "q=%3Cscript%3Ealert(1)%3C%2Fscript%3E&pad=" + ("a" * 2048)
            $response = Test-HttpRequest -Endpoint $uri -IP $script:ClientIP -TraefikUrl $script:TraefikUrl `
                -Method POST -Body $body -ExtraHeaders @{ "Content-Type" = "application/x-www-form-urlencoded" }
            $response.StatusCode | Should -Be 413
            Start-Sleep -Seconds 1
            Get-CrsRuleIds -Since $since -Uri $uri | Should -BeNullOrEmpty -Because "an oversize body is rejected before the sidecar"
        }
    }

    Context "bouncerModsecFailureAction when the sidecar is unreachable" -Tag "modsec" {
        It "Should continue to the origin with passthrough (the default)" {
            $response = Test-HttpRequest -Endpoint "/modsec-fail-pass" -IP $script:ClientIP -TraefikUrl $script:TraefikUrl
            $response.StatusCode | Should -Be 200
            $response.Content | Should -Match "Hostname:"
            Get-ResponseHeader $response $script:Header | Should -BeNullOrEmpty
        }

        It "Should serve the ban page with ban" {
            $response = Test-HttpRequest -Endpoint "/modsec-fail-ban" -IP $script:ClientIP -TraefikUrl $script:TraefikUrl
            $response.StatusCode | Should -Be 403
            Get-ResponseHeader $response $script:Header | Should -Be "ban:modsec-failure"
            $response.Content | Should -Match "E2E_CUSTOM_BAN_PAGE_MARKER"
            $response.Content | Should -Match "reason: MODSEC"
        }

        It "Should serve the captcha page with captcha" {
            $response = Test-HttpRequest -Endpoint "/modsec-fail-captcha" -IP $script:ClientIP -TraefikUrl $script:TraefikUrl
            $response.StatusCode | Should -Be 200
            Get-ResponseHeader $response $script:Header | Should -Be "captcha:modsec-failure"
            $response.Content | Should -Match "E2E captcha challenge"
        }
    }

    Context "WebSocket through the ModSec leg" -Tag "modsec" {
        It "Should echo two WebSocket frames after the handshake is inspected" {
            $first = "ws-echo-a-$(Get-Random)"
            $second = "ws-echo-b-$(Get-Random)"
            $echoed = Invoke-WebSocketEcho -Uri "ws://localhost:8000/modsec-ws" -Message @($first, $second)
            $echoed | Should -Be @($first, $second) -Because "inspecting the handshake GET must leave a working tunnel, not a 101-only upgrade"
        }

        It "Should block a WebSocket handshake that carries a CRS payload" {
            $response = Test-HttpRequest -Endpoint "/modsec-ws?test=../etc" -IP $script:ClientIP -TraefikUrl $script:TraefikUrl `
                -MaximumRedirection 0 -ExtraHeaders @{
                    "Upgrade"               = "websocket"
                    "Connection"            = "Upgrade"
                    "Sec-WebSocket-Key"     = "dGhlIHNhbXBsZSBub25jZQ=="
                    "Sec-WebSocket-Version" = "13"
                }
            $response.StatusCode | Should -Be 403 -Because "Upgrade headers must not skip CRS"
        }

        It "Should inspect a forged Upgrade header without a Connection upgrade token" {
            $response = Test-HttpRequest -Endpoint "/modsec-crs/?test=../etc" -IP $script:ClientIP -TraefikUrl $script:TraefikUrl `
                -MaximumRedirection 0 -ExtraHeaders @{ "Upgrade" = "websocket" }
            $response.StatusCode | Should -Be 403 -Because "a lone Upgrade header must still be CRS-inspected"
        }
    }

    Context "bypassModsec action rule" -Tag "modsec" {
        It "Should skip the sidecar only on the matching path" {
            $skipped = Test-HttpRequest -Endpoint "/modsec-skip/ok?test=../etc" -IP $script:ClientIP -TraefikUrl $script:TraefikUrl
            $skipped.StatusCode | Should -Be 200
            $blocked = Test-HttpRequest -Endpoint "/modsec-skip/hit?test=../etc" -IP $script:ClientIP -TraefikUrl $script:TraefikUrl
            $blocked.StatusCode | Should -Be 403
            Get-ResponseHeader $blocked $script:Header | Should -Be "ban:modsec"
        }
    }

    # HTTP/2 (h2c) bodies without Content-Length: read and inspected like any other, under
    # modsecBodyReadTimeoutSeconds (upstream issue maxlerebourg/crowdsec-bouncer-traefik-plugin#405).
    Context "Bodies without Content-Length over HTTP/2" -Tag "modsec" {
        It "Should let the restic init shape through: an empty POST without Content-Length" {
            $response = Invoke-H2cUnknownLengthRequest -Endpoint "/modsec-allow/restic-repo/?create=true" -IP $script:ClientIP -TraefikUrl $script:TraefikUrl
            $response.StatusCode | Should -Be 200 -Because "an empty body of unknown length is inspected and allowed, not dropped"
            $response.Content | Should -Match "Hostname:"
            Get-ResponseHeader $response $script:Header | Should -BeNullOrEmpty
        }

        It "Should send a body without Content-Length to CRS, which blocks the XSS payload" {
            $since = Get-LogSince
            $uri = "/modsec-allow/xss-no-length-$(Get-Random)"
            $response = Invoke-H2cUnknownLengthRequest -Endpoint $uri -IP $script:ClientIP -TraefikUrl $script:TraefikUrl `
                -BodyText "q=%3Cscript%3Ealert(1)%3C%2Fscript%3E" -ContentType "application/x-www-form-urlencoded"
            $response.StatusCode | Should -Be 403 -Because "leaving out Content-Length must not skip CRS"
            Get-ResponseHeader $response $script:Header | Should -Be "ban:modsec"
            $wait = Wait-ForCondition -Description "CRS XSS rule in the sidecar log" -TimeoutSeconds 10 -Silent -Condition {
                $script:Rules = Get-CrsRuleIds -Since $since -Uri $uri
                return (@($script:Rules | Where-Object { $_ -like "941*" }).Count -gt 0)
            }
            $wait.Success | Should -Be $true -Because "the body must reach CRS; rule ids logged: $($script:Rules -join ',')"
        }

        It "Should answer 400 error:body-read-timeout at the deadline for a body that stalls" {
            $response = Invoke-H2cUnknownLengthRequest -Endpoint "/modsec-stall/upload" -IP $script:ClientIP -TraefikUrl $script:TraefikUrl `
                -BodyText "x" -ContentType "application/octet-stream" -StallSeconds 8
            $response.StatusCode | Should -Be 400 -Because "modsecBodyReadTimeoutSeconds blocks whatever bouncerModsecFailureAction says"
            Get-ResponseHeader $response $script:Header | Should -Be "error:body-read-timeout"
            $response.Content | Should -Not -Match "Hostname:" -Because "the origin must not be called"
            $response.ElapsedMs | Should -BeLessThan 6000 -Because "the plugin cuts the read at the 2 s deadline, before the body ends at 8 s"
        }
    }
}
