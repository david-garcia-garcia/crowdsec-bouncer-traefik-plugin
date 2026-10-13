#!/usr/bin/env pwsh

# Action rules against the live LAPI. A matching ban does not need a CrowdSec decision.
# bypassLapi lets a banned IP through. The prefix itself still consults LAPI.

BeforeAll {
    . "$PSScriptRoot/TestUtils.ps1"

    $script:TraefikUrl = "http://localhost:8000"
    $script:TestIP = "203.0.113.80"

    $ready = Wait-ForCondition -Description "action-rules route" -TimeoutSeconds 60 -RetryIntervalSeconds 2 -Condition {
        try {
            $response = Invoke-WebRequest -Uri "http://localhost:8000/action-rules" -Headers @{ "X-Forwarded-For" = $script:TestIP } -TimeoutSec 3 -UseBasicParsing
            return ($response.StatusCode -eq 200)
        }
        catch {
            return $false
        }
    }
    if (-not $ready.Success) {
        throw "action-rules route did not become ready"
    }
}

Describe "Action rules" {
    AfterEach {
        Remove-TestDecision -IP $script:TestIP
    }

    It "Should ban on a matching path and skip LAPI on the bypass path" {
        $open = Test-HttpRequest -Endpoint "/action-rules" -IP $script:TestIP -TraefikUrl $script:TraefikUrl
        $open.StatusCode | Should -Be 200 -Because "a path with no matching action rule and no decision reaches origin"

        $forced = Test-HttpRequest -Endpoint "/action-rules/ban" -IP $script:TestIP -TraefikUrl $script:TraefikUrl
        $forced.StatusCode | Should -BeIn @(403, 429) -Because "the ban action rule remediates without a CrowdSec decision"

        Add-TestDecision -IP $script:TestIP -Type "ban" -Reason "action rule skip"

        $lookedUp = Test-HttpRequest -Endpoint "/action-rules" -IP $script:TestIP -TraefikUrl $script:TraefikUrl
        $lookedUp.StatusCode | Should -BeIn @(403, 429) -Because "the same IP is banned when no action rule skips LAPI"

        $skipped = Test-HttpRequest -Endpoint "/action-rules/skip" -IP $script:TestIP -TraefikUrl $script:TraefikUrl
        $skipped.StatusCode | Should -Be 200 -Because "bypassLapi must not consult the ban decision"
    }
}
