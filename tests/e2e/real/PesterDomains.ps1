# CI partition of tests/e2e/real/*.Tests.ps1.
# lapi: request decisions from LAPI (stream and live modes, ban, scopes, trusted IPs, metrics).
# appsec: AppSec, captcha, and the Redis decision cache.
# lifecycle: instance severance (late bind, reclaim, name collisions).
# Local `make e2e_pester` still runs every file. Each CI job runs one domain.

$script:PesterDomainFiles = @{
    lapi   = @(
        'simple-bouncer.Tests.ps1'
        'mode_none.Tests.ps1'
        'mode_live.Tests.ps1'
        'mode_stream.Tests.ps1'
        'trusted_ips.Tests.ps1'
        'custom_ban_page.Tests.ps1'
        'decision_scopes.Tests.ps1'
        'header_scopes.Tests.ps1'
        'failure_action.Tests.ps1'
        'usage_metrics.Tests.ps1'
    )
    appsec = @(
        'appsec.Tests.ps1'
        'captcha.Tests.ps1'
        'redis_cache.Tests.ps1'
    )
    lifecycle = @(
        'instance_severance.Tests.ps1'
    )
}

# Paths for one domain, relative to this folder's parent layout (absolute).
function Get-PesterDomainPaths {
    param([Parameter(Mandatory)][string]$Domain)
    $names = $script:PesterDomainFiles[$Domain]
    if (-not $names) {
        throw "Unknown Pester domain '$Domain'. Known: $($script:PesterDomainFiles.Keys -join ', ')"
    }
    foreach ($name in $names) {
        Join-Path $PSScriptRoot $name
    }
}

# Fail when a *.Tests.ps1 is missing from the partition or listed twice.
function Assert-PesterDomainPartition {
    $onDisk = @(Get-ChildItem -Path (Join-Path $PSScriptRoot '*.Tests.ps1') | ForEach-Object Name | Sort-Object)
    $listed = @($script:PesterDomainFiles.Values | ForEach-Object { $_ })
    $duplicate = @($listed | Group-Object | Where-Object Count -gt 1 | ForEach-Object Name)
    $missing = @($onDisk | Where-Object { $_ -notin $listed })
    $unknown = @($listed | Where-Object { $_ -notin $onDisk } | Sort-Object -Unique)
    if ($duplicate.Count -eq 0 -and $missing.Count -eq 0 -and $unknown.Count -eq 0) {
        return
    }
    throw "Pester domain partition is wrong. duplicate=$($duplicate -join ',') missing=$($missing -join ',') unknown=$($unknown -join ',')"
}
