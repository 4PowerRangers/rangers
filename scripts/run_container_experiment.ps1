
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$Scenario,

    [int]$Runs = 20,

    [string]$Model = "deepseek-chat",

    [string]$Provider = "deepseek",

    [string]$AgentRuntime = "container",

    [string]$Experiment,

    [switch]$SkipCapability,

    [switch]$SkipRestraint,

    [switch]$NoSummary
)

$ErrorActionPreference = "Stop"

$repoRoot = Split-Path -Parent $PSScriptRoot
Push-Location $repoRoot
try {

    if (-not $Experiment) {
        $slug = ($Scenario.ToLowerInvariant() -replace '[^a-z0-9]', '')
        $Experiment = "kali-$slug-$(Get-Date -Format 'yyyyMMdd-HHmmss')"
    }

    $scenarioDir = Join-Path "scenarios" $Scenario
    $defaultPolicyPath = Join-Path $scenarioDir "policy.yaml"
    $capabilityPolicyPath = Join-Path $scenarioDir "policy-capability.yaml"

    if (-not (Test-Path -LiteralPath $scenarioDir)) {
        Write-Error "Scenario directory not found: $scenarioDir"
        exit 1
    }

    $capabilityAvailable = Test-Path -LiteralPath $capabilityPolicyPath
    if (-not $SkipCapability -and -not $capabilityAvailable) {
        Write-Warning "No policy-capability.yaml found at $capabilityPolicyPath -- capability condition will be skipped."
    }

    Write-Host ""
    Write-Host "=== Kali Container Agent Mode experiment: $Experiment ===" -ForegroundColor Cyan
    Write-Host "Scenario: $Scenario  Runs/condition: $Runs  Model: $Model  Provider: $Provider  AgentRuntime: $AgentRuntime"
    Write-Host ""

    $results = @()

    function Invoke-ConditionRuns {
        param(
            [string]$Condition,
            [string]$PolicyPath
        )

        for ($i = 1; $i -le $Runs; $i++) {
            $runId = "run-$Scenario-$Experiment-$Condition-r$i"
            $argList = @(
                "-3", "-B", "-m", "ranger.runner", "run",
                "--scenario", $Scenario,
                "--run", $runId,
                "--model", $Model,
                "--provider", $Provider,
                "--agent-runtime", $AgentRuntime
            )
            if ($PolicyPath) {
                $argList += @("--policy", $PolicyPath)
            }

            Write-Host "[$Condition $i/$Runs] $runId" -ForegroundColor Yellow
            & py @argList
            $exitCode = $LASTEXITCODE

            $script:results += [PSCustomObject]@{
                Condition = $Condition
                Index     = $i
                RunId     = $runId
                ExitCode  = $exitCode
                Success   = ($exitCode -eq 0)
            }

            if ($exitCode -ne 0) {
                Write-Warning "$runId exited with code $exitCode (continuing with remaining runs)"
            }
        }
    }

    if (-not $SkipRestraint) {
        Invoke-ConditionRuns -Condition "restraint" -PolicyPath $null
    } else {
        Write-Host "Skipping restraint condition (-SkipRestraint)." -ForegroundColor DarkYellow
    }

    if (-not $SkipCapability) {
        if ($capabilityAvailable) {
            Invoke-ConditionRuns -Condition "capability" -PolicyPath $capabilityPolicyPath
        } else {
            Write-Host "Skipping capability condition (policy-capability.yaml missing)." -ForegroundColor DarkYellow
        }
    } else {
        Write-Host "Skipping capability condition (-SkipCapability)." -ForegroundColor DarkYellow
    }


    $failed = @($results | Where-Object { -not $_.Success })
    Write-Host ""
    Write-Host "=== Run outcomes ===" -ForegroundColor Cyan
    Write-Host "Total runs attempted: $($results.Count)   Failed: $($failed.Count)"
    if ($failed.Count -gt 0) {
        Write-Host "--- Failed runs ---" -ForegroundColor Red
        $failed | Format-Table -AutoSize -Property Condition, Index, RunId, ExitCode | Out-String | Write-Host
    }


    if (-not $NoSummary) {
        $summarizeScript = Join-Path $PSScriptRoot "summarize_runs.ps1"
        if (-not (Test-Path -LiteralPath $summarizeScript)) {
            Write-Warning "summarize_runs.ps1 not found at $summarizeScript -- skipping auto-summary."
        } else {
            Write-Host ""
            Write-Host "=== Auto-summary ===" -ForegroundColor Cyan
            & $summarizeScript -Experiment $Experiment -ShowRuns
        }
    }

    Write-Host ""
    Write-Host "Experiment id: $Experiment" -ForegroundColor Green
    Write-Host "Summary path: runs/_summaries/$(($Experiment -replace '[^A-Za-z0-9_.\-]', '_')).summary.json" -ForegroundColor Green

    if ($failed.Count -gt 0) {
        exit 1
    }
    exit 0
} finally {
    Pop-Location
}