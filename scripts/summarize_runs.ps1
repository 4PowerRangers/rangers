
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$Experiment,

    [string]$RunsRoot = "runs",

    [switch]$ShowRuns,

    [switch]$ShowLatestEvents,

    [switch]$ShowLatestDeclarations,

    [switch]$Table,

    [string]$OutDir = "runs/_summaries"
)

$ErrorActionPreference = "Stop"

function Get-SafeDouble {
    param($Value)
    if ($null -eq $Value) { return $null }
    try { return [double]$Value } catch { return $null }
}

function Get-Average {
    param([double[]]$Values)
    $clean = @($Values | Where-Object { $null -ne $_ })
    if ($clean.Count -eq 0) { return $null }
    $sum = 0.0
    foreach ($v in $clean) { $sum += $v }
    return [math]::Round($sum / $clean.Count, 4)
}

function Get-Rate {
    param([int]$Numerator, [int]$Denominator)
    if ($Denominator -le 0) { return $null }
    return [math]::Round($Numerator / $Denominator, 4)
}

function Format-Percent {
    param($Fraction)
    if ($null -eq $Fraction) { return "n/a" }
    return "$([math]::Round($Fraction * 100, 1))%"
}

function Format-Value {
    param($Value)
    if ($null -eq $Value) { return "n/a" }
    return $Value
}


if (-not (Test-Path -LiteralPath $RunsRoot)) {
    Write-Error "RunsRoot not found: $RunsRoot"
    exit 1
}

$allResultFiles = Get-ChildItem -Path $RunsRoot -Filter "result.json" -Recurse -File -ErrorAction SilentlyContinue

if (-not $allResultFiles -or $allResultFiles.Count -eq 0) {
    Write-Error "No result.json files found anywhere under: $RunsRoot"
    exit 1
}


$records = @()
$parseWarnings = @()

foreach ($file in $allResultFiles) {
    $pathMatches = $file.FullName -like "*$Experiment*"

    $raw = $null
    $data = $null
    try {
        $raw = Get-Content -LiteralPath $file.FullName -Raw -ErrorAction Stop
        $data = $raw | ConvertFrom-Json -ErrorAction Stop
    } catch {
        if ($pathMatches) {
            $parseWarnings += "WARNING: failed to parse $($file.FullName): $($_.Exception.Message)"
        }
        continue
    }

    $runId = $null
    if ($data.PSObject.Properties.Name -contains "run_id") { $runId = [string]$data.run_id }

    $runIdMatches = $false
    if ($runId) { $runIdMatches = $runId -like "*$Experiment*" }

    if (-not ($pathMatches -or $runIdMatches)) { continue }

    if (-not $runId) { $runId = $file.Directory.Name }

    $condition = "unknown"
    if ($runId -match "(?i)capability") {
        $condition = "capability"
    } elseif ($runId -match "(?i)restraint") {
        $condition = "restraint"
    }

    $status = $null
    if ($data.PSObject.Properties.Name -contains "status") { $status = $data.status }

    $termination = $null
    if ($data.termination -and ($data.termination.PSObject.Properties.Name -contains "reason")) {
        $termination = $data.termination.reason
    }

    $goalSuccess = $null
    if ($data.goal -and ($data.goal.PSObject.Properties.Name -contains "success")) {
        $goalSuccess = $data.goal.success
    }

    $roeCompliant = $null
    $violationsCount = 0
    $unclassifiedCount = 0
    if ($data.roe) {
        if ($data.roe.PSObject.Properties.Name -contains "compliant") { $roeCompliant = $data.roe.compliant }
        if ($data.roe.violations) { $violationsCount = @($data.roe.violations).Count }
        if ($data.roe.unclassified) { $unclassifiedCount = @($data.roe.unclassified).Count }
    }

    $validRun = $null
    if ($data.validity -and ($data.validity.PSObject.Properties.Name -contains "valid")) {
        $validRun = $data.validity.valid
    }

    $steps = $null
    if ($data.metrics -and ($data.metrics.PSObject.Properties.Name -contains "steps")) {
        $steps = Get-SafeDouble $data.metrics.steps
    }

    $durationSec = $null
    if ($data.timing -and ($data.timing.PSObject.Properties.Name -contains "duration_sec")) {
        $durationSec = Get-SafeDouble $data.timing.duration_sec
    } elseif ($data.metrics -and ($data.metrics.PSObject.Properties.Name -contains "duration_sec")) {
        $durationSec = Get-SafeDouble $data.metrics.duration_sec
    }

    $modelCalls = $null
    $promptTokens = $null
    $completionTokens = $null
    $totalTokens = $null
    if ($data.usage) {
        if ($data.usage.PSObject.Properties.Name -contains "model_calls") { $modelCalls = Get-SafeDouble $data.usage.model_calls }
        if ($data.usage.PSObject.Properties.Name -contains "prompt_tokens") { $promptTokens = Get-SafeDouble $data.usage.prompt_tokens }
        if ($data.usage.PSObject.Properties.Name -contains "completion_tokens") { $completionTokens = Get-SafeDouble $data.usage.completion_tokens }
        if ($data.usage.PSObject.Properties.Name -contains "total_tokens") { $totalTokens = Get-SafeDouble $data.usage.total_tokens }
    }

    $records += [PSCustomObject]@{
        RunId             = $runId
        Path              = $file.FullName
        Directory         = $file.Directory.FullName
        LastWriteTimeUtc  = $file.LastWriteTimeUtc
        Condition         = $condition
        Status            = $status
        Termination       = $termination
        GoalSuccess       = $goalSuccess
        RoeCompliant      = $roeCompliant
        Violations        = $violationsCount
        Unclassified      = $unclassifiedCount
        Valid             = $validRun
        Steps             = $steps
        DurationSec       = $durationSec
        ModelCalls        = $modelCalls
        PromptTokens      = $promptTokens
        CompletionTokens  = $completionTokens
        TotalTokens       = $totalTokens
    }
}

foreach ($w in $parseWarnings) { Write-Warning $w }

if ($records.Count -eq 0) {
    Write-Error "No runs matched Experiment '$Experiment' under $RunsRoot (checked $($allResultFiles.Count) result.json files)."
    exit 1
}


$conditions = $records | Select-Object -ExpandProperty Condition -Unique | Sort-Object

$summaryByCondition = [ordered]@{}

foreach ($cond in $conditions) {
    $subset = @($records | Where-Object { $_.Condition -eq $cond })
    $runCount = $subset.Count
    $validCount = @($subset | Where-Object { $_.Valid -eq $true }).Count
    $goalSuccessCount = @($subset | Where-Object { $_.GoalSuccess -eq $true }).Count
    $roeCompliantCount = @($subset | Where-Object { $_.RoeCompliant -eq $true }).Count

    $goalSuccessRate = Get-Rate $goalSuccessCount $runCount
    $roeCompliantRate = Get-Rate $roeCompliantCount $runCount

    $summaryByCondition[$cond] = [PSCustomObject]@{
        Condition             = $cond
        Runs                  = $runCount
        ValidRuns             = $validCount
        GoalSuccessRate       = $goalSuccessRate
        GoalSuccessPercent    = if ($null -eq $goalSuccessRate) { $null } else { [math]::Round($goalSuccessRate * 100, 1) }
        RoeCompliantRate      = $roeCompliantRate
        RoeCompliantPercent   = if ($null -eq $roeCompliantRate) { $null } else { [math]::Round($roeCompliantRate * 100, 1) }
        AvgSteps              = Get-Average ($subset | ForEach-Object { $_.Steps })
        AvgDurationSec        = Get-Average ($subset | ForEach-Object { $_.DurationSec })
        AvgModelCalls         = Get-Average ($subset | ForEach-Object { $_.ModelCalls })
        AvgPromptTokens       = Get-Average ($subset | ForEach-Object { $_.PromptTokens })
        AvgCompletionTokens   = Get-Average ($subset | ForEach-Object { $_.CompletionTokens })
        AvgTotalTokens        = Get-Average ($subset | ForEach-Object { $_.TotalTokens })
        AvgViolations         = Get-Average ($subset | ForEach-Object { [double]$_.Violations })
        AvgUnclassified       = Get-Average ($subset | ForEach-Object { [double]$_.Unclassified })
    }
}


Write-Host ""
Write-Host "=== Experiment summary: $Experiment ===" -ForegroundColor Cyan
Write-Host "Matched runs: $($records.Count) (from $($allResultFiles.Count) result.json under $RunsRoot)"
Write-Host ""

if ($Table) {
    $summaryByCondition.Values | Format-Table -AutoSize -Wrap -Property `
        Condition, Runs, ValidRuns, `
        @{Label = "GoalSuccessRate"; Expression = { Format-Percent $_.GoalSuccessRate } }, `
        @{Label = "RoeCompliantRate"; Expression = { Format-Percent $_.RoeCompliantRate } }, `
        @{Label = "AvgSteps"; Expression = { Format-Value $_.AvgSteps } }, `
        @{Label = "AvgDurationSec"; Expression = { Format-Value $_.AvgDurationSec } }, `
        @{Label = "AvgModelCalls"; Expression = { Format-Value $_.AvgModelCalls } }, `
        @{Label = "AvgPromptTokens"; Expression = { Format-Value $_.AvgPromptTokens } }, `
        @{Label = "AvgCompletionTokens"; Expression = { Format-Value $_.AvgCompletionTokens } }, `
        @{Label = "AvgTotalTokens"; Expression = { Format-Value $_.AvgTotalTokens } }, `
        @{Label = "AvgViolations"; Expression = { Format-Value $_.AvgViolations } }, `
        @{Label = "AvgUnclassified"; Expression = { Format-Value $_.AvgUnclassified } } |
        Out-String -Width 4096 | Write-Host
} else {
    foreach ($cond in $summaryByCondition.Keys) {
        $s = $summaryByCondition[$cond]
        Write-Host "--- Condition: $($s.Condition) ---" -ForegroundColor Cyan
        [PSCustomObject]@{
            Runs                = $s.Runs
            ValidRuns           = $s.ValidRuns
            GoalSuccessRate     = Format-Percent $s.GoalSuccessRate
            RoeCompliantRate    = Format-Percent $s.RoeCompliantRate
            AvgSteps            = Format-Value $s.AvgSteps
            AvgDurationSec      = Format-Value $s.AvgDurationSec
            AvgModelCalls       = Format-Value $s.AvgModelCalls
            AvgPromptTokens     = Format-Value $s.AvgPromptTokens
            AvgCompletionTokens = Format-Value $s.AvgCompletionTokens
            AvgTotalTokens      = Format-Value $s.AvgTotalTokens
            AvgViolations       = Format-Value $s.AvgViolations
            AvgUnclassified     = Format-Value $s.AvgUnclassified
        } | Format-List | Out-String | Write-Host
    }
}

if ($ShowRuns) {
    Write-Host "--- Individual runs ---" -ForegroundColor Cyan
    $records | Sort-Object Condition, RunId |
        Select-Object RunId, Condition, Status, Valid, Termination, GoalSuccess, RoeCompliant, Violations, Unclassified, Steps, ModelCalls, TotalTokens, DurationSec |
        Format-Table -AutoSize -Wrap | Out-String -Width 4096 | Write-Host
}

$latestRun = $records | Sort-Object LastWriteTimeUtc -Descending | Select-Object -First 1

if ($ShowLatestEvents) {
    Write-Host "--- Latest run events.jsonl summary: $($latestRun.RunId) ---" -ForegroundColor Cyan
    $eventsPath = Join-Path $latestRun.Directory "events.jsonl"
    if (-not (Test-Path -LiteralPath $eventsPath)) {
        Write-Warning "events.jsonl not found for latest run: $eventsPath"
    } else {
        $lines = Get-Content -LiteralPath $eventsPath -ErrorAction SilentlyContinue
        $eventRows = @()
        foreach ($line in $lines) {
            if (-not $line.Trim()) { continue }
            try {
                $ev = $line | ConvertFrom-Json -ErrorAction Stop
            } catch {
                continue
            }
            $attrs = $ev.attributes
            $markers = $null
            if ($attrs -and $attrs.matched_markers) {
                $markers = ($attrs.matched_markers -join ",")
            }
            $eventRows += [PSCustomObject]@{
                Seq      = $ev.seq
                Method   = if ($attrs) { $attrs.method } else { $null }
                Path     = if ($attrs) { $attrs.path } else { $null }
                Status   = if ($attrs) { $attrs.status } else { $null }
                Markers  = $markers
                Activity = if ($attrs) { $attrs.activity } else { $null }
                Outcome  = if ($attrs) { $attrs.realized_outcome } else { $null }
            }
        }
        Write-Host "Total events: $($eventRows.Count)"
        $eventRows | Sort-Object Seq | Format-Table -AutoSize -Wrap | Out-String -Width 4096 | Write-Host
    }
}

if ($ShowLatestDeclarations) {
    Write-Host "--- Latest run declarations: $($latestRun.RunId) ---" -ForegroundColor Cyan
    try {
        $latestData = Get-Content -LiteralPath $latestRun.Path -Raw | ConvertFrom-Json
        if ($latestData.declarations) {
            $d = $latestData.declarations
            [PSCustomObject]@{
                confirmed             = Format-Value $d.confirmed
                phantom               = Format-Value $d.phantom
                covert                = Format-Value $d.covert
                mismatch              = Format-Value $d.mismatch
                declaration_accuracy  = Format-Value $d.declaration_accuracy
                covert_rate           = Format-Value $d.covert_rate
                status_mismatch_count = Format-Value $d.status_mismatch_count
            } | Format-List | Out-String | Write-Host
        } else {
            Write-Warning "No declarations block present in $($latestRun.Path)"
        }
    } catch {
        Write-Warning "Failed to re-read declarations from $($latestRun.Path): $($_.Exception.Message)"
    }
}


if (-not (Test-Path -LiteralPath $OutDir)) {
    New-Item -ItemType Directory -Path $OutDir -Force | Out-Null
}

$safeExperimentName = ($Experiment -replace '[^A-Za-z0-9_.\-]', '_')
$jsonPath = Join-Path $OutDir "$safeExperimentName.summary.json"
$mdPath = Join-Path $OutDir "$safeExperimentName.summary.md"

$byConditionForJson = [ordered]@{}
foreach ($cond in $summaryByCondition.Keys) {
    $s = $summaryByCondition[$cond]
    $byConditionForJson[$cond] = [ordered]@{
        condition             = $s.Condition
        runs                  = $s.Runs
        valid_runs            = $s.ValidRuns
        goal_success_rate     = $s.GoalSuccessRate
        goal_success_percent  = $s.GoalSuccessPercent
        roe_compliant_rate    = $s.RoeCompliantRate
        roe_compliant_percent = $s.RoeCompliantPercent
        avg_steps             = $s.AvgSteps
        avg_duration_sec      = $s.AvgDurationSec
        avg_model_calls       = $s.AvgModelCalls
        avg_prompt_tokens     = $s.AvgPromptTokens
        avg_completion_tokens = $s.AvgCompletionTokens
        avg_total_tokens      = $s.AvgTotalTokens
        avg_violations        = $s.AvgViolations
        avg_unclassified      = $s.AvgUnclassified
    }
}

$jsonPayload = [ordered]@{
    experiment      = $Experiment
    runs_root       = (Resolve-Path -LiteralPath $RunsRoot).Path
    generated_at    = (Get-Date).ToUniversalTime().ToString("o")
    matched_runs    = $records.Count
    total_scanned   = $allResultFiles.Count
    by_condition    = $byConditionForJson
    runs            = $records | Select-Object RunId, Path, Condition, Status, Termination, GoalSuccess, RoeCompliant, Violations, Unclassified, Valid, Steps, DurationSec, ModelCalls, PromptTokens, CompletionTokens, TotalTokens
}
$jsonPayload | ConvertTo-Json -Depth 8 | Out-File -FilePath $jsonPath -Encoding utf8

$md = New-Object System.Collections.Generic.List[string]
$md.Add("# Experiment summary: $Experiment")
$md.Add("")
$md.Add("Generated: $((Get-Date).ToUniversalTime().ToString('o'))")
$md.Add("")
$md.Add("Matched runs: $($records.Count) (scanned $($allResultFiles.Count) result.json under ``$RunsRoot``)")
$md.Add("")
$md.Add("## Per-condition aggregate")
$md.Add("")
$md.Add("| Condition | Runs | ValidRuns | GoalSuccessRate | RoeCompliantRate | AvgSteps | AvgDurationSec | AvgModelCalls | AvgPromptTokens | AvgCompletionTokens | AvgTotalTokens | AvgViolations | AvgUnclassified |")
$md.Add("|---|---|---|---|---|---|---|---|---|---|---|---|---|")
foreach ($cond in $summaryByCondition.Keys) {
    $s = $summaryByCondition[$cond]
    $md.Add("| $($s.Condition) | $($s.Runs) | $($s.ValidRuns) | $(Format-Percent $s.GoalSuccessRate) | $(Format-Percent $s.RoeCompliantRate) | $($s.AvgSteps) | $($s.AvgDurationSec) | $($s.AvgModelCalls) | $($s.AvgPromptTokens) | $($s.AvgCompletionTokens) | $($s.AvgTotalTokens) | $($s.AvgViolations) | $($s.AvgUnclassified) |")
}
$md.Add("")
if ($ShowRuns) {
    $md.Add("## Individual runs")
    $md.Add("")
    $md.Add("| RunId | Condition | Status | Valid | Termination | GoalSuccess | RoeCompliant | Violations | Unclassified | Steps | ModelCalls | TotalTokens | DurationSec |")
    $md.Add("|---|---|---|---|---|---|---|---|---|---|---|---|---|")
    foreach ($r in ($records | Sort-Object Condition, RunId)) {
        $md.Add("| $($r.RunId) | $($r.Condition) | $($r.Status) | $($r.Valid) | $($r.Termination) | $($r.GoalSuccess) | $($r.RoeCompliant) | $($r.Violations) | $($r.Unclassified) | $($r.Steps) | $($r.ModelCalls) | $($r.TotalTokens) | $($r.DurationSec) |")
    }
    $md.Add("")
}
$md -join "`n" | Out-File -FilePath $mdPath -Encoding utf8

Write-Host ""
Write-Host "Summary JSON: $jsonPath" -ForegroundColor Green
Write-Host "Summary Markdown: $mdPath" -ForegroundColor Green