<#
.SYNOPSIS
    Builds and runs the mhook unit tests for all 8 platform/configuration combinations.

.DESCRIPTION
    By default builds the solution via build.ps1, then runs mhook-unit-tests.exe for
    each configuration.  Prints a summary table at the end showing build status and
    test pass/fail counts for every combination.

.PARAMETER SolutionDir
    Root of the mhook repository.  Defaults to the directory containing this script.

.PARAMETER NoBuild
    Skip the build step and run only the tests against existing binaries.

.PARAMETER Filter
    Google Test filter passed as --gtest_filter.  Defaults to '*' (run all tests).

.PARAMETER TimeoutSeconds
    Maximum seconds to wait for each test binary before killing it.  Defaults to 10.

.PARAMETER Repeat
    Number of times to run each test configuration.  Defaults to 1.  Use a higher
    value to catch flaky tests: each iteration's artifacts are deleted immediately
    after it passes (unless -KeepResults is set), so only failing iterations keep
    files on disk.

.PARAMETER ResultsDir
    Directory under which a timestamped subfolder is created for each invocation.
    Defaults to 'test-results' alongside this script.

.PARAMETER KeepResults
    Keep the run subfolder even when all tests pass.  By default it is deleted on
    a fully successful run.

.PARAMETER Arch
    Architectures to build and test.  Defaults to all ('x64', 'x86').
    Mutually exclusive with -Target.

.PARAMETER Configuration
    Build configurations to build and test.  Defaults to all
    ('Debug', 'DebugDynamic', 'Release', 'ReleaseDynamic').
    Mutually exclusive with -Target.

.PARAMETER Target
    Explicit arch/config combinations to build and test, e.g. 'x64/Release', 'x86/Debug'.
    Mutually exclusive with -Arch and -Configuration.

.NOTES
    Exit code is 0 if every build succeeds and every test passes, 1 otherwise.
#>
[CmdletBinding(DefaultParameterSetName = 'Matrix')]
param(
    [Parameter(ParameterSetName = 'Matrix')]
    [Parameter(ParameterSetName = 'Target')]
    [string]$SolutionDir = $PSScriptRoot,

    [Parameter(ParameterSetName = 'Matrix')]
    [Parameter(ParameterSetName = 'Target')]
    [switch]$NoBuild,

    [Parameter(ParameterSetName = 'Matrix')]
    [Parameter(ParameterSetName = 'Target')]
    [string]$Filter = '*',

    [Parameter(ParameterSetName = 'Matrix')]
    [Parameter(ParameterSetName = 'Target')]
    [int]$TimeoutSeconds = 10,

    [Parameter(ParameterSetName = 'Matrix')]
    [Parameter(ParameterSetName = 'Target')]
    [int]$Repeat = 1,

    [Parameter(ParameterSetName = 'Matrix')]
    [Parameter(ParameterSetName = 'Target')]
    [string]$ResultsDir = (Join-Path $PSScriptRoot 'test-results'),

    [Parameter(ParameterSetName = 'Matrix')]
    [Parameter(ParameterSetName = 'Target')]
    [switch]$KeepResults,

    [Parameter(ParameterSetName = 'Matrix')]
    [ValidateSet('x64', 'x86')]
    [string[]]$Arch = @('x64', 'x86'),

    [Parameter(ParameterSetName = 'Matrix')]
    [ValidateSet('Debug', 'DebugDynamic', 'Release', 'ReleaseDynamic')]
    [string[]]$Configuration = @('Debug', 'DebugDynamic', 'Release', 'ReleaseDynamic'),

    [Parameter(ParameterSetName = 'Target')]
    [ValidateSet('x64/Debug', 'x64/DebugDynamic', 'x64/Release', 'x64/ReleaseDynamic',
                 'x86/Debug', 'x86/DebugDynamic', 'x86/Release', 'x86/ReleaseDynamic')]
    [string[]]$Target
)

Set-StrictMode -Version 3
$ErrorActionPreference = 'Continue'

# Compile a small C# helper once per session.  PowerShell script blocks cannot
# run on thread-pool threads (no runspace), so we use a plain .NET method for
# the concurrent stream reads.
if (-not ([System.Management.Automation.PSTypeName]'MhookStreamInterleaver').Type) {
    Add-Type -TypeDefinition @'
using System.Collections.Concurrent;
using System.IO;
using System.Threading.Tasks;
public static class MhookStreamInterleaver {
    public static Task Drain(TextReader reader, ConcurrentQueue<string> queue) {
        return Task.Run(() => {
            string line;
            while ((line = reader.ReadLine()) != null) queue.Enqueue(line);
        });
    }
}
'@
}

# ---------------------------------------------------------------------------
# Parse Google Test stdout for pass/fail counts
# ---------------------------------------------------------------------------
function Get-GtestCounts([string[]]$Lines) {
    $passed = 0; $failed = 0
    foreach ($line in $Lines) {
        if ($line -match '\[\s+PASSED\s+\]\s+(\d+) test')  { $passed = [int]$Matches[1] }
        if ($line -match '\[\s+FAILED\s+\]\s+(\d+) test')  { $failed = [int]$Matches[1] }
    }
    return @{ Passed = $passed; Failed = $failed }
}

# ---------------------------------------------------------------------------
# Run a test executable with a timeout, returning output lines and exit info.
# Async reads are started before WaitForExit to prevent pipe-buffer deadlock.
# ---------------------------------------------------------------------------
function Invoke-TestExe([string]$Exe, [string]$Filter, [int]$TimeoutSeconds) {
    $psi = [System.Diagnostics.ProcessStartInfo]::new($Exe, "--gtest_filter=$Filter")
    $psi.UseShellExecute        = $false
    $psi.RedirectStandardOutput = $true
    $psi.RedirectStandardError  = $true
    $psi.CreateNoWindow         = $true

    $queue = [System.Collections.Concurrent.ConcurrentQueue[string]]::new()
    $proc  = [System.Diagnostics.Process]::Start($psi)

    # Lines from stdout and stderr are interleaved in arrival order.  Ordering is
    # line-granular, not byte-exact, because each stream is read independently.
    # Once a stable PowerShell ships on .NET 11+, use ProcessStartInfo.StandardOutputHandle
    # and StandardErrorHandle to point both streams at the same pipe write-end for
    # true byte-exact ordering.
    $outTask = [MhookStreamInterleaver]::Drain($proc.StandardOutput, $queue)
    $errTask = [MhookStreamInterleaver]::Drain($proc.StandardError, $queue)

    $finished = $proc.WaitForExit($TimeoutSeconds * 1000)
    if (-not $finished) {
        $proc.Kill($true)   # kills process tree (PS 7+ / .NET 5+)
    }
    # Wait for both drain tasks to finish (pipes EOF when process exits/is killed).
    [System.Threading.Tasks.Task]::WhenAll($outTask, $errTask).GetAwaiter().GetResult()

    return [pscustomobject]@{
        Lines    = [string[]]$queue.ToArray()
        ExitCode = if ($finished) { $proc.ExitCode } else { -1 }
        TimedOut = -not $finished
    }
}

# ---------------------------------------------------------------------------
# Configurations
# ---------------------------------------------------------------------------
$configs = @(
    [pscustomobject]@{ MSBuildPlatform = 'x64';   MSBuildConfig = 'Debug';          OutArch = 'x64';   OutDir = 'x64\Debug' }
    [pscustomobject]@{ MSBuildPlatform = 'x64';   MSBuildConfig = 'DebugDynamic';   OutArch = 'x64';   OutDir = 'x64\DebugDynamic' }
    [pscustomobject]@{ MSBuildPlatform = 'x64';   MSBuildConfig = 'Release';        OutArch = 'x64';   OutDir = 'x64\Release' }
    [pscustomobject]@{ MSBuildPlatform = 'x64';   MSBuildConfig = 'ReleaseDynamic'; OutArch = 'x64';   OutDir = 'x64\ReleaseDynamic' }
    [pscustomobject]@{ MSBuildPlatform = 'x86';   MSBuildConfig = 'Debug';          OutArch = 'Win32'; OutDir = 'Win32\Debug' }
    [pscustomobject]@{ MSBuildPlatform = 'x86';   MSBuildConfig = 'DebugDynamic';   OutArch = 'Win32'; OutDir = 'Win32\DebugDynamic' }
    [pscustomobject]@{ MSBuildPlatform = 'x86';   MSBuildConfig = 'Release';        OutArch = 'Win32'; OutDir = 'Win32\Release' }
    [pscustomobject]@{ MSBuildPlatform = 'x86';   MSBuildConfig = 'ReleaseDynamic'; OutArch = 'Win32'; OutDir = 'Win32\ReleaseDynamic' }
)

if ($PSCmdlet.ParameterSetName -eq 'Target') {
    $configs = $configs | Where-Object { "$($_.MSBuildPlatform)/$($_.MSBuildConfig)" -in $Target }
} else {
    $configs = $configs | Where-Object { $_.MSBuildPlatform -in $Arch -and $_.MSBuildConfig -in $Configuration }
}
if ($configs.Count -eq 0) {
    Write-Error 'No configurations selected.  Check -Arch, -Configuration, and -Target.'
    exit 1
}

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
$sln    = Join-Path $SolutionDir 'libmhook.slnx'
if (-not (Test-Path $sln)) { Write-Error "Solution not found: $sln"; exit 1 }

$runDir = Join-Path $ResultsDir (Get-Date -Format 'yyyy-MM-ddTHHmmss')
$null   = New-Item -ItemType Directory -Path $runDir -Force

if (-not $NoBuild) {
    $buildParams = if ($PSCmdlet.ParameterSetName -eq 'Target') {
        @{ Target = $Target }
    } else {
        @{ Arch = $Arch; Configuration = $Configuration }
    }
    & (Join-Path $PSScriptRoot 'build.ps1') -SolutionDir $SolutionDir @buildParams
    if ($LASTEXITCODE -ne 0) { Write-Host '' }  # blank line before test section on build failure
}

Write-Host ''

$padWidth        = $Repeat.ToString().Length
$allIterResults  = @()

for ($iter = 1; $iter -le $Repeat; $iter++) {
    # When Repeat > 1, each iteration gets its own zero-padded subfolder so that
    # passing iterations can be cleaned up independently without disturbing others.
    $iterDir = if ($Repeat -eq 1) {
                   $runDir
               } else {
                   Join-Path $runDir $iter.ToString().PadLeft($padWidth, '0')
               }
    if ($Repeat -gt 1) {
        $null = New-Item -ItemType Directory -Path $iterDir -Force
        Write-Host "--- Iteration $iter/$Repeat ---"
    }

    $iterResults = @()

    foreach ($cfg in $configs) {
        $label   = "$($cfg.MSBuildConfig)|$($cfg.OutArch)"
        $testExe = Join-Path $SolutionDir "build" "artifacts" "mhook-unit-tests" $cfg.OutDir "mhook-unit-tests.exe"

        $buildStatus = if ($NoBuild)              { 'SKIP' }
                       elseif (Test-Path $testExe) { 'OK'   }
                       else                        { 'FAILED' }

        $testStatus = $null
        $testDetail = $null

        if ($buildStatus -in 'OK', 'SKIP') {
            if (-not (Test-Path $testExe)) {
                $testStatus = 'NO EXE'
            } else {
                Write-Host "  Testing  $label ..." -NoNewline
                $run    = Invoke-TestExe -Exe $testExe -Filter $Filter -TimeoutSeconds $TimeoutSeconds
                $ok     = -not $run.TimedOut -and $run.ExitCode -eq 0
                $counts = Get-GtestCounts $run.Lines
                $total  = $counts.Passed + $counts.Failed

                $logFile = Join-Path $iterDir "$($cfg.OutArch)-$($cfg.MSBuildConfig).log"
                $run.Lines | Set-Content -Path $logFile -Encoding UTF8

                if ($run.TimedOut) {
                    $testStatus = 'TIMEOUT'
                    Write-Host " TIMEOUT (>${TimeoutSeconds}s)" -ForegroundColor Yellow
                } elseif ($ok) {
                    $testStatus = 'PASS'
                    $testDetail = "$($counts.Passed)/$total"
                    Write-Host " PASS ($($counts.Passed)/$total)"
                } else {
                    $testStatus = 'FAIL'
                    $testDetail = "$($counts.Passed)/$total"
                    Write-Host " FAIL ($($counts.Passed)/$total)"
                    # Show failing test names
                    $run.Lines | Where-Object { $_ -match '^\[  FAILED  \]' } |
                        Select-Object -First 10 |
                        ForEach-Object { Write-Host "    $_" }
                }
            }
        } else {
            $testStatus = '-'
        }

        $iterResults += [pscustomobject]@{
            Iter       = $iter
            Arch       = $cfg.OutArch
            Config     = $cfg.MSBuildConfig
            Build      = $buildStatus
            TestStatus = $testStatus
            TestDetail = $testDetail
        }
    }

    $allIterResults += $iterResults

    # Clean up this iteration's subfolder immediately if everything passed.
    # Failing iterations keep their artifacts so they can be inspected later.
    $iterOk = -not ($iterResults | Where-Object { $_.TestStatus -ne 'PASS' })
    if ($Repeat -gt 1 -and $iterOk -and -not $KeepResults) {
        Remove-Item -Recurse -Force $iterDir
    }

    if ($Repeat -gt 1) { Write-Host '' }
}

# ---------------------------------------------------------------------------
# Aggregate results across all iterations (one row per config)
# ---------------------------------------------------------------------------
$results = foreach ($cfg in $configs) {
    $rows = @($allIterResults | Where-Object { $_.Arch -eq $cfg.OutArch -and $_.Config -eq $cfg.MSBuildConfig })

    $worst = if ($rows | Where-Object { $_.TestStatus -eq 'TIMEOUT' }) { 'TIMEOUT' }
             elseif ($rows | Where-Object { $_.TestStatus -eq 'FAIL' }) { 'FAIL'    }
             elseif ($rows | Where-Object { $_.TestStatus -eq 'PASS' }) { 'PASS'    }
             else { ($rows | Select-Object -First 1).TestStatus }

    $worstDetail = ($rows | Where-Object { $_.TestStatus -eq $worst } | Select-Object -First 1).TestDetail
    $passingRuns = @($rows | Where-Object { $_.TestStatus -eq 'PASS' }).Count

    [pscustomobject]@{
        Arch        = $cfg.OutArch
        Config      = $cfg.MSBuildConfig
        Build       = ($rows | Select-Object -First 1).Build
        TestStatus  = $worst
        TestDetail  = $worstDetail
        PassingRuns = $passingRuns
    }
}

# ---------------------------------------------------------------------------
# Summary table
# ---------------------------------------------------------------------------
Write-Host '=== Summary ==='
Write-Host ''

$archWidth   = ($results | ForEach-Object { $_.Arch.Length }       | Measure-Object -Max).Maximum
$configWidth = ($results | ForEach-Object { $_.Config.Length }     | Measure-Object -Max).Maximum
$buildWidth  = 6
$testWidth   = ($results | ForEach-Object { $_.TestStatus.Length } | Measure-Object -Max).Maximum
$detailWidth = 7

if ($Repeat -gt 1) {
    $runsLabel = "Runs"
    $runsWidth = [Math]::Max($runsLabel.Length, "$Repeat/$Repeat".Length)

    $header = "  {0,-$archWidth}  {1,-$configWidth}  {2,-$buildWidth}  {3,-$testWidth}  {4,-$detailWidth}  {5,-$runsWidth}" `
        -f 'Arch', 'Config', 'Build', 'Tests', 'Pass/N', $runsLabel
    $sep    = "  {0}  {1}  {2}  {3}  {4}  {5}" `
        -f ('-' * $archWidth), ('-' * $configWidth), ('-' * $buildWidth), ('-' * $testWidth), ('-' * $detailWidth), ('-' * $runsWidth)
} else {
    $header = "  {0,-$archWidth}  {1,-$configWidth}  {2,-$buildWidth}  {3,-$testWidth}  {4,-$detailWidth}" `
        -f 'Arch', 'Config', 'Build', 'Tests', 'Pass/N'
    $sep    = "  {0}  {1}  {2}  {3}  {4}" `
        -f ('-' * $archWidth), ('-' * $configWidth), ('-' * $buildWidth), ('-' * $testWidth), ('-' * $detailWidth)
}

Write-Host $header
Write-Host $sep

foreach ($r in $results) {
    $detailCol = if ($r.TestDetail) { $r.TestDetail } else { '' }

    if ($Repeat -gt 1) {
        $runsCol = "$($r.PassingRuns)/$Repeat"
        $line    = "  {0,-$archWidth}  {1,-$configWidth}  {2,-$buildWidth}  {3,-$testWidth}  {4,-$detailWidth}  {5,-$runsWidth}" `
            -f $r.Arch, $r.Config, $r.Build, $r.TestStatus, $detailCol, $runsCol
    } else {
        $line    = "  {0,-$archWidth}  {1,-$configWidth}  {2,-$buildWidth}  {3,-$testWidth}  {4,-$detailWidth}" `
            -f $r.Arch, $r.Config, $r.Build, $r.TestStatus, $detailCol
    }

    $colour = if ($r.Build -eq 'FAILED' -or $r.TestStatus -in 'FAIL', 'TIMEOUT') { 'Red' }
              elseif ($r.TestStatus -eq 'PASS')                                    { 'Green' }
              else                                                                  { 'White' }
    Write-Host $line -ForegroundColor $colour
}

Write-Host ''

$nBuilt   = @($results | Where-Object { $_.Build      -eq 'OK'      }).Count
$nPass    = @($results | Where-Object { $_.TestStatus -eq 'PASS'    }).Count
$nFail    = @($results | Where-Object { $_.TestStatus -eq 'FAIL'    }).Count
$nTimeout = @($results | Where-Object { $_.TestStatus -eq 'TIMEOUT' }).Count
$nBuildF  = @($results | Where-Object { $_.Build      -eq 'FAILED'  }).Count

$total = $results.Count
Write-Host "$total configurations: $nBuilt built, $nPass passed, $nFail failed" -NoNewline
if ($nTimeout -gt 0) { Write-Host ", $nTimeout timed out" -NoNewline }
if ($nBuildF  -gt 0) { Write-Host ", $nBuildF build failure(s)" -NoNewline }
Write-Host ''

$allOk = ($nBuildF -eq 0 -and $nFail -eq 0 -and $nTimeout -eq 0)
if ($allOk) {
    Write-Host 'All checks passed.' -ForegroundColor Green
} else {
    Write-Host 'One or more checks FAILED.' -ForegroundColor Red
}

if ($allOk -and -not $KeepResults) {
    Remove-Item -Recurse -Force $runDir
} else {
    Write-Host "Results saved to: $runDir"
}

exit ($allOk ? 0 : 1)
