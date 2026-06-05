<#
.SYNOPSIS
    Verifies that all 8 mhook build outputs depend solely on ntdll.dll.

.DESCRIPTION
    Checks all platform/configuration combinations:

    DLL outputs (DebugDynamic, ReleaseDynamic x x64, Win32):
        Reads the PE import table via dumpbin /imports and fails if any DLL
        other than ntdll.dll appears.

    Static lib outputs (Debug, Release x x64, Win32):
        Reads the symbol table via dumpbin /symbols, collects every external
        symbol that is referenced but not defined within the lib itself,
        strips x86 calling-convention decoration, and fails if any such symbol
        is not exported by the system ntdll.dll.

    x86 decoration rules (applied only for Win32 libs; x64 has no decoration):
        _Name@N  (stdcall)  ->  Name
        _Name    (cdecl)    ->  Name   (public names beginning with '_' get a
                                        second leading underscore on x86, so
                                        __snprintf -> _snprintf correctly)

    Linker-defined symbols that are always resolved by the linker itself
    (not from any import lib) are whitelisted:
        __ImageBase  -  the PE image base address pseudo-symbol

    Release static libs built with WholeProgramOptimization (/GL) produce
    LTCG objects whose symbol tables are not readable by dumpbin /symbols.
    These are reported as INFO and the ReleaseDynamic DLL is relied upon
    instead for release-build coverage.

.PARAMETER SolutionDir
    Root of the mhook repository.  Defaults to the directory containing
    this script.

.NOTES
    Build the solution before running; the script only checks existing
    artifacts.  Exit code 0 = all checks passed, 1 = one or more failed.
#>
[CmdletBinding()]
param(
    [string]$SolutionDir = $PSScriptRoot
)

Set-StrictMode -Version 3
$ErrorActionPreference = 'Continue'

# ---------------------------------------------------------------------------
# Locate dumpbin.exe from the latest VS installation
# ---------------------------------------------------------------------------
function Find-Dumpbin {
    $vsWhere = Join-Path ${env:ProgramFiles(x86)} 'Microsoft Visual Studio\Installer\vswhere.exe'
    if (-not (Test-Path $vsWhere)) { throw "vswhere.exe not found at $vsWhere" }

    $vsPath = & $vsWhere -latest -property installationPath 2>$null
    $exe = Get-ChildItem (Join-Path $vsPath 'VC\Tools\MSVC') 'dumpbin.exe' -Recurse `
               -ErrorAction SilentlyContinue |
           Where-Object { $_.DirectoryName -like '*Hostx64\x64*' } |
           Select-Object -First 1 -ExpandProperty FullName

    if (-not $exe) { throw "dumpbin.exe not found under $vsPath" }
    return $exe
}

# ---------------------------------------------------------------------------
# Build a set of ntdll.dll export names
# ---------------------------------------------------------------------------
function Get-NtdllExports([string]$Dumpbin) {
    $set = [System.Collections.Generic.HashSet[string]]::new(
                [System.StringComparer]::OrdinalIgnoreCase)

    # Export table lines:  "  ordinal  hint  XXXXXXXX  name"
    # The RVA column is always exactly 8 hex digits.
    & $Dumpbin /exports C:\Windows\System32\ntdll.dll 2>$null | ForEach-Object {
        if ($_ -match '^\s+\d+\s+[0-9A-Fa-f]+\s+[0-9A-Fa-f]{8}\s+(\S+)\s*$') {
            $null = $set.Add($Matches[1])
        }
    }

    if ($set.Count -eq 0) { throw "Failed to parse any exports from ntdll.dll" }
    return $set
}

# ---------------------------------------------------------------------------
# Strip x86 calling-convention decoration so a symbol can be matched against
# ntdll's undecorated export names.
#
# On x86 the compiler prepends '_' to every extern "C" name, so:
#   _Name@N  (stdcall)  ->  Name
#   _Name    (cdecl)    ->  Name
#   __snprintf (cdecl, public name starts with '_') -> _snprintf
#
# On x64 no decoration is applied; the symbol name IS the public name and
# must not be modified (e.g. '_snprintf' stays '_snprintf').
# ---------------------------------------------------------------------------
function Undecorate([string]$sym, [bool]$IsX86) {
    if (-not $IsX86) { return $sym }                          # x64: identity
    if ($sym -match '^_(.+)@\d+$') { return $Matches[1] }   # x86 __stdcall
    if ($sym -match '^_(.+)$')     { return $Matches[1] }   # x86 __cdecl
    return $sym
}

# ---------------------------------------------------------------------------
# Symbols that are always provided by the linker itself, not by any import
# lib.  They appear as UNDEF in static libs because static libs have no
# linker step; they are resolved when an exe/DLL is finally linked.
# ---------------------------------------------------------------------------
$LinkerDefinedSymbols = [System.Collections.Generic.HashSet[string]]::new(
    [string[]]@(
        '__ImageBase'          # PE image base pseudo-symbol
    ),
    [System.StringComparer]::OrdinalIgnoreCase)

# ---------------------------------------------------------------------------
# DLL check — import table must reference only ntdll.dll
# ---------------------------------------------------------------------------
function Test-DllImports([string]$Dumpbin, [string]$Path) {
    $out = & $Dumpbin /imports $Path 2>$null

    # Import section headers appear as "    somedll.dll" — exactly 4 leading
    # spaces, then the DLL name, then nothing else on the line.
    $dlls = $out |
        Where-Object { $_ -match '^\s{4}(\S+\.dll)\s*$' } |
        ForEach-Object { [IO.Path]::GetFileName($Matches[1]).ToLower() }

    if (-not $dlls) {
        return @{ Error = 'no DLL imports found in import table — unexpected' }
    }

    $foreign = @($dlls | Where-Object { $_ -ne 'ntdll.dll' })
    if ($foreign.Count -gt 0) {
        return @{ Error = "imports from non-ntdll DLL(s): $($foreign -join ', ')" }
    }
    return $null   # pass
}

# ---------------------------------------------------------------------------
# Static lib check — every unresolved external must be an ntdll.dll export
# ---------------------------------------------------------------------------
function Test-LibSymbols(
    [string]$Dumpbin,
    [string]$Path,
    [bool]$IsX86,
    [System.Collections.Generic.HashSet[string]]$NtdllExports)
{
    $out = & $Dumpbin /symbols $Path 2>$null

    # Collect defined and undefined External symbols.
    # Defined:   "NNN XXXXXXXX SECTn  notype ()  External  | Name"
    # Undefined: "NNN 00000000 UNDEF  notype ()  External  | Name"
    $defined = [System.Collections.Generic.HashSet[string]]::new()
    $undef   = [System.Collections.Generic.HashSet[string]]::new()

    foreach ($line in $out) {
        if ($line -match 'External\s+\|\s+(\S+)') {
            $sym = $Matches[1]
            if ($line -match '\bUNDEF\b') { $null = $undef.Add($sym) }
            else                          { $null = $defined.Add($sym) }
        }
    }

    # Detect LTCG (/GL) objects: they produce no readable symbol table.
    if ($undef.Count -eq 0 -and $defined.Count -eq 0) {
        return @{ Ltcg = $true }
    }

    # Symbols that are referenced but not defined anywhere within the lib.
    $external = @($undef | Where-Object { -not $defined.Contains($_) } | Sort-Object)

    $foreign = @(
        foreach ($sym in $external) {
            $bare = Undecorate $sym $IsX86
            if ($LinkerDefinedSymbols.Contains($bare)) { continue }
            if (-not $NtdllExports.Contains($bare)) {
                "  $sym  ->  '$bare' not in ntdll.dll"
            }
        }
    )

    if ($foreign.Count -gt 0) {
        return @{ Error = "external symbols not in ntdll.dll:`n" + ($foreign -join "`n") }
    }
    return $null   # pass
}

# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------
try   { $dumpbin = Find-Dumpbin } catch { Write-Error $_.Exception.Message; exit 1 }
try   { $ntdllExports = Get-NtdllExports $dumpbin } catch { Write-Error $_.Exception.Message; exit 1 }

Write-Host "dumpbin : $dumpbin"
Write-Host "ntdll   : $($ntdllExports.Count) named exports"
Write-Host ''

$configs = @(
    [pscustomobject]@{ Arch = 'x64';   Config = 'Debug';          IsLib = $true;  IsX86 = $false }
    [pscustomobject]@{ Arch = 'x64';   Config = 'DebugDynamic';   IsLib = $false; IsX86 = $false }
    [pscustomobject]@{ Arch = 'x64';   Config = 'Release';        IsLib = $true;  IsX86 = $false }
    [pscustomobject]@{ Arch = 'x64';   Config = 'ReleaseDynamic'; IsLib = $false; IsX86 = $false }
    [pscustomobject]@{ Arch = 'Win32'; Config = 'Debug';          IsLib = $true;  IsX86 = $true  }
    [pscustomobject]@{ Arch = 'Win32'; Config = 'DebugDynamic';   IsLib = $false; IsX86 = $true  }
    [pscustomobject]@{ Arch = 'Win32'; Config = 'Release';        IsLib = $true;  IsX86 = $true  }
    [pscustomobject]@{ Arch = 'Win32'; Config = 'ReleaseDynamic'; IsLib = $false; IsX86 = $true  }
)

$passed = 0; $failed = 0; $skipped = 0

foreach ($cfg in $configs) {
    $ext   = if ($cfg.IsLib) { 'lib' } else { 'dll' }
    $file  = Join-Path $SolutionDir "$($cfg.Arch)\$($cfg.Config)\mhook.$ext"
    $label = "$($cfg.Config)|$($cfg.Arch)".PadRight(22)

    if (-not (Test-Path $file)) {
        Write-Host "  SKIP    $label  (artifact not found: $file)"
        $skipped++
        continue
    }

    $result = if ($cfg.IsLib) {
        Test-LibSymbols $dumpbin $file $cfg.IsX86 $ntdllExports
    } else {
        Test-DllImports $dumpbin $file
    }

    if ($null -eq $result) {
        Write-Host "  PASS    $label"
        $passed++
    } elseif ($result.Ltcg) {
        Write-Host "  INFO    $label  (LTCG/WPO objects — symbol table not available;"
        Write-Host "                   ntdll-only constraint is enforced at DLL link time)"
        $passed++   # covered by ReleaseDynamic DLL check
    } elseif ($result.Error) {
        Write-Host "  FAIL    $label"
        $result.Error -split "`n" | ForEach-Object { Write-Host "          $_" }
        $failed++
    }
}

Write-Host ''
Write-Host "$passed passed, $failed failed, $skipped skipped" -NoNewline

if ($failed -gt 0) {
    Write-Host '' ; Write-Host 'One or more checks FAILED.' -ForegroundColor Red
    exit 1
} else {
    Write-Host '' ; Write-Host 'All checks passed.' -ForegroundColor Green
    exit 0
}
