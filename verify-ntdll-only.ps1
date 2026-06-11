<#
.SYNOPSIS
    Verifies that all 8 mhook build outputs depend solely on ntdll.dll.

.DESCRIPTION
    Checks all platform/configuration combinations:

    DLL outputs (DebugDynamic, ReleaseDynamic x x64, Win32):
        Reads the PE import table via dumpbin /imports and fails if any DLL
        other than ntdll.dll appears.

    Static lib outputs (Debug, Release x x64, Win32):
        Links the .lib into a temporary DLL using only ntdll.lib and
        ntdll_extra.lib, then inspects that DLL's import table.  This works
        for both normal and LTCG/WPO (/GL) objects and catches dependencies
        independently of the DLL configurations.

    x86 decoration rules used when reporting unresolved symbols from the
    link step:
        _Name@N  (stdcall)  ->  Name
        _Name    (cdecl)    ->  Name

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
# Locate VS tools using the canonical vswhere method (see
# https://github.com/microsoft/vswhere/wiki/Find-VC):
#   1. vswhere gives the VS installation path.
#   2. VC\Auxiliary\Build\Microsoft.VCToolsVersion.default.txt contains the
#      exact toolset version string that matches what the build actually used.
#   3. Tools live at VC\Tools\MSVC\<version>\bin\Host<host>\<target>\<tool>.
#
# dumpbin and the x64-targeting link.exe are from Hostx64\x64.
# The x86-targeting link.exe comes from Hostx64\x86 (cross: host x64 -> x86).
# Using the version from the .txt file is critical for LTCG: the linker
# back-end (c2.exe / P2) must match the front-end version baked into the
# .obj files, or you get C1900 "Il mismatch between P1 and P2".
# ---------------------------------------------------------------------------
function Find-VsTools {
    $vsWhere = Join-Path ${env:ProgramFiles(x86)} 'Microsoft Visual Studio\Installer\vswhere.exe'
    if (-not (Test-Path $vsWhere)) { throw "vswhere.exe not found at $vsWhere" }

    $vsPath = & $vsWhere -latest -products * `
        -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 `
        -property installationPath 2>$null

    if (-not $vsPath) { throw "vswhere: no VS installation with VC tools found" }

    $versionFile = Join-Path $vsPath 'VC\Auxiliary\Build\Microsoft.VCToolsVersion.default.txt'
    if (-not (Test-Path $versionFile)) { throw "Toolset version file not found: $versionFile" }

    $toolsVersion = (Get-Content $versionFile -Raw).Trim()
    $hostBin = Join-Path $vsPath "VC\Tools\MSVC\$toolsVersion\bin\Hostx64"

    return @{
        Dumpbin = Join-Path $hostBin 'x64\dumpbin.exe'
        LinkX64 = Join-Path $hostBin 'x64\link.exe'   # native x64
        LinkX86 = Join-Path $hostBin 'x86\link.exe'   # cross: host x64, target x86
    }
}

# ---------------------------------------------------------------------------
# Locate the Windows SDK ntdll.lib for a given architecture
# ---------------------------------------------------------------------------
function Find-SdkNtdllLib([string]$Arch) {
    $libArch = if ($Arch -eq 'x64') { 'x64' } else { 'x86' }

    # Prefer the registry-provided kits root; fall back to the standard path.
    $kitsRoot = (Get-ItemProperty `
        'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows Kits\Installed Roots' `
        -ErrorAction SilentlyContinue).'KitsRoot10'
    if (-not $kitsRoot) {
        $kitsRoot = 'C:\Program Files (x86)\Windows Kits\10\'
    }

    $lib = Get-ChildItem (Join-Path $kitsRoot 'Lib') 'ntdll.lib' -Recurse `
               -ErrorAction SilentlyContinue |
           Where-Object { $_.DirectoryName -like "*\um\$libArch" } |
           Sort-Object { $_.DirectoryName } -Descending |
           Select-Object -First 1 -ExpandProperty FullName

    if (-not $lib) { throw "SDK ntdll.lib not found for $Arch under $kitsRoot" }
    return $lib
}

# ---------------------------------------------------------------------------
# Build a set of ntdll.dll export names
# ---------------------------------------------------------------------------
function Get-NtdllExports([string]$Dumpbin) {
    $set = [System.Collections.Generic.HashSet[string]]::new(
                [System.StringComparer]::OrdinalIgnoreCase)

    & $Dumpbin /exports C:\Windows\System32\ntdll.dll 2>$null | ForEach-Object {
        # "  ordinal  hint  XXXXXXXX  name"  — RVA is exactly 8 hex digits
        if ($_ -match '^\s+\d+\s+[0-9A-Fa-f]+\s+[0-9A-Fa-f]{8}\s+(\S+)\s*$') {
            $null = $set.Add($Matches[1])
        }
    }

    if ($set.Count -eq 0) { throw "Failed to parse any exports from ntdll.dll" }
    return $set
}

# ---------------------------------------------------------------------------
# Strip x86 calling-convention decoration for display purposes
# ---------------------------------------------------------------------------
function Undecorate([string]$sym, [bool]$IsX86) {
    if (-not $IsX86) { return $sym }
    if ($sym -match '^_(.+)@\d+$') { return $Matches[1] }
    if ($sym -match '^_(.+)$')     { return $Matches[1] }
    return $sym
}

# ---------------------------------------------------------------------------
# DLL check — import table must reference only ntdll.dll
# ---------------------------------------------------------------------------
function Test-DllImports([string]$Dumpbin, [string]$Path, [string[]]$AllowImports = @('ntdll.dll')) {
    $out = & $Dumpbin /imports $Path 2>$null

    # Import section headers: "    somedll.dll"  (4 spaces, name, nothing else)
    $dlls = $out |
        Where-Object { $_ -match '^\s{4}(\S+\.dll)\s*$' } |
        ForEach-Object { [IO.Path]::GetFileName($Matches[1]).ToLower() }

    if (-not $dlls) {
        return "no DLL imports found in import table — unexpected"
    }

    $allowed = $AllowImports | ForEach-Object { $_.ToLower() }
    $foreign = @($dlls | Where-Object { $_ -notin $allowed })
    if ($foreign.Count -gt 0) {
        return "imports from disallowed DLL(s): $($foreign -join ', ') (allowed: $($allowed -join ', '))"
    }
    return $null   # pass
}

# ---------------------------------------------------------------------------
# Static lib check — link the lib against only ntdll and inspect the result.
#
# Works for both normal and LTCG/WPO (/GL) objects, giving an independent
# check that does not rely on the DLL configurations being unchanged.
# ---------------------------------------------------------------------------
function Test-LibByLinking(
    [string]$Dumpbin,
    [string]$LinkX64,
    [string]$LinkX86,
    [string]$LibPath,
    [string]$Arch,
    [string]$SdkNtdllLib,
    [string]$NtdllExtraLib,
    [string[]]$Exports = @('Mhook_SetHook', 'Mhook_Unhook'),
    [string[]]$AdditionalLibs = @())
{
    $machine = if ($Arch -eq 'x64') { 'X64' } else { 'X86' }
    $link    = if ($Arch -eq 'x64') { $LinkX64 } else { $LinkX86 }
    $isX86   = $Arch -ne 'x64'

    $tempDir  = Join-Path ([IO.Path]::GetTempPath()) ("mhook-verify-" + [IO.Path]::GetRandomFileName())
    $tempDll  = Join-Path $tempDir 'check.dll'
    $tempImp  = Join-Path $tempDir 'check.lib'   # discard; required by link.exe

    $null = New-Item -ItemType Directory -Path $tempDir -Force

    try {
        # Export the public API so the linker has roots to keep.  Without at
        # least one export, dead-code elimination removes all code (there are
        # no other roots in a /NOENTRY DLL) and the import table ends up empty.
        $linkArgs = @(
            '/DLL', '/NOENTRY', '/NODEFAULTLIB',
            ($Exports | ForEach-Object { "/EXPORT:$_" }),
            "/MACHINE:$machine",
            "/OUT:$tempDll",
            "/IMPLIB:$tempImp",
            $LibPath,
            $SdkNtdllLib,
            $NtdllExtraLib
        ) + $AdditionalLibs

        $linkOut = & $link @linkArgs 2>&1
        $linkOk  = $LASTEXITCODE -eq 0

        if (-not $linkOk) {
            # Surface all diagnostic lines: any compiler/linker error code
            # ([A-Z]\d{4}), "fatal error" prose, or generic "error:" lines.
            $errors = @($linkOut |
                Where-Object { $_ -match '(?i)\b(fatal\s+)?error\b' -or $_ -match '[A-Z]\d{4}' } |
                Select-Object -Unique |
                ForEach-Object {
                    # Undecorate symbol names in the message for readability.
                    $line = $_ -replace 'unresolved external symbol\s+(\S+)',
                        { "unresolved external symbol " + (Undecorate $_.Groups[1].Value $isX86) }
                    "  $($line.Trim())"
                })
            return "link.exe failed:`n" + ($errors -join "`n")
        }

        # Link succeeded — verify no non-ntdll DLL crept in.
        return Test-DllImports $Dumpbin $tempDll
    }
    finally {
        Remove-Item $tempDir -Recurse -Force -ErrorAction SilentlyContinue
    }
}

# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------
try   { $tools = Find-VsTools } catch { Write-Error $_.Exception.Message; exit 1 }
$dumpbin = $tools.Dumpbin
$linkX64 = $tools.LinkX64
$linkX86 = $tools.LinkX86

foreach ($exe in @($dumpbin, $linkX64, $linkX86)) {
    if (-not (Test-Path $exe)) { Write-Error "Tool not found: $exe"; exit 1 }
}

try { $ntdllExports = Get-NtdllExports $dumpbin } catch { Write-Error $_.Exception.Message; exit 1 }

Write-Host "dumpbin : $dumpbin"
Write-Host "link x64: $linkX64"
Write-Host "link x86: $linkX86"
Write-Host "ntdll   : $($ntdllExports.Count) named exports"
Write-Host ''

$configs = @(
    # libmhook — static: exports Mhook_SetHook + Mhook_Unhook; no extra link inputs
    [pscustomobject]@{ Project='libmhook';    BaseName='mhook';        Arch='x64';   Config='Debug';          IsLib=$true;  IsX86=$false; Exports=@('Mhook_SetHook','Mhook_Unhook'); NeedsMhook=$false }
    [pscustomobject]@{ Project='libmhook';    BaseName='mhook';        Arch='x64';   Config='DebugDynamic';   IsLib=$false; IsX86=$false; Exports=@();                               NeedsMhook=$false }
    [pscustomobject]@{ Project='libmhook';    BaseName='mhook';        Arch='x64';   Config='Release';        IsLib=$true;  IsX86=$false; Exports=@('Mhook_SetHook','Mhook_Unhook'); NeedsMhook=$false }
    [pscustomobject]@{ Project='libmhook';    BaseName='mhook';        Arch='x64';   Config='ReleaseDynamic'; IsLib=$false; IsX86=$false; Exports=@();                               NeedsMhook=$false }
    [pscustomobject]@{ Project='libmhook';    BaseName='mhook';        Arch='Win32'; Config='Debug';          IsLib=$true;  IsX86=$true;  Exports=@('Mhook_SetHook','Mhook_Unhook'); NeedsMhook=$false }
    [pscustomobject]@{ Project='libmhook';    BaseName='mhook';        Arch='Win32'; Config='DebugDynamic';   IsLib=$false; IsX86=$true;  Exports=@();                               NeedsMhook=$false }
    [pscustomobject]@{ Project='libmhook';    BaseName='mhook';        Arch='Win32'; Config='Release';        IsLib=$true;  IsX86=$true;  Exports=@('Mhook_SetHook','Mhook_Unhook'); NeedsMhook=$false }
    [pscustomobject]@{ Project='libmhook';    BaseName='mhook';        Arch='Win32'; Config='ReleaseDynamic'; IsLib=$false; IsX86=$true;  Exports=@();                               NeedsMhook=$false }

    # mhook_inject — static: exports Mhook_Inject; also links mhook.lib to resolve
    #                SetHook/Unhook used by inject_entry.c in static builds
    [pscustomobject]@{ Project='mhook_inject'; BaseName='mhook_inject'; Arch='x64';   Config='Debug';          IsLib=$true;  IsX86=$false; Exports=@('Mhook_Inject'); NeedsMhook=$true  }
    [pscustomobject]@{ Project='mhook_inject'; BaseName='mhook_inject'; Arch='x64';   Config='DebugDynamic';   IsLib=$false; IsX86=$false; Exports=@();               NeedsMhook=$false }
    [pscustomobject]@{ Project='mhook_inject'; BaseName='mhook_inject'; Arch='x64';   Config='Release';        IsLib=$true;  IsX86=$false; Exports=@('Mhook_Inject'); NeedsMhook=$true  }
    [pscustomobject]@{ Project='mhook_inject'; BaseName='mhook_inject'; Arch='x64';   Config='ReleaseDynamic'; IsLib=$false; IsX86=$false; Exports=@();               NeedsMhook=$false }
    [pscustomobject]@{ Project='mhook_inject'; BaseName='mhook_inject'; Arch='Win32'; Config='Debug';          IsLib=$true;  IsX86=$true;  Exports=@('Mhook_Inject'); NeedsMhook=$true; NeedsSeh3=$true  }
    [pscustomobject]@{ Project='mhook_inject'; BaseName='mhook_inject'; Arch='Win32'; Config='DebugDynamic';   IsLib=$false; IsX86=$true;  Exports=@();               NeedsMhook=$false }
    [pscustomobject]@{ Project='mhook_inject'; BaseName='mhook_inject'; Arch='Win32'; Config='Release';        IsLib=$true;  IsX86=$true;  Exports=@('Mhook_Inject'); NeedsMhook=$true; NeedsSeh3=$true  }
    [pscustomobject]@{ Project='mhook_inject'; BaseName='mhook_inject'; Arch='Win32'; Config='ReleaseDynamic'; IsLib=$false; IsX86=$true;  Exports=@();               NeedsMhook=$false }

    # mhook_inject_proxy (x64-only) — the native 32->64 proxy, built per flavour.
    #   .exe static (Debug/Release): self-contained → imports only ntdll.dll.
    #   .exe dynamic (DebugDynamic/ReleaseDynamic): imports ntdll.dll + mhook_inject.dll
    #        (both of which are themselves verified ntdll-only by their own rows).
    #   .lib (Debug/Release): the consumer deliverable; links mhook_inject.lib + mhook.lib
    #        → resolves to ntdll only.
    # (All Win32 configs, and the dynamic LIB configs, are Utility no-ops — no artifact.)
    [pscustomobject]@{ Project='mhook_inject_proxy';     BaseName='mhook_inject_proxy'; Arch='x64'; Config='Debug';          IsLib=$false; IsX86=$false; Ext='exe'; Exports=@();                       NeedsMhook=$false }
    [pscustomobject]@{ Project='mhook_inject_proxy';     BaseName='mhook_inject_proxy'; Arch='x64'; Config='Release';        IsLib=$false; IsX86=$false; Ext='exe'; Exports=@();                       NeedsMhook=$false }
    [pscustomobject]@{ Project='mhook_inject_proxy';     BaseName='mhook_inject_proxy'; Arch='x64'; Config='DebugDynamic';   IsLib=$false; IsX86=$false; Ext='exe'; AllowImports=@('ntdll.dll','mhook_inject.dll'); Exports=@(); NeedsMhook=$false }
    [pscustomobject]@{ Project='mhook_inject_proxy';     BaseName='mhook_inject_proxy'; Arch='x64'; Config='ReleaseDynamic'; IsLib=$false; IsX86=$false; Ext='exe'; AllowImports=@('ntdll.dll','mhook_inject.dll'); Exports=@(); NeedsMhook=$false }
    [pscustomobject]@{ Project='mhook_inject_proxy_lib'; BaseName='mhook_inject_proxy'; Arch='x64'; Config='Debug';          IsLib=$true;  IsX86=$false;            Exports=@('MhookInjectProxyMain'); NeedsMhook=$true; NeedsInject=$true }
    [pscustomobject]@{ Project='mhook_inject_proxy_lib'; BaseName='mhook_inject_proxy'; Arch='x64'; Config='Release';        IsLib=$true;  IsX86=$false;            Exports=@('MhookInjectProxyMain'); NeedsMhook=$true; NeedsInject=$true }
)

# Cache SDK ntdll.lib paths per architecture (looked up on first use).
$sdkLibCache = @{}

$passed = 0; $failed = 0; $skipped = 0

foreach ($cfg in $configs) {
    $ext   = if ($cfg.IsLib) { 'lib' }
             elseif ($cfg.PSObject.Properties.Name -contains 'Ext') { $cfg.Ext }
             else { 'dll' }
    $file  = Join-Path $SolutionDir build artifacts $cfg.Project $cfg.Arch $cfg.Config "$($cfg.BaseName).$ext"
    $label = "$($cfg.Project) $($cfg.Config)|$($cfg.Arch)".PadRight(38)

    if (-not (Test-Path $file)) {
        Write-Host "  SKIP    $label  (artifact not found)"
        $skipped++
        continue
    }

    if ($cfg.IsLib) {
        # Locate SDK ntdll.lib (cached per architecture).
        if (-not $sdkLibCache.ContainsKey($cfg.Arch)) {
            try   { $sdkLibCache[$cfg.Arch] = Find-SdkNtdllLib $cfg.Arch }
            catch { Write-Error $_.Exception.Message; exit 1 }
        }
        $sdkNtdll      = $sdkLibCache[$cfg.Arch]
        $ntdllExtraLib = Join-Path $SolutionDir build artifacts ntdll_extra_stub "$($cfg.Arch)\$($cfg.Config)\ntdll_extra.lib"

        if (-not (Test-Path $ntdllExtraLib)) {
            Write-Host "  SKIP    $label  (ntdll_extra.lib not found)"
            $skipped++
            continue
        }

        # mhook_inject static builds reference Mhook_SetHook/Unhook from mhook.lib
        $extraLibs = @()
        if ($cfg.NeedsMhook) {
            $mhookLib = Join-Path $SolutionDir build artifacts libmhook "$($cfg.Arch)\$($cfg.Config)\mhook.lib"
            if (-not (Test-Path $mhookLib)) {
                Write-Host "  SKIP    $label  (mhook.lib not found)"
                $skipped++
                continue
            }
            $extraLibs = @($mhookLib)
        }

        # mhook_inject_proxy_lib references Mhook_Inject from mhook_inject.lib.
        if (($cfg.PSObject.Properties.Name -contains 'NeedsInject') -and $cfg.NeedsInject) {
            $injectLib = Join-Path $SolutionDir build artifacts mhook_inject "$($cfg.Arch)\$($cfg.Config)\mhook_inject.lib"
            if (-not (Test-Path $injectLib)) {
                Write-Host "  SKIP    $label  (mhook_inject.lib not found)"
                $skipped++
                continue
            }
            $extraLibs += $injectLib
        }

        # x86 mhook_inject static: inject_entry.c's __try needs our self-provided
        # _except_handler3 + SafeSEH load-config from mhook_seh3.lib (ntdll-only).
        # (-contains short-circuits before $cfg.NeedsSeh3 under StrictMode.)
        if (($cfg.PSObject.Properties.Name -contains 'NeedsSeh3') -and $cfg.NeedsSeh3) {
            $seh3Lib = Join-Path $SolutionDir build artifacts mhook_seh3 "$($cfg.Arch)\$($cfg.Config)\mhook_seh3.lib"
            if (-not (Test-Path $seh3Lib)) {
                Write-Host "  SKIP    $label  (mhook_seh3.lib not found)"
                $skipped++
                continue
            }
            $extraLibs += $seh3Lib
        }

        $err = Test-LibByLinking $dumpbin $linkX64 $linkX86 $file $cfg.Arch $sdkNtdll $ntdllExtraLib `
                                 -Exports $cfg.Exports -AdditionalLibs $extraLibs
    } else {
        $allow = if ($cfg.PSObject.Properties.Name -contains 'AllowImports') { $cfg.AllowImports }
                 else { @('ntdll.dll') }
        $err = Test-DllImports $dumpbin $file -AllowImports $allow
    }

    if ($err) {
        Write-Host "  FAIL    $label"
        $err -split "`n" | ForEach-Object { Write-Host "          $_" }
        $failed++
    } else {
        Write-Host "  PASS    $label"
        $passed++
    }
}

Write-Host ''
Write-Host "$passed passed, $failed failed, $skipped skipped" -NoNewline

if ($failed -gt 0) {
    Write-Host ''; Write-Host 'One or more checks FAILED.' -ForegroundColor Red
    exit 1
} else {
    Write-Host ''; Write-Host 'All checks passed.' -ForegroundColor Green
    exit 0
}
