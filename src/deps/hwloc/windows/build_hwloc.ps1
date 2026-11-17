# Copyright (C) 2026 Intel Corporation
# Under the Apache License v2.0 with LLVM Exceptions. See LICENSE.TXT.
# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception

# Builds the static hwloc library bundled with UMF for Windows x64 and copies
# it, together with its headers, into src/deps/hwloc.
# Requires git, CMake and Visual Studio with the x64 C/C++ build tools.

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$HwlocRepo = if ($env:HWLOC_REPO) { $env:HWLOC_REPO } else { 'https://github.com/open-mpi/hwloc.git' }
$HwlocTag = if ($env:HWLOC_TAG) { $env:HWLOC_TAG } else { 'hwloc-2.13.0' }

$ScriptDir = $PSScriptRoot
$DepsDir = Split-Path $ScriptDir -Parent
$UmfRoot = (Resolve-Path (Join-Path $ScriptDir '..\..\..\..')).Path
$TempDir = Join-Path $ScriptDir 'temp'
$SrcDir = Join-Path $TempDir 'src'
$BuildDir = Join-Path $TempDir 'build'

function Invoke-Native {
    param([string]$Exe, [string[]]$Arguments)
    & $Exe @Arguments
    if ($LASTEXITCODE -ne 0) {
        throw "'$Exe $Arguments' failed with exit code $LASTEXITCODE"
    }
}

# The windows-cmake build has no symbol prefix option, so patch the config
# templates the same way configure's --with-hwloc-symbol-prefix would.
function Set-HwlocSymbolPrefix {
    param([string]$Path)
    $content = [IO.File]::ReadAllText($Path)
    $replacements = [ordered]@{
        '(?m)^(#define HWLOC_SYM_TRANSFORM) 0(?=\r?$)'        = '$1 1'
        '(?m)^(#define HWLOC_SYM_PREFIX) hwloc_(?=\r?$)'      = '$1 umf_hwloc_'
        '(?m)^(#define HWLOC_SYM_PREFIX_CAPS) HWLOC_(?=\r?$)' = '$1 UMF_HWLOC_'
    }
    foreach ($pattern in $replacements.Keys) {
        if ($content -notmatch $pattern) {
            throw "Pattern '$pattern' not found in $Path"
        }
        $content = $content -replace $pattern, $replacements[$pattern]
    }
    [IO.File]::WriteAllText($Path, $content)
}

function Find-Dumpbin {
    $cmd = Get-Command dumpbin.exe -ErrorAction SilentlyContinue
    if ($cmd) {
        return $cmd.Source
    }
    $vswhere = Join-Path ${env:ProgramFiles(x86)} 'Microsoft Visual Studio\Installer\vswhere.exe'
    if (Test-Path $vswhere) {
        $found = & $vswhere -latest -products * -find 'VC\Tools\MSVC\**\bin\Hostx64\x64\dumpbin.exe' |
        Select-Object -First 1
        if ($found) {
            return $found
        }
    }
    throw 'dumpbin.exe not found - install the Visual Studio C++ build tools'
}

function Get-NormalizedText {
    param([string]$Path)
    return [IO.File]::ReadAllText($Path) -replace "`r`n", "`n"
}

if (Test-Path $TempDir) {
    Remove-Item -Recurse -Force $TempDir
}

try {
    Invoke-Native git @('clone', '-c', 'core.autocrlf=false', '-c', 'advice.detachedHead=false',
        '--depth', '1', '--branch', $HwlocTag, $HwlocRepo, $SrcDir)
    # The UMF checkout may have CRLF line endings, the hwloc clone has LF.
    $patch = Join-Path $TempDir 'fix_coverity_issues.patch'
    [IO.File]::WriteAllText($patch,
        (Get-NormalizedText (Join-Path $UmfRoot 'cmake\fix_coverity_issues.patch')))
    Invoke-Native git @('-C', $SrcDir, 'apply', $patch)

    Set-HwlocSymbolPrefix (Join-Path $SrcDir 'contrib\windows\hwloc_config.h')
    Set-HwlocSymbolPrefix (Join-Path $SrcDir 'contrib\windows-cmake\private_config.h.in')

    # /Zl omits the CRT name, so the archive links into both /MD and /MDd builds
    # of UMF; /Brepro makes the output reproducible. RtlGetVersionProc is a
    # global missing from hwloc's rename.h, so it is prefixed here.
    Invoke-Native cmake @('-S', (Join-Path $SrcDir 'contrib\windows-cmake'), '-B', $BuildDir,
        '-A', 'x64',
        '-DBUILD_SHARED_LIBS=OFF',
        '-DHWLOC_ENABLE_TESTING=OFF',
        '-DHWLOC_SKIP_LSTOPO=ON',
        '-DHWLOC_SKIP_TOOLS=ON',
        '-DHWLOC_SKIP_INCLUDES=ON',
        '-DCMAKE_MSVC_RUNTIME_LIBRARY=MultiThreadedDLL',
        '-DCMAKE_C_FLAGS_RELEASE=/O2 /Ob2 /DNDEBUG /Zl /Brepro /DRtlGetVersionProc=umf_hwloc_RtlGetVersionProc',
        '-DCMAKE_STATIC_LINKER_FLAGS=/Brepro')
    Invoke-Native cmake @('--build', $BuildDir, '--config', 'Release', '--parallel')

    $lib = Join-Path $BuildDir 'Release\hwloc.lib'
    $dumpbin = Find-Dumpbin
    $dump = & $dumpbin /nologo /linkermember:1 $lib
    if ($LASTEXITCODE -ne 0) {
        throw "Failed to list symbols of $lib"
    }
    # Only the block after the "N public symbols" line lists symbol names.
    $symbols = @()
    $inSymbols = $false
    foreach ($line in $dump) {
        if ($line -match '^\s*[0-9A-F]+ public symbols\s*$') {
            $inSymbols = $true
        }
        elseif ($inSymbols -and $line -match '^\s*$') {
            if ($symbols.Count -gt 0) { break }
        }
        elseif ($inSymbols -and $line -match '^\s+[0-9A-F]+\s+(\S+)\s*$') {
            $symbols += $Matches[1]
        }
    }
    if ($symbols.Count -eq 0) {
        throw "No public symbols found in $lib"
    }
    # COMDAT constants, string literals and CRT header inlines cannot conflict.
    $allowedPrefixes = '^(__real@|__xmm@|__ymm@|\?\?_C@|\?_OptionsStorage@)'
    $allowedNames = @(
        '__isa_available_default', '__local_stdio_printf_options',
        '__local_stdio_scanf_options', '_snprintf', '_vfprintf_l', '_vsnprintf',
        '_vsnprintf_l', '_vsprintf_l', '_vsscanf_l', 'fabsf', 'fprintf', 'fstat',
        'sprintf', 'sscanf', 'stat', 'vsnprintf')
    $unprefixed = @($symbols | Sort-Object -Unique | Where-Object {
            $_ -notmatch '^umf_hwloc_' -and $_ -notmatch $allowedPrefixes -and
            $_ -notin $allowedNames
        })
    if ($unprefixed.Count -gt 0) {
        throw "hwloc defines symbols without the umf_hwloc_ prefix:`n$($unprefixed -join "`n")"
    }

    Copy-Item $lib $ScriptDir -Force
    $autogenDir = Join-Path $ScriptDir 'include\hwloc\autogen'
    New-Item -ItemType Directory -Force $autogenDir | Out-Null
    Copy-Item (Join-Path $BuildDir 'include\hwloc\autogen\config.h') $autogenDir -Force

    $commonInclude = Join-Path $DepsDir 'include'
    New-Item -ItemType Directory -Force (Join-Path $commonInclude 'hwloc') | Out-Null
    Copy-Item (Join-Path $SrcDir 'include\hwloc.h') $commonInclude -Force
    Copy-Item (Join-Path $SrcDir 'include\hwloc\*.h') (Join-Path $commonInclude 'hwloc') -Force
}
finally {
    if (Test-Path $TempDir) {
        Remove-Item -Recurse -Force $TempDir
    }
}

Write-Host "Bundled hwloc ($HwlocTag) updated in $DepsDir"
