# Copyright (C) 2023-2024 Intel Corporation
# Under the Apache License v2.0 with LLVM Exceptions. See LICENSE.TXT.
# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception

# Invoke-CmdScript runs a command script and updates the current environment 
# with any flag changes set by the script.
function Invoke-CmdScript {
  param(
    [String] $scriptName
  )
  $cmdLine = """$scriptName"" $args & set"
  & $Env:SystemRoot\system32\cmd.exe /c $cmdLine |
  select-string '^([^=]*)=(.*)$' | foreach-object {
    $varName = $_.Matches[0].Groups[1].Value
    $varValue = $_.Matches[0].Groups[2].Value
    set-item Env:$varName $varValue
  }
}

# Get the path to vcvarsall.bat
$vsPath = & "${env:ProgramFiles(x86)}\Microsoft Visual Studio\Installer\vswhere.exe" `
  -latest -products * -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 `
  -property installationPath
$vsPath = "$vsPath\VC\Auxiliary\Build"
$vcvarsall = "${vsPath}\vcvarsall.bat"
echo "Visual Studio path: $vsPath"
echo "vcvarsall.bat path: $vcvarsall"

# Call vcvarsall.bat so we can run MSVC commands
echo "Setting up MSVC environment..."
Invoke-CmdScript "$vcvarsall" x86

# Get umf.dll configuration flags and check if DEPENDENTLOADFLAG is set to 0x2000
$flags = & "${env:VCToolsInstallDir}\bin\Hostx64\x64\dumpbin.exe" /LOADCONFIG "$args"
if (($flags | Where-Object { $_ -match '(\d+).*Dependent' } | ForEach-Object { $matches[1] } ) -eq "2000") { 
  echo "The DEPENDENTLOADFLAG is correctly set to 0x2000."
  exit 0
} else {
  echo "The DEPENDENTLOADFLAG is not correctly set"
  echo "$flags"
  exit 1
}
