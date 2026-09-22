$ErrorActionPreference = 'Stop'
Set-Location (Split-Path -Parent $PSScriptRoot)
if (-not $IsWindows -and $env:OS -ne 'Windows_NT') {
    throw 'This build must run on Windows x64; PyInstaller does not cross-compile Windows EXEs on Linux.'
}
if (-not $env:JAVA_HOME -or -not (Test-Path "$env:JAVA_HOME\bin\javac.exe")) {
    throw 'Set JAVA_HOME to a JDK 17 installation for the Java/JAR integration smoke test (not bundled in the EXE).'
}
function Invoke-Checked {
    param([string]$Program, [string[]]$Arguments)
    & $Program @Arguments 2>&1 | Tee-Object -Variable CommandLog
    if ($LASTEXITCODE -ne 0) {
        $Code = $LASTEXITCODE
        $Details = ($CommandLog | Select-Object -Last 70 | Out-String).Replace('%', '%25').Replace("`r", '%0D').Replace("`n", '%0A')
        if ($env:GITHUB_ACTIONS) { Write-Host "::error::$Details" }
        throw "$Program failed ($Code)"
    }
}
Invoke-Checked -Program 'python' -Arguments @('-m', 'venv', '.venv-build')
$Python = Join-Path (Get-Location) '.venv-build\Scripts\python.exe'
Invoke-Checked -Program $Python -Arguments @('-m', 'pip', 'install', '-r', 'packaging/requirements-build.txt')
Invoke-Checked -Program $Python -Arguments @('-m', 'unittest', 'discover', '-s', 'tests', '-q')
Invoke-Checked -Program $Python -Arguments @('-m', 'PyInstaller', '--clean', '--noconfirm', 'packaging/ProtoHunter.spec')
Invoke-Checked -Program $Python -Arguments @('packaging/smoke_exe.py', 'dist/ProtoHunter.exe')
Copy-Item 'docs/workspaces.md' 'dist/workspaces.md' -Force
Copy-Item 'packaging/README-Windows.md' 'dist/README-Windows.md' -Force
Copy-Item 'LICENSE' 'dist/LICENSE.txt' -Force
$Hash = (Get-FileHash 'dist/ProtoHunter.exe' -Algorithm SHA256).Hash.ToLowerInvariant()
"$Hash  ProtoHunter.exe" | Set-Content 'dist/SHA256SUMS.txt' -Encoding ascii
Write-Host 'Ready: dist\ProtoHunter.exe'
