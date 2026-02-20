#requires -Version 5.1

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"
$ProgressPreference = "SilentlyContinue"

# Colors
$Cyan = [char]27 + "[96m"
$Red = [char]27 + "[91m"
$Green = [char]27 + "[92m"
$Yellow = [char]27 + "[93m"
$Default = [char]27 + "[0m"

# Legends
$InfoS = "$Cyan[$Yellow*$Cyan]$Default"
$OkS = "$Cyan[$Green+$Cyan]$Default"
$ErrS = "$Cyan[$Red!$Cyan]$Default"
$script:OllamaSigninNoticeShown = $false

function Write-Info([string]$Message) { Write-Host "$InfoS $Message" }
function Write-Ok([string]$Message) { Write-Host "$OkS $Message" }
function Write-Err([string]$Message) { Write-Host "$ErrS $Message" }

function Write-OllamaSigninNotice([string]$ModelName) {
    if ($script:OllamaSigninNoticeShown) {
        return
    }
    $script:OllamaSigninNoticeShown = $true

    Write-Err "================ OLLAMA CLOUD AUTH NOTICE ================"
    Write-Err "This setup uses a cloud Ollama model and may require login."
    Write-Err "Run: ollama signin"
    if (-not [string]::IsNullOrWhiteSpace($ModelName)) {
        Write-Info "After sign-in, pull the model: ollama pull $ModelName"
    }
    Write-Err "=========================================================="
}

function Invoke-NativeCommandCapture([string]$FilePath, [string[]]$Arguments) {
    $output = @()
    $exitCode = 1
    if ([string]::IsNullOrWhiteSpace($FilePath)) {
        return [PSCustomObject]@{
            ExitCode = 127
            Output   = @("Executable path is empty.")
        }
    }

    $looksLikePath =
        [System.IO.Path]::IsPathRooted($FilePath) -or
        ($FilePath -like "*\*") -or
        ($FilePath -like "*/*")
    if ($looksLikePath -and (-not (Test-Path -LiteralPath $FilePath))) {
        return [PSCustomObject]@{
            ExitCode = 127
            Output   = @("Executable not found: $FilePath")
        }
    }

    $prevPreference = $ErrorActionPreference
    try {
        # Some tools (notably pip) write useful diagnostics to stderr even when we want to handle failures ourselves.
        $ErrorActionPreference = "Continue"
        try {
            $output = & $FilePath @Arguments 2>&1
        } catch {
            $output = @($_.Exception.Message)
            $exitCode = 127
            return [PSCustomObject]@{
                ExitCode = $exitCode
                Output   = @($output)
            }
        }
        $exitCode = $LASTEXITCODE
        if ($null -eq $exitCode) {
            $exitCode = 0
        }
    } finally {
        $ErrorActionPreference = $prevPreference
    }

    return [PSCustomObject]@{
        ExitCode = $exitCode
        Output   = @($output)
    }
}

function Invoke-ProcessWithTimeoutCapture([string]$FilePath, [string[]]$Arguments, [int]$TimeoutSeconds = 0) {
    $output = @()
    $exitCode = 1
    $timedOut = $false

    if ([string]::IsNullOrWhiteSpace($FilePath)) {
        return [PSCustomObject]@{
            ExitCode = 127
            TimedOut = $false
            Output   = @("Executable path is empty.")
        }
    }
    if ([System.IO.Path]::IsPathRooted($FilePath) -and (-not (Test-Path -LiteralPath $FilePath))) {
        return [PSCustomObject]@{
            ExitCode = 127
            TimedOut = $false
            Output   = @("Executable not found: $FilePath")
        }
    }

    $tmpDir = Join-Path ([System.IO.Path]::GetTempPath()) ("cmd-out-{0}" -f ([guid]::NewGuid().ToString("N")))
    Ensure-Directory $tmpDir
    $stdoutPath = Join-Path $tmpDir "stdout.txt"
    $stderrPath = Join-Path $tmpDir "stderr.txt"

    try {
        $proc = Start-Process -FilePath $FilePath -ArgumentList $Arguments -PassThru -NoNewWindow -RedirectStandardOutput $stdoutPath -RedirectStandardError $stderrPath
        if ($TimeoutSeconds -gt 0) {
            if (-not $proc.WaitForExit($TimeoutSeconds * 1000)) {
                $timedOut = $true
                try { $proc.Kill() } catch {}
            } else {
                $exitCode = $proc.ExitCode
            }
        } else {
            $proc.WaitForExit()
            $exitCode = $proc.ExitCode
        }

        if ($timedOut) {
            $exitCode = 124
        }
    } catch {
        $output = @($_.Exception.Message)
        return [PSCustomObject]@{
            ExitCode = 127
            TimedOut = $false
            Output   = @($output)
        }
    } finally {
        if (Test-Path -LiteralPath $stdoutPath) {
            $output += Get-Content -LiteralPath $stdoutPath -ErrorAction SilentlyContinue
        }
        if (Test-Path -LiteralPath $stderrPath) {
            $output += Get-Content -LiteralPath $stderrPath -ErrorAction SilentlyContinue
        }
        if (Test-Path -LiteralPath $tmpDir) { Remove-Item -LiteralPath $tmpDir -Force -Recurse }
    }

    return [PSCustomObject]@{
        ExitCode = $exitCode
        TimedOut = $timedOut
        Output   = @($output)
    }
}

function Get-PythonExecutable() {
    if (-not [string]::IsNullOrWhiteSpace($script:PythonExe)) {
        if ([System.IO.Path]::IsPathRooted($script:PythonExe) -and (-not (Test-Path -LiteralPath $script:PythonExe))) {
            $script:PythonExe = $null
        } else {
            return $script:PythonExe
        }
    }
    if (-not [string]::IsNullOrWhiteSpace($script:PythonExe)) {
        return $script:PythonExe
    }
    $cmd = Get-Command python -ErrorAction SilentlyContinue
    if (($null -ne $cmd) -and (-not [string]::IsNullOrWhiteSpace($cmd.Source))) {
        return $cmd.Source
    }
    return "python"
}

function Resolve-UsablePython() {
    $candidates = @()

    $cmd = Get-Command python -ErrorAction SilentlyContinue
    if (($null -ne $cmd) -and (-not [string]::IsNullOrWhiteSpace($cmd.Source))) {
        $candidates += $cmd.Source
    }

    $knownCandidates = @(
        (Join-Path $env:LOCALAPPDATA "Microsoft\\WindowsApps\\python.exe"),
        (Join-Path $env:LOCALAPPDATA "Programs\\Python\\Python312\\python.exe"),
        (Join-Path $env:LOCALAPPDATA "Programs\\Python\\Python311\\python.exe"),
        (Join-Path $env:ProgramFiles "Python312\\python.exe"),
        (Join-Path $env:ProgramFiles "Python311\\python.exe"),
        (Join-Path ${env:ProgramFiles(x86)} "Python312\\python.exe"),
        (Join-Path ${env:ProgramFiles(x86)} "Python311\\python.exe")
    ) | Where-Object { $_ }
    $candidates += $knownCandidates

    $searchBases = @(
        (Join-Path $env:LOCALAPPDATA "Programs\\Python"),
        $env:ProgramFiles,
        ${env:ProgramFiles(x86)}
    ) | Where-Object { $_ -and (Test-Path -LiteralPath $_) }

    foreach ($base in $searchBases) {
        $pythonDirs = Get-ChildItem -LiteralPath $base -Directory -Filter "Python*" -ErrorAction SilentlyContinue
        foreach ($dir in $pythonDirs) {
            $exe = Join-Path $dir.FullName "python.exe"
            if (Test-Path -LiteralPath $exe) {
                $candidates += $exe
            }
        }
    }

    $uniqueCandidates = @(
        $candidates |
            Where-Object {
                if ([string]::IsNullOrWhiteSpace($_)) { return $false }
                if ([System.IO.Path]::IsPathRooted($_)) { return (Test-Path -LiteralPath $_) }
                return $true
            } |
            Select-Object -Unique
    )
    foreach ($candidate in $uniqueCandidates) {
        $probe = Invoke-NativeCommandCapture -FilePath $candidate -Arguments @("-c", "import sys; print('%d.%d' % sys.version_info[:2])")
        if ($probe.ExitCode -ne 0) {
            continue
        }
        $ver = (($probe.Output | ForEach-Object { $_.ToString().Trim() } | Where-Object { $_ }) | Select-Object -Last 1)
        if ($ver -match "^\d+\.\d+$") {
            return [PSCustomObject]@{
                Path    = $candidate
                Version = $ver
            }
        }
    }

    return $null
}

function Ensure-Directory([string]$Path) {
    if (-not (Test-Path -LiteralPath $Path)) {
        $null = New-Item -ItemType Directory -Path $Path -Force
    }
}

function Get-NormalizedPath([string]$Path) {
    if ([string]::IsNullOrWhiteSpace($Path)) {
        return ""
    }
    $full = $Path
    try {
        $full = [System.IO.Path]::GetFullPath($Path)
    } catch {
        $full = $Path
    }
    return $full.TrimEnd("\")
}

function Ensure-PathEntry([string]$PathToAdd, [ValidateSet("Process", "User")] [string]$Scope) {
    $normalizedToAdd = Get-NormalizedPath -Path $PathToAdd
    if ([string]::IsNullOrWhiteSpace($normalizedToAdd)) {
        return $false
    }

    $currentPath = if ($Scope -eq "Process") { $env:PATH } else { [Environment]::GetEnvironmentVariable("Path", "User") }
    $entries = @()
    if (-not [string]::IsNullOrWhiteSpace($currentPath)) {
        $entries = @($currentPath -split ";" | Where-Object { -not [string]::IsNullOrWhiteSpace($_) })
    }

    foreach ($entry in $entries) {
        if ((Get-NormalizedPath -Path $entry) -ieq $normalizedToAdd) {
            return $false
        }
    }

    $newPath = if ($entries.Length -gt 0) { "$PathToAdd;$($entries -join ';')" } else { $PathToAdd }
    if ($Scope -eq "Process") {
        $env:PATH = $newPath
    } else {
        [Environment]::SetEnvironmentVariable("Path", $newPath, "User")
    }
    return $true
}

function Invoke-Download([string]$Uri, [string]$OutFile) {
    # Prefer Invoke-WebRequest (available on both Windows PowerShell and PowerShell 7+).
    $iwr = Get-Command Invoke-WebRequest -ErrorAction SilentlyContinue
    if ($null -eq $iwr) {
        throw "Invoke-WebRequest is not available on this system."
    }

    # -UseBasicParsing exists only on Windows PowerShell.
    $params = @{
        Uri     = $Uri
        OutFile = $OutFile
    }
    if ($iwr.Parameters.ContainsKey("UseBasicParsing")) {
        $params["UseBasicParsing"] = $true
    }
    Invoke-WebRequest @params | Out-Null
}

function Test-JadxInstall([string]$JadxDir, [string]$JadxVersion) {
    $launcher = Join-Path $JadxDir "bin\\jadx.bat"
    $jarCli = Join-Path $JadxDir ("lib\\jadx-cli-{0}.jar" -f $JadxVersion)
    $jarAll = Join-Path $JadxDir ("lib\\jadx-{0}-all.jar" -f $JadxVersion)
    return ((Test-Path -LiteralPath $launcher) -and ((Test-Path -LiteralPath $jarCli) -or (Test-Path -LiteralPath $jarAll)))
}

function Update-IniLine([string]$Path, [string]$Key, [string]$Value) {
    if (-not (Test-Path -LiteralPath $Path)) {
        throw "File not found: $Path"
    }
    $lines = Get-Content -LiteralPath $Path -ErrorAction Stop
    $updated = $false
    $out = foreach ($line in $lines) {
        if ($line -match ("^\s*{0}\s*=" -f [regex]::Escape($Key))) {
            $updated = $true
            "{0} = {1}" -f $Key, $Value
        } else {
            $line
        }
    }
    if (-not $updated) {
        $out += ("{0} = {1}" -f $Key, $Value)
    }
    $utf8NoBom = New-Object System.Text.UTF8Encoding($false)
    [System.IO.File]::WriteAllLines($Path, [string[]]$out, $utf8NoBom)
}

function Ensure-Python() {
    $py = Resolve-UsablePython
    if ($null -eq $py) {
        Write-Info "Python not found. Installing Python 3.12 via winget..."
        $null = Ensure-Winget
        $pyInstall = Invoke-NativeCommandCapture -FilePath "winget" -Arguments @(
            "install",
            "-e",
            "--id", "Python.Python.3.12",
            "--scope", "user",
            "--accept-package-agreements",
            "--accept-source-agreements"
        )
        if ($pyInstall.ExitCode -ne 0) {
            $outText = ($pyInstall.Output | ForEach-Object { $_.ToString() }) -join "`n"
            throw "Python installation via winget failed.`n$outText"
        }

        $windowsApps = Join-Path $env:LOCALAPPDATA "Microsoft\\WindowsApps"
        if (Test-Path -LiteralPath $windowsApps) {
            $null = Ensure-PathEntry -PathToAdd $windowsApps -Scope "Process"
            $null = Ensure-PathEntry -PathToAdd $windowsApps -Scope "User"
        }

        $py = Resolve-UsablePython
        if ($null -eq $py) {
            throw "Python installation attempted but a usable python.exe was not found. Restart terminal and re-run setup."
        }
    }

    $script:PythonExe = $py.Path
    $pythonDir = Split-Path -Parent $script:PythonExe
    if (-not [string]::IsNullOrWhiteSpace($pythonDir)) {
        $null = Ensure-PathEntry -PathToAdd $pythonDir -Scope "Process"
        $null = Ensure-PathEntry -PathToAdd $pythonDir -Scope "User"
        $pythonScriptsDir = Join-Path $pythonDir "Scripts"
        if (Test-Path -LiteralPath $pythonScriptsDir) {
            $null = Ensure-PathEntry -PathToAdd $pythonScriptsDir -Scope "Process"
            $null = Ensure-PathEntry -PathToAdd $pythonScriptsDir -Scope "User"
        }
    }

    $ver = $py.Version
    if ([string]::IsNullOrWhiteSpace($ver) -or (-not ($ver -match "^\d+\.\d+$"))) {
        throw "Python version probe returned an invalid value: '$ver'"
    }
    $majorMinor = $ver.Split(".")
    $maj = [int]$majorMinor[0]
    $min = [int]$majorMinor[1]
    if (($maj -lt 3) -or (($maj -eq 3) -and ($min -lt 10))) {
        throw "Python 3.10+ is required. Found: $ver"
    }

    # Ensure pip
    $pipProbe = Invoke-NativeCommandCapture -FilePath (Get-PythonExecutable) -Arguments @("-m", "pip", "--version")
    if ($pipProbe.ExitCode -ne 0) {
        $pipText = ($pipProbe.Output | ForEach-Object { $_.ToString() }) -join "`n"
        throw "pip is not available for Python at $($script:PythonExe).`n$pipText"
    }
}

function Ensure-PythonRequirements([string]$RepoRoot) {
    $req = Join-Path $RepoRoot "requirements.txt"
    if (-not (Test-Path -LiteralPath $req)) {
        throw "requirements.txt not found in: $RepoRoot"
    }
    $lines = Get-Content -LiteralPath $req
    $hasYaraDependency = $false
    foreach ($line in $lines) {
        $trimmed = $line.Trim()
        if ($trimmed -match "^\s*yara-python(\s|=|>|<|!|~|$)") {
            $hasYaraDependency = $true
            break
        }
    }

    Write-Info "Installing python modules from requirements.txt..."
    $installResult = Invoke-NativeCommandCapture -FilePath (Get-PythonExecutable) -Arguments @("-m", "pip", "install", "-r", $req)
    $installOut = $installResult.Output
    if ($installResult.ExitCode -eq 0) {
        Write-Ok "Python modules installed."
        return
    }

    $installText = ($installOut | ForEach-Object { $_.ToString() }) -join "`n"
    $isYaraBuildFailure =
        ($installText -match "(?i)yara-python") -and
        ($installText -match "(?i)Microsoft Visual C\+\+ 14|failed building wheel|failed-wheel-build-for-install")

    if (-not $hasYaraDependency) {
        throw "Failed to install Python requirements.`n$installText"
    }

    if ($isYaraBuildFailure -or ($installText -match "(?i)subprocess-exited-with-error")) {
        Write-Err "Initial requirements installation failed (likely yara-python build). Retrying without yara-python..."
    } else {
        Write-Err "Initial requirements installation failed. requirements.txt contains yara-python, retrying without it..."
    }
    Write-Info "Retrying requirements installation without yara-python so setup can continue..."

    $tmpReq = Join-Path ([System.IO.Path]::GetTempPath()) ("requirements-no-yara-{0}.txt" -f ([guid]::NewGuid().ToString("N")))
    try {
        $filtered = @()
        foreach ($line in $lines) {
            $trimmed = $line.Trim()
            if ([string]::IsNullOrWhiteSpace($trimmed) -or $trimmed.StartsWith("#")) {
                $filtered += $line
                continue
            }
            if ($trimmed -match "^\s*yara-python(\s|=|>|<|!|~|$)") {
                continue
            }
            $filtered += $line
        }

        Set-Content -LiteralPath $tmpReq -Value $filtered -Encoding UTF8
        $retryResult = Invoke-NativeCommandCapture -FilePath (Get-PythonExecutable) -Arguments @("-m", "pip", "install", "-r", $tmpReq)
        $retryOut = $retryResult.Output
        if ($retryResult.ExitCode -ne 0) {
            $retryText = ($retryOut | ForEach-Object { $_.ToString() }) -join "`n"
            throw "Fallback requirements installation failed.`n--- First attempt ---`n$installText`n--- Second attempt (without yara-python) ---`n$retryText"
        }
    } finally {
        if (Test-Path -LiteralPath $tmpReq) { Remove-Item -LiteralPath $tmpReq -Force }
    }

    Write-Err "yara-python was skipped."
    Write-Info "Setup will continue and force-install yara-python in a dedicated step."
    Write-Ok "Python modules installed (without yara-python for now)."
}

function Ensure-YaraPython() {
    $probeResult = Invoke-NativeCommandCapture -FilePath (Get-PythonExecutable) -Arguments @("-c", "import yara")
    if ($probeResult.ExitCode -eq 0) {
        Write-Info "yara-python is already available."
        return
    }

    Write-Info "Installing yara-python (preferring prebuilt wheel)..."
    $wheelResult = Invoke-NativeCommandCapture -FilePath (Get-PythonExecutable) -Arguments @("-m", "pip", "install", "--only-binary=:all:", "yara-python==4.5.0")
    $wheelOut = $wheelResult.Output
    if ($wheelResult.ExitCode -eq 0) {
        $verifyWheel = Invoke-NativeCommandCapture -FilePath (Get-PythonExecutable) -Arguments @("-c", "import yara; print(yara.__version__)")
        if ($verifyWheel.ExitCode -eq 0) {
            Write-Ok "yara-python installed from wheel."
            return
        }
    }

    Write-Info "Prebuilt yara-python wheel is not available. Installing Microsoft C++ Build Tools..."
    $null = Ensure-Winget
    $buildToolsResult = Invoke-NativeCommandCapture -FilePath "winget" -Arguments @(
        "install",
        "-e",
        "--id", "Microsoft.VisualStudio.2022.BuildTools",
        "--accept-package-agreements",
        "--accept-source-agreements",
        "--override", "--quiet --wait --norestart --nocache --add Microsoft.VisualStudio.Workload.VCTools --includeRecommended"
    )
    if ($buildToolsResult.ExitCode -ne 0) {
        $wheelText = ($wheelOut | ForEach-Object { $_.ToString() }) -join "`n"
        throw "yara-python requires Microsoft C++ Build Tools but automatic installation failed.`n--- pip output ---`n$wheelText`nInstall Build Tools manually and re-run setup."
    }
    Write-Ok "Microsoft C++ Build Tools installed."

    Write-Info "Retrying yara-python installation from source..."
    $srcResult = Invoke-NativeCommandCapture -FilePath (Get-PythonExecutable) -Arguments @("-m", "pip", "install", "--no-binary=:all:", "yara-python==4.5.0")
    $srcOut = $srcResult.Output
    if ($srcResult.ExitCode -ne 0) {
        $srcText = ($srcOut | ForEach-Object { $_.ToString() }) -join "`n"
        throw "Failed to install yara-python even after Build Tools setup.`n$srcText"
    }

    $verifySrc = Invoke-NativeCommandCapture -FilePath (Get-PythonExecutable) -Arguments @("-c", "import yara; print(yara.__version__)")
    if ($verifySrc.ExitCode -ne 0) {
        throw "yara-python installation finished but import test failed."
    }

    Write-Ok "yara-python installed successfully."
}

function Ensure-PyOneNote() {
    $probeResult = Invoke-NativeCommandCapture -FilePath (Get-PythonExecutable) -Arguments @("-c", "from pyOneNote.Main import OneDocment")
    if ($probeResult.ExitCode -eq 0) {
        Write-Info "pyOneNote is already available."
        return
    }

    Write-Info "Installing pyOneNote..."
    & (Get-PythonExecutable) -m pip install -U --force-reinstall "https://github.com/DissectMalware/pyOneNote/archive/master.zip" | Out-Null
    Write-Ok "pyOneNote installed."
}

function Ensure-ZipTooling() {
    $ea = Get-Command Expand-Archive -ErrorAction SilentlyContinue
    if ($null -eq $ea) {
        throw "Expand-Archive is not available. Please install a newer PowerShell or required modules."
    }
}

function Ensure-Jadx([string]$BaseDir, [string]$RepoRoot, [string]$JadxVersion) {
    $jadxDir = Join-Path $BaseDir "jadx"
    $jadxLauncher = Join-Path $jadxDir "bin\\jadx.bat"
    $jadxUrl = "https://github.com/skylot/jadx/releases/download/v{0}/jadx-{0}.zip" -f $JadxVersion

    if (Test-JadxInstall -JadxDir $jadxDir -JadxVersion $JadxVersion) {
        Write-Info "JADX already exists in $jadxDir"
        return $jadxLauncher
    }

    if (Test-Path -LiteralPath $jadxDir) {
        Write-Info "JADX directory exists but version/launcher validation failed. Re-installing..."
        Remove-Item -LiteralPath $jadxDir -Force -Recurse
    }
    Ensure-Directory $jadxDir

    Write-Info ("Downloading JADX v{0}..." -f $JadxVersion)
    $tmpZip = Join-Path ([System.IO.Path]::GetTempPath()) ("jadx-{0}.zip" -f ([guid]::NewGuid().ToString("N")))
    $tmpExtract = Join-Path ([System.IO.Path]::GetTempPath()) ("jadx-{0}" -f ([guid]::NewGuid().ToString("N")))
    Ensure-Directory $tmpExtract

    try {
        Invoke-Download -Uri $jadxUrl -OutFile $tmpZip
        Write-Info "Extracting JADX..."
        Expand-Archive -LiteralPath $tmpZip -DestinationPath $tmpExtract -Force

        # JADX packaging can be either:
        # - direct content in archive root (bin/, lib/, ...)
        # - nested under a single jadx-* folder
        $sourceRoot = $tmpExtract
        $rootBin = Join-Path $sourceRoot "bin"
        $rootLib = Join-Path $sourceRoot "lib"
        if (-not ((Test-Path -LiteralPath $rootBin) -and (Test-Path -LiteralPath $rootLib))) {
            $inner = Get-ChildItem -LiteralPath $tmpExtract -Directory | Select-Object -First 1
            if ($null -ne $inner) {
                $sourceRoot = $inner.FullName
            }
        }

        $sourceBin = Join-Path $sourceRoot "bin"
        $sourceLib = Join-Path $sourceRoot "lib"
        if (-not ((Test-Path -LiteralPath $sourceBin) -and (Test-Path -LiteralPath $sourceLib))) {
            throw "Unexpected JADX archive layout (bin/lib folders were not found)."
        }

        Get-ChildItem -LiteralPath $sourceRoot -Force | Copy-Item -Destination $jadxDir -Recurse -Force
    } finally {
        if (Test-Path -LiteralPath $tmpZip) { Remove-Item -LiteralPath $tmpZip -Force }
        if (Test-Path -LiteralPath $tmpExtract) { Remove-Item -LiteralPath $tmpExtract -Force -Recurse }
    }

    if (-not (Test-JadxInstall -JadxDir $jadxDir -JadxVersion $JadxVersion)) {
        throw "JADX installation completed, but launcher/jar validation failed."
    }
    Write-Ok "JADX installed at $jadxDir"

    # Update Android decompiler path in config
    $libScannerConf = Join-Path $RepoRoot "Systems\\Android\\libScanner.conf"
    Write-Info "Updating Systems/Android/libScanner.conf..."
    Update-IniLine -Path $libScannerConf -Key "decompiler" -Value $jadxLauncher
    Write-Ok "libScanner.conf updated."

    return $jadxLauncher
}

function Ensure-PlatformTools([string]$BaseDir, [string]$RepoRoot) {
    $ptDir = Join-Path $BaseDir "platform-tools"
    $adbExe = Join-Path $ptDir "adb.exe"
    if (Test-Path -LiteralPath $adbExe) {
        Write-Info "Android Platform Tools already exist in $ptDir"
    } else {
        Write-Info "Downloading Android Platform Tools..."
        $url = "https://dl.google.com/android/repository/platform-tools-latest-windows.zip"
        $tmpZip = Join-Path ([System.IO.Path]::GetTempPath()) ("platform-tools-{0}.zip" -f ([guid]::NewGuid().ToString("N")))
        $tmpExtract = Join-Path ([System.IO.Path]::GetTempPath()) ("platform-tools-{0}" -f ([guid]::NewGuid().ToString("N")))
        Ensure-Directory $tmpExtract
        try {
            Invoke-Download -Uri $url -OutFile $tmpZip
            Expand-Archive -LiteralPath $tmpZip -DestinationPath $tmpExtract -Force
            $src = Join-Path $tmpExtract "platform-tools"
            if (-not (Test-Path -LiteralPath $src)) {
                throw "Unexpected platform-tools archive layout."
            }
            if (Test-Path -LiteralPath $ptDir) {
                Remove-Item -LiteralPath $ptDir -Force -Recurse
            }
            Move-Item -LiteralPath $src -Destination $ptDir -Force
        } finally {
            if (Test-Path -LiteralPath $tmpZip) { Remove-Item -LiteralPath $tmpZip -Force }
            if (Test-Path -LiteralPath $tmpExtract) { Remove-Item -LiteralPath $tmpExtract -Force -Recurse }
        }
        Write-Ok "Android Platform Tools installed at $ptDir"
    }

    # Update Windows adb path config
    $winConf = Join-Path $RepoRoot "Systems\\Windows\\windows.conf"
    Write-Info "Updating Systems/Windows/windows.conf..."
    Update-IniLine -Path $winConf -Key "win_adb_path" -Value $adbExe
    Write-Ok "windows.conf updated."
}

function Ensure-ToolsBin([string]$BaseDir) {
    $toolsBin = Join-Path $BaseDir "bin"
    Ensure-Directory $toolsBin
    $null = Ensure-PathEntry -PathToAdd $toolsBin -Scope "Process"
    $addedToUserPath = Ensure-PathEntry -PathToAdd $toolsBin -Scope "User"
    if ($addedToUserPath) {
        Write-Ok "Added $toolsBin to user PATH (persistent)."
    } else {
        Write-Info "$toolsBin already exists in user PATH."
    }
    return $toolsBin
}

function Ensure-FileCommand([string]$ToolsBin) {
    $fileExe = Join-Path $ToolsBin "file.exe"
    $magic = Join-Path $ToolsBin "magic.mgc"
    if ((Test-Path -LiteralPath $fileExe) -and (Test-Path -LiteralPath $magic)) {
        Write-Info "file command already exists in $ToolsBin"
        return
    }

    Write-Info "Downloading file command (Windows build)..."
    $url = "https://github.com/nscaife/file-windows/releases/download/20170108/file-windows-20170108.zip"
    $tmpZip = Join-Path ([System.IO.Path]::GetTempPath()) ("file-windows-{0}.zip" -f ([guid]::NewGuid().ToString("N")))
    $tmpExtract = Join-Path ([System.IO.Path]::GetTempPath()) ("file-windows-{0}" -f ([guid]::NewGuid().ToString("N")))
    Ensure-Directory $tmpExtract

    try {
        Invoke-Download -Uri $url -OutFile $tmpZip
        Expand-Archive -LiteralPath $tmpZip -DestinationPath $tmpExtract -Force
        $root = Join-Path $tmpExtract "file-windows"
        if (-not (Test-Path -LiteralPath $root)) {
            # fallback: zip might extract directly
            $root = $tmpExtract
        }
        Copy-Item -LiteralPath (Join-Path $root "file.exe") -Destination $fileExe -Force
        Copy-Item -LiteralPath (Join-Path $root "magic.mgc") -Destination $magic -Force
        Copy-Item -LiteralPath (Join-Path $root "libgnurx-0.dll") -Destination (Join-Path $ToolsBin "libgnurx-0.dll") -Force
        Copy-Item -LiteralPath (Join-Path $root "libmagic-1.dll") -Destination (Join-Path $ToolsBin "libmagic-1.dll") -Force
    } finally {
        if (Test-Path -LiteralPath $tmpZip) { Remove-Item -LiteralPath $tmpZip -Force }
        if (Test-Path -LiteralPath $tmpExtract) { Remove-Item -LiteralPath $tmpExtract -Force -Recurse }
    }

    Write-Ok "file command installed into $ToolsBin"
}

function Ensure-StringsEulaAccepted([string]$StringsExe) {
    if ([string]::IsNullOrWhiteSpace($StringsExe) -or (-not (Test-Path -LiteralPath $StringsExe))) {
        return
    }

    $eulaPath = "HKCU:\\Software\\Sysinternals\\Strings"
    try {
        if (-not (Test-Path -LiteralPath $eulaPath)) {
            $null = New-Item -Path $eulaPath -Force
        }
        $existing = Get-ItemProperty -Path $eulaPath -Name "EulaAccepted" -ErrorAction SilentlyContinue
        if (($null -eq $existing) -or ([int]$existing.EulaAccepted -ne 1)) {
            $null = New-ItemProperty -Path $eulaPath -Name "EulaAccepted" -PropertyType DWord -Value 1 -Force
        }
    } catch {
        # Best effort only.
    }

    # Also pass -accepteula once to cover edge cases where registry path/value differs by build.
    $null = Invoke-NativeCommandCapture -FilePath $StringsExe -Arguments @("-accepteula", "-nobanner")
}

function Ensure-StringsCommand([string]$ToolsBin) {
    $stringsExe = Join-Path $ToolsBin "strings.exe"
    if (Test-Path -LiteralPath $stringsExe) {
        Ensure-StringsEulaAccepted -StringsExe $stringsExe
        Write-Info "strings command already exists in $ToolsBin"
        return
    }

    Write-Info "Downloading Sysinternals Strings..."
    $url = "https://download.sysinternals.com/files/Strings.zip"
    $tmpZip = Join-Path ([System.IO.Path]::GetTempPath()) ("strings-{0}.zip" -f ([guid]::NewGuid().ToString("N")))
    $tmpExtract = Join-Path ([System.IO.Path]::GetTempPath()) ("strings-{0}" -f ([guid]::NewGuid().ToString("N")))
    Ensure-Directory $tmpExtract

    try {
        Invoke-Download -Uri $url -OutFile $tmpZip
        Expand-Archive -LiteralPath $tmpZip -DestinationPath $tmpExtract -Force
        $root = Join-Path $tmpExtract "strings"
        if (-not (Test-Path -LiteralPath $root)) {
            $root = $tmpExtract
        }
        Copy-Item -LiteralPath (Join-Path $root "strings.exe") -Destination $stringsExe -Force
    } finally {
        if (Test-Path -LiteralPath $tmpZip) { Remove-Item -LiteralPath $tmpZip -Force }
        if (Test-Path -LiteralPath $tmpExtract) { Remove-Item -LiteralPath $tmpExtract -Force -Recurse }
    }

    Ensure-StringsEulaAccepted -StringsExe $stringsExe
    Write-Ok "strings command installed into $ToolsBin"
}

function Resolve-SevenZipExecutable() {
    $cmd = Get-Command 7z -ErrorAction SilentlyContinue
    if (($null -ne $cmd) -and (-not [string]::IsNullOrWhiteSpace($cmd.Source))) {
        return $cmd.Source
    }

    $candidates = @(
        (Join-Path $env:ProgramFiles "7-Zip\\7z.exe"),
        (Join-Path ${env:ProgramFiles(x86)} "7-Zip\\7z.exe"),
        (Join-Path $env:LOCALAPPDATA "Programs\\7-Zip\\7z.exe"),
        (Join-Path $env:LOCALAPPDATA "Microsoft\\WinGet\\Links\\7z.exe"),
        (Join-Path $env:LOCALAPPDATA "Programs\\7-Zip\\7zz.exe"),
        (Join-Path $env:LOCALAPPDATA "Microsoft\\WinGet\\Links\\7zz.exe")
    ) | Where-Object { $_ -and (Test-Path -LiteralPath $_) }

    $candidates = @($candidates)
    if ($candidates.Length -gt 0) {
        return $candidates[0]
    }

    return ""
}

function Ensure-7Zip() {
    $sevenZipExe = Resolve-SevenZipExecutable
    if (-not [string]::IsNullOrWhiteSpace($sevenZipExe)) {
        $sevenZipDir = Split-Path -Parent $sevenZipExe
        $null = Ensure-PathEntry -PathToAdd $sevenZipDir -Scope "Process"
        $null = Ensure-PathEntry -PathToAdd $sevenZipDir -Scope "User"
        Write-Info "7-Zip is already available: $sevenZipExe"
        return
    }

    # Try installing via common Windows package managers.
    $winget = Get-Command winget -ErrorAction SilentlyContinue
    if ($null -ne $winget) {
        Write-Info "Installing 7-Zip via winget (user scope)..."
        & winget install -e --id 7zip.7zip --scope user --accept-package-agreements --accept-source-agreements | Out-Null
        if ($LASTEXITCODE -ne 0) {
            Write-Info "Retrying 7-Zip installation via winget (without scope)..."
            & winget install -e --id 7zip.7zip --accept-package-agreements --accept-source-agreements | Out-Null
        }

        $sevenZipExe = Resolve-SevenZipExecutable
        if (-not [string]::IsNullOrWhiteSpace($sevenZipExe)) {
            $sevenZipDir = Split-Path -Parent $sevenZipExe
            $null = Ensure-PathEntry -PathToAdd $sevenZipDir -Scope "Process"
            $null = Ensure-PathEntry -PathToAdd $sevenZipDir -Scope "User"
            Write-Ok "7-Zip installed: $sevenZipExe"
            return
        }
    }

    $choco = Get-Command choco -ErrorAction SilentlyContinue
    if ($null -ne $choco) {
        Write-Info "Installing 7-Zip via Chocolatey..."
        & choco install 7zip -y | Out-Null
        $sevenZipExe = Resolve-SevenZipExecutable
        if (-not [string]::IsNullOrWhiteSpace($sevenZipExe)) {
            $sevenZipDir = Split-Path -Parent $sevenZipExe
            $null = Ensure-PathEntry -PathToAdd $sevenZipDir -Scope "Process"
            $null = Ensure-PathEntry -PathToAdd $sevenZipDir -Scope "User"
            Write-Ok "7-Zip installed: $sevenZipExe"
            return
        }
    }

    $scoop = Get-Command scoop -ErrorAction SilentlyContinue
    if ($null -ne $scoop) {
        Write-Info "Installing 7-Zip via Scoop..."
        & scoop install 7zip | Out-Null
        $sevenZipExe = Resolve-SevenZipExecutable
        if (-not [string]::IsNullOrWhiteSpace($sevenZipExe)) {
            $sevenZipDir = Split-Path -Parent $sevenZipExe
            $null = Ensure-PathEntry -PathToAdd $sevenZipDir -Scope "Process"
            $null = Ensure-PathEntry -PathToAdd $sevenZipDir -Scope "User"
            Write-Ok "7-Zip installed: $sevenZipExe"
            return
        }
    }

    throw "7-Zip is required for ACE archive extraction. Install 7-Zip (7z/7zz) and re-run setup."
}

function Ensure-WindowsAppRuntimeFramework() {
    $installed = Get-AppxPackage -Name "Microsoft.WindowsAppRuntime.1.8*" -ErrorAction SilentlyContinue
    if ($null -ne $installed) {
        Write-Info "Microsoft.WindowsAppRuntime.1.8 is already installed."
        return
    }

    Write-Info "Installing Microsoft.WindowsAppRuntime.1.8 dependency..."
    $tmpDir = Join-Path ([System.IO.Path]::GetTempPath()) ("windowsappruntime-{0}" -f ([guid]::NewGuid().ToString("N")))
    Ensure-Directory $tmpDir
    $runtimeInstaller = Join-Path $tmpDir "WindowsAppRuntimeInstall.exe"

    $runtimeUrl = if ([Environment]::Is64BitOperatingSystem) {
        "https://aka.ms/windowsappsdk/1.8/1.8.260209005/windowsappruntimeinstall-x64.exe"
    } else {
        "https://aka.ms/windowsappsdk/1.8/1.8.260209005/windowsappruntimeinstall-x86.exe"
    }

    try {
        Invoke-Download -Uri $runtimeUrl -OutFile $runtimeInstaller
        $installResult = Invoke-NativeCommandCapture -FilePath $runtimeInstaller -Arguments @("--quiet", "--force")
        if ($installResult.ExitCode -ne 0) {
            $outText = ($installResult.Output | ForEach-Object { $_.ToString() }) -join "`n"
            throw "Windows App Runtime installer failed (exit code: $($installResult.ExitCode)).`n$outText"
        }
    } finally {
        if (Test-Path -LiteralPath $tmpDir) { Remove-Item -LiteralPath $tmpDir -Force -Recurse }
    }

    $installed = Get-AppxPackage -Name "Microsoft.WindowsAppRuntime.1.8*" -ErrorAction SilentlyContinue
    if ($null -eq $installed) {
        throw "Microsoft.WindowsAppRuntime.1.8 installation completed but framework was not detected."
    }

    Write-Ok "Microsoft.WindowsAppRuntime.1.8 installed."
}

function Install-WingetFromReleaseAssets() {
    Write-Info "Falling back to official winget release assets..."
    $tmpDir = Join-Path ([System.IO.Path]::GetTempPath()) ("winget-release-{0}" -f ([guid]::NewGuid().ToString("N")))
    Ensure-Directory $tmpDir

    $releaseJsonPath = Join-Path $tmpDir "release.json"
    $depsZipPath = Join-Path $tmpDir "DesktopAppInstaller_Dependencies.zip"
    $depsExtractPath = Join-Path $tmpDir "dependencies"
    $bundlePath = Join-Path $tmpDir "Microsoft.DesktopAppInstaller_8wekyb3d8bbwe.msixbundle"

    try {
        Invoke-Download -Uri "https://api.github.com/repos/microsoft/winget-cli/releases/latest" -OutFile $releaseJsonPath
        $release = Get-Content -LiteralPath $releaseJsonPath -Raw | ConvertFrom-Json
        if ($null -eq $release -or $null -eq $release.assets) {
            throw "Unable to parse winget release metadata from GitHub."
        }

        $depsAsset = $release.assets | Where-Object { $_.name -eq "DesktopAppInstaller_Dependencies.zip" } | Select-Object -First 1
        $bundleAsset = $release.assets | Where-Object { $_.name -eq "Microsoft.DesktopAppInstaller_8wekyb3d8bbwe.msixbundle" } | Select-Object -First 1
        if (($null -eq $depsAsset) -or ($null -eq $bundleAsset)) {
            throw "Required winget release assets were not found in latest GitHub release."
        }

        Invoke-Download -Uri $depsAsset.browser_download_url -OutFile $depsZipPath
        Invoke-Download -Uri $bundleAsset.browser_download_url -OutFile $bundlePath

        Ensure-Directory $depsExtractPath
        Expand-Archive -LiteralPath $depsZipPath -DestinationPath $depsExtractPath -Force

        $depPackages = Get-ChildItem -LiteralPath $depsExtractPath -Recurse -Filter "*.appx" -File |
            Sort-Object FullName
        if (@($depPackages).Length -eq 0) {
            throw "No dependency APPX packages were found in DesktopAppInstaller_Dependencies.zip."
        }

        foreach ($pkg in $depPackages) {
            try {
                Add-AppxPackage -Path $pkg.FullName -ErrorAction Stop | Out-Null
            } catch {
                # Continue: dependency bundles can include optional/older packages on some systems.
            }
        }

        Add-AppxPackage -Path $bundlePath -ErrorAction Stop | Out-Null
    } finally {
        if (Test-Path -LiteralPath $tmpDir) { Remove-Item -LiteralPath $tmpDir -Force -Recurse }
    }
}

function Ensure-Winget() {
    $winget = Get-Command winget -ErrorAction SilentlyContinue
    if ($null -ne $winget) {
        return $winget.Source
    }

    Write-Info "winget not found. Installing App Installer (winget)..."
    $tmpDir = Join-Path ([System.IO.Path]::GetTempPath()) ("winget-{0}" -f ([guid]::NewGuid().ToString("N")))
    Ensure-Directory $tmpDir
    $bundlePath = Join-Path $tmpDir "Microsoft.DesktopAppInstaller_8wekyb3d8bbwe.msixbundle"
    $vclibsPath = Join-Path $tmpDir "Microsoft.VCLibs.x64.14.00.Desktop.appx"

    try {
        Invoke-Download -Uri "https://aka.ms/getwinget" -OutFile $bundlePath
        Invoke-Download -Uri "https://aka.ms/Microsoft.VCLibs.x64.14.00.Desktop.appx" -OutFile $vclibsPath

        # VCLibs may already be installed. Ignore errors and continue.
        try { Add-AppxPackage -Path $vclibsPath -ErrorAction Stop | Out-Null } catch {}
        try {
            Add-AppxPackage -Path $bundlePath -ErrorAction Stop | Out-Null
        } catch {
            $msg = $_.Exception.Message
            if (
                ($msg -match "0x80073CF3") -or
                ($msg -match "Microsoft\.WindowsAppRuntime\.1\.8") -or
                ($msg -match "Microsoft\.VCLibs\.140\.00\.UWPDesktop")
            ) {
                if ($msg -match "Microsoft\.WindowsAppRuntime\.1\.8") {
                    Write-Err "App Installer dependency missing: Microsoft.WindowsAppRuntime.1.8"
                    Ensure-WindowsAppRuntimeFramework
                }
                try {
                    Add-AppxPackage -Path $bundlePath -ErrorAction Stop | Out-Null
                } catch {
                    Install-WingetFromReleaseAssets
                }
            } else {
                throw
            }
        }
    } finally {
        if (Test-Path -LiteralPath $tmpDir) { Remove-Item -LiteralPath $tmpDir -Force -Recurse }
    }

    # App Installer usually exposes winget via WindowsApps.
    $windowsApps = Join-Path $env:LOCALAPPDATA "Microsoft\\WindowsApps"
    if (Test-Path -LiteralPath $windowsApps) {
        $null = Ensure-PathEntry -PathToAdd $windowsApps -Scope "Process"
        $null = Ensure-PathEntry -PathToAdd $windowsApps -Scope "User"
    }

    $winget = Get-Command winget -ErrorAction SilentlyContinue
    if ($null -ne $winget) {
        Write-Ok "winget installed: $($winget.Source)"
        return $winget.Source
    }

    $wingetExe = Join-Path $windowsApps "winget.exe"
    if (Test-Path -LiteralPath $wingetExe) {
        Write-Ok "winget installed: $wingetExe"
        return $wingetExe
    }

    throw "winget installation attempted but winget.exe is still not available. Restart Windows and re-run setup."
}

function Resolve-OllamaPath() {
    $cmd = Get-Command ollama -ErrorAction SilentlyContinue
    if ($null -ne $cmd) {
        return $cmd.Source
    }

    $candidates = @(
        (Join-Path $env:LOCALAPPDATA "Programs\\Ollama\\ollama.exe"),
        (Join-Path $env:ProgramFiles "Ollama\\ollama.exe")
    ) | Where-Object { $_ -and (Test-Path -LiteralPath $_) }
    $candidates = @($candidates)
    if ($candidates.Length -gt 0) {
        return $candidates[0]
    }
    return ""
}

function Ensure-Ollama() {
    $ollamaExe = Resolve-OllamaPath
    if (-not [string]::IsNullOrWhiteSpace($ollamaExe)) {
        $ollamaDir = Split-Path -Parent $ollamaExe
        $null = Ensure-PathEntry -PathToAdd $ollamaDir -Scope "Process"
        $null = Ensure-PathEntry -PathToAdd $ollamaDir -Scope "User"
        Write-Info "Ollama is already available: $ollamaExe"
        return $ollamaExe
    }

    $wingetExe = Ensure-Winget

    Write-Info "Installing Ollama via winget (user scope)..."
    $ollamaInstallResult = Invoke-NativeCommandCapture -FilePath $wingetExe -Arguments @(
        "install",
        "-e",
        "--id", "Ollama.Ollama",
        "--scope", "user",
        "--accept-package-agreements",
        "--accept-source-agreements"
    )
    if ($ollamaInstallResult.ExitCode -ne 0) {
        Write-Info "Retrying Ollama installation via winget (without scope)..."
        $retryResult = Invoke-NativeCommandCapture -FilePath $wingetExe -Arguments @(
            "install",
            "-e",
            "--id", "Ollama.Ollama",
            "--accept-package-agreements",
            "--accept-source-agreements"
        )
        if ($retryResult.ExitCode -eq 0) {
            $ollamaInstallResult = $retryResult
        } else {
            # Keep both outputs for diagnostics, but still check whether ollama.exe became available.
            $allOut = (($ollamaInstallResult.Output | ForEach-Object { $_.ToString() }) + ($retryResult.Output | ForEach-Object { $_.ToString() })) -join "`n"
            $ollamaExe = Resolve-OllamaPath
            if ([string]::IsNullOrWhiteSpace($ollamaExe)) {
                throw "winget failed to install Ollama.`n$allOut"
            }
            Write-Err "winget reported errors during Ollama installation, but ollama.exe is available."
        }
    }

    $ollamaExe = Resolve-OllamaPath
    if ([string]::IsNullOrWhiteSpace($ollamaExe)) {
        throw "Ollama installation completed but ollama.exe was not found. Restart terminal and re-run setup."
    }

    $ollamaDir = Split-Path -Parent $ollamaExe
    $null = Ensure-PathEntry -PathToAdd $ollamaDir -Scope "Process"
    $null = Ensure-PathEntry -PathToAdd $ollamaDir -Scope "User"
    Write-Ok "Ollama installed: $ollamaExe"
    return $ollamaExe
}

function Ensure-OllamaModel([string]$OllamaExe, [string]$ModelName) {
    if ([string]::IsNullOrWhiteSpace($ModelName)) {
        throw "Model name is empty."
    }
    $isCloudModel = $ModelName.Trim().ToLowerInvariant().EndsWith(":cloud")
    if ($isCloudModel) {
        Write-OllamaSigninNotice -ModelName $ModelName
    }

    $listResult = Invoke-NativeCommandCapture -FilePath $OllamaExe -Arguments @("list")
    $existing = $listResult.Output
    if (($listResult.ExitCode -eq 0) -and ($existing | Where-Object { $_ -match ("^\s*{0}(?:\s|$)" -f [regex]::Escape($ModelName)) })) {
        Write-Info "Ollama model already exists: $ModelName"
        return $true
    }
    if (($listResult.ExitCode -ne 0) -and $isCloudModel) {
        Write-Info "Could not query existing Ollama models cleanly; continuing with pull attempt."
    }

    Write-Info "Pulling Ollama model: $ModelName"
    $pullTimeout = if ($isCloudModel) { 240 } else { 0 }
    $pullResult = Invoke-ProcessWithTimeoutCapture -FilePath $OllamaExe -Arguments @("pull", $ModelName) -TimeoutSeconds $pullTimeout
    $pullOutput = $pullResult.Output
    if ($pullResult.TimedOut -and $isCloudModel) {
        Write-Err "Timed out while pulling cloud model '$ModelName'."
        Write-OllamaSigninNotice -ModelName $ModelName
        Write-Info "Setup will continue without pulling this model."
        return $false
    }
    if ($pullResult.ExitCode -ne 0) {
        Write-Info "Model pull failed on first attempt. Trying to start Ollama service and retry..."
        try {
            Start-Process -FilePath $OllamaExe -ArgumentList "serve" -WindowStyle Hidden | Out-Null
            Start-Sleep -Seconds 3
        } catch {
            # best-effort; retry pull anyway
        }
        $retryResult = Invoke-ProcessWithTimeoutCapture -FilePath $OllamaExe -Arguments @("pull", $ModelName) -TimeoutSeconds $pullTimeout
        $retryOutput = $retryResult.Output
        if ($retryResult.TimedOut -and $isCloudModel) {
            Write-Err "Timed out while pulling cloud model '$ModelName' after retry."
            Write-OllamaSigninNotice -ModelName $ModelName
            Write-Info "Setup will continue without pulling this model."
            return $false
        }
        if ($retryResult.ExitCode -ne 0) {
            $allOutput = (($pullOutput | ForEach-Object { $_.ToString() }) + ($retryOutput | ForEach-Object { $_.ToString() })) -join "`n"
            if ($isCloudModel -and ($allOutput -match "(?i)\b401\b|unauthorized|authentication|auth")) {
                Write-Err "Cloud model pull requires Ollama authentication."
                Write-OllamaSigninNotice -ModelName $ModelName
                Write-Info "Setup will continue without pulling this model."
                return $false
            }
            if ($isCloudModel) {
                Write-Err "Failed to pull cloud model '$ModelName'."
                Write-OllamaSigninNotice -ModelName $ModelName
                Write-Info "Try manually later: ollama pull $ModelName"
                Write-Info "Setup will continue without pulling this model."
                return $false
            }
            throw "Failed to pull Ollama model '$ModelName'. Try manually: ollama pull $ModelName"
        }
    }

    Write-Ok "Ollama model is ready: $ModelName"
    return $true
}

try {
    $RepoRoot = Split-Path -Parent $MyInvocation.MyCommand.Path
    Set-Location -LiteralPath $RepoRoot

    Ensure-ZipTooling
    $null = Ensure-Winget
    Ensure-Python
    Ensure-7Zip
    Ensure-PythonRequirements -RepoRoot $RepoRoot
    Ensure-YaraPython

    $BaseDir = Join-Path $HOME "sc0pe_Base"
    Ensure-Directory $BaseDir
    Write-Ok "sc0pe_Base is ready at $BaseDir"

    $ToolsBin = Ensure-ToolsBin -BaseDir $BaseDir
    Ensure-FileCommand -ToolsBin $ToolsBin
    Ensure-StringsCommand -ToolsBin $ToolsBin
    $OllamaExe = Ensure-Ollama
    $ollamaModelReady = Ensure-OllamaModel -OllamaExe $OllamaExe -ModelName "kimi-k2.5:cloud"
    if (-not $ollamaModelReady) {
        Write-Info "Continuing setup without a pulled Ollama cloud model."
        Write-OllamaSigninNotice -ModelName "kimi-k2.5:cloud"
    }

    $JadxVersion = "1.5.3"
    $null = Ensure-Jadx -BaseDir $BaseDir -RepoRoot $RepoRoot -JadxVersion $JadxVersion
    Ensure-PlatformTools -BaseDir $BaseDir -RepoRoot $RepoRoot

    Ensure-PyOneNote

    Write-Ok "All done."
    Write-Info "Note: Tools were installed into $ToolsBin and added to PATH (current session + persistent user PATH)."
} catch {
    Write-Err $_.Exception.Message
    exit 1
}
