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

function Write-Info([string]$Message) { Write-Host "$InfoS $Message" }
function Write-Ok([string]$Message) { Write-Host "$OkS $Message" }
function Write-Err([string]$Message) { Write-Host "$ErrS $Message" }

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
    Set-Content -LiteralPath $Path -Value $out -Encoding UTF8
}

function Ensure-Python() {
    $py = Get-Command python -ErrorAction SilentlyContinue
    if ($null -eq $py) {
        throw "Python is not installed (python not found in PATH). Install Python 3.10+ and try again."
    }

    $ver = & python -c "import sys; print('%d.%d' % sys.version_info[:2])"
    $majorMinor = $ver.Split(".")
    $maj = [int]$majorMinor[0]
    $min = [int]$majorMinor[1]
    if (($maj -lt 3) -or (($maj -eq 3) -and ($min -lt 10))) {
        throw "Python 3.10+ is required. Found: $ver"
    }

    # Ensure pip
    & python -m pip --version | Out-Null
}

function Ensure-PythonRequirements([string]$RepoRoot) {
    $req = Join-Path $RepoRoot "requirements.txt"
    if (-not (Test-Path -LiteralPath $req)) {
        throw "requirements.txt not found in: $RepoRoot"
    }
    Write-Info "Installing python modules from requirements.txt..."
    & python -m pip install -r $req | Out-Null
    Write-Ok "Python modules installed."
}

function Ensure-PyOneNote() {
    $ok = $false
    try {
        & python -c "from pyOneNote.Main import OneDocment" | Out-Null
        $ok = $true
    } catch {
        $ok = $false
    }

    if ($ok) {
        Write-Info "pyOneNote is already available."
        return
    }

    Write-Info "Installing pyOneNote..."
    & python -m pip install -U --force-reinstall "https://github.com/DissectMalware/pyOneNote/archive/master.zip" | Out-Null
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

function Ensure-StringsCommand([string]$ToolsBin) {
    $stringsExe = Join-Path $ToolsBin "strings.exe"
    if (Test-Path -LiteralPath $stringsExe) {
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

    Write-Ok "strings command installed into $ToolsBin"
}

function Ensure-7Zip() {
    $cmd = Get-Command 7z -ErrorAction SilentlyContinue
    if ($null -ne $cmd) {
        Write-Info "7z is already available: $($cmd.Source)"
        return
    }

    $candidatePaths = @(
        (Join-Path $env:ProgramFiles "7-Zip\\7z.exe"),
        (Join-Path ${env:ProgramFiles(x86)} "7-Zip\\7z.exe")
    ) | Where-Object { $_ -and (Test-Path -LiteralPath $_) }

    $candidatePaths = @($candidatePaths)
    if ($candidatePaths.Length -gt 0) {
        $sevenZipDir = Split-Path -Parent $candidatePaths[0]
        if (-not ($env:PATH -split ";" | Where-Object { $_ -eq $sevenZipDir })) {
            $env:PATH = "$sevenZipDir;$env:PATH"
        }
        Write-Ok "7z found at $($candidatePaths[0]) (added to PATH for this session)."
        return
    }

    # Try installing via common Windows package managers.
    $winget = Get-Command winget -ErrorAction SilentlyContinue
    if ($null -ne $winget) {
        Write-Info "Installing 7-Zip via winget (user scope)..."
        & winget install -e --id 7zip.7zip --scope user --accept-package-agreements --accept-source-agreements | Out-Null
        $cmd = Get-Command 7z -ErrorAction SilentlyContinue
        if ($null -ne $cmd) {
            Write-Ok "7z installed: $($cmd.Source)"
            return
        }
    }

    $choco = Get-Command choco -ErrorAction SilentlyContinue
    if ($null -ne $choco) {
        Write-Info "Installing 7-Zip via Chocolatey..."
        & choco install 7zip -y | Out-Null
        $cmd = Get-Command 7z -ErrorAction SilentlyContinue
        if ($null -ne $cmd) {
            Write-Ok "7z installed: $($cmd.Source)"
            return
        }
    }

    $scoop = Get-Command scoop -ErrorAction SilentlyContinue
    if ($null -ne $scoop) {
        Write-Info "Installing 7-Zip via Scoop..."
        & scoop install 7zip | Out-Null
        $cmd = Get-Command 7z -ErrorAction SilentlyContinue
        if ($null -ne $cmd) {
            Write-Ok "7z installed: $($cmd.Source)"
            return
        }
    }

    throw "7z (7-Zip) is required for ACE archive extraction. Install 7-Zip (7z) and re-run setup."
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
        Add-AppxPackage -Path $bundlePath -ErrorAction Stop | Out-Null
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
    & $wingetExe install -e --id Ollama.Ollama --scope user --accept-package-agreements --accept-source-agreements | Out-Null
    if ($LASTEXITCODE -ne 0) {
        throw "winget failed to install Ollama. Try manually: winget install -e --id Ollama.Ollama --scope user"
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

    $existing = & $OllamaExe list 2>$null
    if (($LASTEXITCODE -eq 0) -and ($existing | Where-Object { $_ -match ("^\s*{0}(?:\s|$)" -f [regex]::Escape($ModelName)) })) {
        Write-Info "Ollama model already exists: $ModelName"
        return $true
    }

    Write-Info "Pulling Ollama model: $ModelName"
    $pullOutput = & $OllamaExe pull $ModelName 2>&1
    if ($LASTEXITCODE -ne 0) {
        Write-Info "Model pull failed on first attempt. Trying to start Ollama service and retry..."
        try {
            Start-Process -FilePath $OllamaExe -ArgumentList "serve" -WindowStyle Hidden | Out-Null
            Start-Sleep -Seconds 3
        } catch {
            # best-effort; retry pull anyway
        }
        $retryOutput = & $OllamaExe pull $ModelName 2>&1
        if ($LASTEXITCODE -ne 0) {
            $allOutput = (($pullOutput | ForEach-Object { $_.ToString() }) + ($retryOutput | ForEach-Object { $_.ToString() })) -join "`n"
            if ($isCloudModel -and ($allOutput -match "(?i)\b401\b|unauthorized|authentication|auth")) {
                Write-Err "Cloud model pull requires Ollama authentication. Run: ollama signin"
                Write-Info "Then retry manually: ollama pull $ModelName"
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
    Ensure-Python
    Ensure-PythonRequirements -RepoRoot $RepoRoot

    $BaseDir = Join-Path $HOME "sc0pe_Base"
    Ensure-Directory $BaseDir
    Write-Ok "sc0pe_Base is ready at $BaseDir"

    $ToolsBin = Ensure-ToolsBin -BaseDir $BaseDir
    Ensure-FileCommand -ToolsBin $ToolsBin
    Ensure-StringsCommand -ToolsBin $ToolsBin
    Ensure-7Zip
    $OllamaExe = Ensure-Ollama
    $ollamaModelReady = Ensure-OllamaModel -OllamaExe $OllamaExe -ModelName "kimi-k2.5:cloud"
    if (-not $ollamaModelReady) {
        Write-Info "Continuing setup without a pulled Ollama cloud model."
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
