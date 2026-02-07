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
    $jar = Join-Path $JadxDir ("lib\\jadx-cli-{0}.jar" -f $JadxVersion)
    return ((Test-Path -LiteralPath $launcher) -and (Test-Path -LiteralPath $jar))
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

        # zip content usually contains 'jadx-*' folder.
        $inner = Get-ChildItem -LiteralPath $tmpExtract | Where-Object { $_.PSIsContainer } | Select-Object -First 1
        if ($null -eq $inner) {
            throw "Unexpected JADX archive layout (no inner folder)."
        }

        Copy-Item -LiteralPath (Join-Path $inner.FullName "*") -Destination $jadxDir -Recurse -Force
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
    # Make available for current session; persistent PATH is intentionally not modified.
    if (-not ($env:PATH -split ";" | Where-Object { $_ -eq $toolsBin })) {
        $env:PATH = "$toolsBin;$env:PATH"
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

    $JadxVersion = "1.5.3"
    $null = Ensure-Jadx -BaseDir $BaseDir -RepoRoot $RepoRoot -JadxVersion $JadxVersion
    Ensure-PlatformTools -BaseDir $BaseDir -RepoRoot $RepoRoot

    Ensure-PyOneNote

    Write-Ok "All done."
    Write-Info "Note: Tools were installed into $ToolsBin and added to PATH for this session."
} catch {
    Write-Err $_.Exception.Message
    exit 1
}

