# Colors for cute outputs
$cyan = [char]27 + "[96m"
$red = [char]27 + "[91m"
$green = [char]27 + "[92m"
$default = [char]27 + "[0m"

# Legends
$infoS = "$cyan[$red*$cyan]$default"
$errorS = "$cyan[$red!$cyan]$default"
$succesS = "$cyan[$red+$cyan]$default"

# Python module installation
if (Get-Command pip -ErrorAction SilentlyContinue) {
    Write-Host "$infoS Installing necessary Python modules..."
    pip install -r requirements.txt
} else {
    Write-Host "$errorS Looks like you don't have$green pip$default command. Quitting!"
    sleep 3
    exit
}

# Check for git command
Write-Host "`n$infoS Checking existence of$green git$default command."
if (Get-Command git -ErrorAction SilentlyContinue) {
    Write-Host "$succesS$green git$default command is already exist."
} else {
    Write-Host "$errorS Looks like you don't have$green git$default command. Quitting!"
    sleep 3
    exit
}

# Setting up sc0pe_Base folder
Write-Host "`n$infoS Checking existence of$green sc0pe_Base$default folder."
if (Test-Path "$env:HOMEPATH\sc0pe_Base") {
    Write-Host "$succesS$green sc0pe_Base$default folder is already exist.`n"
} else {
    Write-Host "$infoS Creating$green sc0pe_Base$default folder in$green $env:HOMEPATH"
    $null = New-Item -Path "$env:HOMEPATH\sc0pe_Base" -ItemType Directory
}

# Checking for Jadx
Write-Host "`n$infoS Checking for$green Jadx$default"
if (Test-Path "$env:HOMEPATH\sc0pe_Base\jadx") {
    Write-Host "$succesS$green Jadx$default is already exist.`n"
} else {
    Write-Host "$infoS Downloading$green Jadx$default..."
    wget "https://github.com/skylot/jadx/releases/download/v1.4.5/jadx-1.4.5.zip" -O jadx.zip
    Write-Host "$infoS Extracting archive..."
    Expand-Archive -Path .\jadx.zip -DestinationPath .\jadx
    Write-Host "$infoS Removing junk files..."
    Remove-Item -Path .\jadx.zip -Force -Recurse
    Write-Host "$infoS Setting up$green Jadx$default..."
    Move-Item -Path .\jadx -Destination "$env:HOMEPATH\sc0pe_Base\"
    Write-Host "$infoS Modifying$green libScanner.conf$default..."
    $content = Get-Content -Path .\Systems\Android\libScanner.conf -Raw
    $modifiedContent = $content -replace [regex]::Escape("/usr/bin/jadx"), "C:$env:HOMEPATH\sc0pe_Base\jadx\bin\jadx.bat"
    Set-Content -Path .\Systems\Android\libScanner.conf -Value $modifiedContent
}

# Installing windows-file command
Write-Host "`n$infoS Checking$green file$default command..."
if (Get-Command file -ErrorAction SilentlyContinue) {
    Write-Host "$succesS$green file$default is already exist."
} else {
    Write-Host "$infoS Downloading$green file$default command..."
    wget "https://github.com/nscaife/file-windows/releases/download/20170108/file-windows-20170108.zip" -O file-windows.zip
    Write-Host "$infoS Extracting archive..."
    Expand-Archive -Path .\file-windows.zip -DestinationPath .\file-windows
    Write-Host "$infoS Copying files..."
    Copy-Item -Path ".\file-windows\file.exe" -Destination "C:\Windows\System32"
    Copy-Item -Path ".\file-windows\magic.mgc" -Destination "C:\Windows\System32"
    Copy-Item -Path ".\file-windows\libgnurx-0.dll" -Destination "C:\Windows\System32"
    Copy-Item -Path ".\file-windows\libmagic-1.dll" -Destination "C:\Windows\System32"
    Write-Host "$infoS Removing junk files..."
    Remove-Item -Path .\file-windows.zip -Force -Recurse
    Remove-Item -Path .\file-windows -Force -Recurse
}

# Installing strings command
Write-Host "`n$infoS Checking$green strings$default command..."
if (Get-Command strings -ErrorAction SilentlyContinue) {
    Write-Host "$succesS$green strings$default is already exist."
} else {
    Write-Host "$infoS Downloading$green strings$default command..."
    wget "https://download.sysinternals.com/files/Strings.zip" -O strings.zip
    Write-Host "$infoS Extracting archive..."
    Expand-Archive -Path .\strings.zip -DestinationPath .\strings
    Write-Host "$infoS Copying files..."
    Copy-Item -Path ".\strings\strings.exe" -Destination "C:\Windows\System32"
    Write-Host "$infoS Removing junk files..."
    Remove-Item -Path .\strings.zip -Force -Recurse
    Remove-Item -Path .\strings -Force -Recurse
}

# Check for pyOneNote
Write-Host "`n$infoS Checking$green pyOneNote$default..."
if (Get-Command pyonenote.exe -ErrorAction SilentlyContinue) {
    Write-Host "$succesS$green pyOneNote$default is already exist."
} else {
    Write-Host "$infoS Downloading$green pyOneNote$default via$green pip$default"
    pip install -U "https://github.com/DissectMalware/pyOneNote/archive/master.zip" --force
}

# Copying sc0pe_helper
Write-Host "`n$infoS Checking$green sc0pe_helper$default"
if (Test-Path "$env:LOCALAPPDATA\programs\Python\Python310\Lib\site-packages\sc0pe_helper.py") {
    Write-Host "$succesS$green sc0pe_helper$default is already exist."
} else {
    Write-Host "$infoS Copying$green sc0pe_helper$default..."
    Copy-Item -Path .\Modules\lib\sc0pe_helper.py -Destination "$env:LOCALAPPDATA\programs\Python\Python310\Lib\site-packages\"
}

# Checking exiftool command
Write-Host "`n$infoS Checking$green exiftool$default command..."
if (Get-Command exiftool -ErrorAction SilentlyContinue) {
    Write-Host "$succesS$green exiftool$default command is already exist."
} else {
    Write-Host "$infoS Fetching version information..."
    $ver = Invoke-WebRequest -Uri "https://exiftool.org/ver.txt"
    $verz = $ver.Content
    Write-Host "$infoS Downloading$green exiftool$default command..."
    wget "https://exiftool.org/exiftool-$verz.zip" -O exiftool.zip
    Write-Host "$infoS Extracting archive..."
    Expand-Archive -Path .\exiftool.zip -DestinationPath .\exiftool
    Write-Host "$infoS Installing command..."
    Move-Item -Path ".\exiftool\exiftool(-k).exe" -Destination .
    Rename-Item -Path ".\exiftool(-k).exe" -NewName ".\exiftool.exe"
    Copy-Item -Path ".\exiftool.exe" -Destination "C:\Windows\System32"
    Write-Host "$infoS Removing junk files..."
    Remove-Item -Path .\exiftool.zip -Force -Recurse
    Remove-Item -Path .\exiftool -Force -Recurse
    Remove-Item -Path ".\exiftool.exe" -Force -Recurse
}

# Check for PyExifTool
Write-Host "`n$infoS Checking$green PyExifTool$default..."
if (dir "$env:LOCALAPPDATA\programs\Python\Python310\Lib\site-packages\" | findstr "PyExifTool") {
    Write-Host "$succesS$green PyExifTool$default is already exist."
} else {
    Write-Host "$infoS Installing$green PyExifTool$default..."
    git clone "https://github.com/smarnach/pyexiftool.git"
    cd .\pyexiftool
    python .\setup.py install
    cd ..
    Remove-Item -Path .\pyexiftool -Force -Recurse
}

# Installing android platform tools
Write-Host "`n$infoS Checking$green Android Platform Tools$default..."
if (Test-Path "$env:HOMEPATH\sc0pe_Base\platform-tools") {
    Write-Host "$succesS$green Android Platform Tools$default is already exist."
} else {
    Write-Host "$infoS Installing$green Android Platform Tools$default..."
    wget "https://dl.google.com/android/repository/platform-tools-latest-windows.zip" -O platform-tools.zip
    Expand-Archive -Path .\platform-tools.zip -DestinationPath .
    Move-Item -Path .\platform-tools -Destination "$env:HOMEPATH\sc0pe_Base\"
    Write-Host "$infoS Configuring$green ADB$default path..."
    $content = Get-Content -Path .\Systems\Windows\windows.conf -Raw
    $modifiedContent = $content -replace [regex]::Escape("\sc0pe_Base\platform-tools\"), "C:$env:HOMEPATH\sc0pe_Base\platform-tools\adb.exe"
    Set-Content -Path .\Systems\Windows\windows.conf -Value $modifiedContent
    Write-Host "$infoS Removing junk files..."
    Remove-Item -Path .\platform-tools.zip -Recurse -Force
}

Write-Host "`n$succesS All done.`n"