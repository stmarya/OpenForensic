#Requires -Version 5.1
<#
.SYNOPSIS
    Installer dependensi OpenForensic untuk Windows (39 tool).
.DESCRIPTION
    Memasang seluruh toolchain OpenForensic di Windows:
      1. Prasyarat (Python, Git, winget)
      2. Volatility 3
      3. Paket Python (oletools, yara-python, msoffcrypto-tool, dll)
      4. Tool via winget (ExifTool, 7-Zip, ClamAV, opsional Wireshark)
      5. Unduhan rilis GitHub (Hayabusa, Chainsaw, evtx_dump, YARA, capa, FLOSS, rizin, dll)
      6. Skrip DidierStevensSuite (oledump, zipdump, pdfid, pdf-parser, base64dump)
      7. Menyalin executable ke bin/ + membuat shim .cmd
      8. Verifikasi lewat katalog tool

    Untuk Linux dan macOS gunakan ./setup_tools.sh - script ini memakai winget dan
    shim .cmd yang khusus Windows.

    Setiap unduhan dicatat SHA256-nya di bin/_downloads.log agar dapat diaudit.
    Kegagalan satu tool tidak menghentikan tool lain; ringkasan ditampilkan di akhir.
.EXAMPLE
    .\setup_tools.ps1
.EXAMPLE
    .\setup_tools.ps1 -IncludeOptional -IncludeHeavy
.EXAMPLE
    .\setup_tools.ps1 -SkipVolatility -SkipWinget -Only hayabusa,chainsaw
#>

[CmdletBinding()]
param(
    [switch]$SkipVolatility,
    [switch]$SkipPython,
    [switch]$SkipWinget,
    [switch]$SkipDownload,
    [switch]$IncludeOptional,
    [switch]$IncludeHeavy,
    [string[]]$Only,
    [switch]$Force
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$root = $PSScriptRoot
$binDir = Join-Path $root 'bin'
$rulesDir = Join-Path $root 'rules'
$downloadLog = Join-Path $binDir '_downloads.log'
$failures = New-Object System.Collections.ArrayList
$warnings = New-Object System.Collections.ArrayList
$manualNotes = New-Object System.Collections.ArrayList

# Modul platform dipakai untuk deteksi OS dan direktori sementara. Diimpor lebih awal
# supaya installer bisa menolak berjalan di OS yang salah sebelum mengubah apa pun.
$platformLoaded = $false
try {
    Import-Module (Join-Path $root 'OpenForensic.Platform.psm1') -Force -DisableNameChecking -ErrorAction Stop
    $platformLoaded = $true
} catch {
    Write-Verbose "Modul platform tidak dapat dimuat: $($_.Exception.Message)"
}

function Test-OFSetupWindows {
    if ($platformLoaded -and (Get-Command Test-OFWindows -ErrorAction SilentlyContinue)) {
        return [bool](Test-OFWindows)
    }
    $variable = Get-Variable -Name 'IsWindows' -ErrorAction SilentlyContinue
    if ($variable) { return [bool]$variable.Value }
    # PowerShell 5.1 hanya berjalan di Windows.
    return $true
}

function Get-OFSetupTempRoot {
    if ($platformLoaded -and (Get-Command Get-OFTempDirectory -ErrorAction SilentlyContinue)) {
        return [string](Get-OFTempDirectory)
    }
    return [string][IO.Path]::GetTempPath()
}

if (-not (Test-OFSetupWindows)) {
    Write-Host '[-] setup_tools.ps1 hanya untuk Windows (memakai winget dan shim .cmd).' -ForegroundColor Red
    Write-Host '    Di Linux atau macOS jalankan: ./setup_tools.sh' -ForegroundColor Yellow
    Write-Host '    Lihat juga docs/CROSS-PLATFORM.md dan docs/INSTALL.md.' -ForegroundColor DarkGray
    exit 2
}

# TLS 1.2 wajib untuk api.github.com pada PowerShell 5.1
try {
    [Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12
} catch {
    Write-Verbose "Tidak dapat menyetel TLS 1.2: $($_.Exception.Message)"
}

function Write-Step {
    param([Parameter(Mandatory)][string]$Message)
    Write-Host ''
    Write-Host "[+] $Message" -ForegroundColor Yellow
}

function Write-Ok {
    param([Parameter(Mandatory)][string]$Message)
    Write-Host "    $Message" -ForegroundColor Green
}

function Write-Fail {
    param([Parameter(Mandatory)][string]$Message)
    Write-Host "    [-] $Message" -ForegroundColor Red
    [void]$failures.Add($Message)
}

function Write-Warn {
    param([Parameter(Mandatory)][string]$Message)
    Write-Host "    [!] $Message" -ForegroundColor DarkYellow
    [void]$warnings.Add($Message)
}

function Add-ManualNote {
    param([Parameter(Mandatory)][string]$Message)
    [void]$manualNotes.Add($Message)
}

function Test-OFCommand {
    param([Parameter(Mandatory)][string]$Name)
    return [bool](Get-Command -Name $Name -ErrorAction SilentlyContinue)
}

function Test-OFSelected {
    param([Parameter(Mandatory)][string]$Id)
    if (-not $Only -or $Only.Count -eq 0) { return $true }
    foreach ($item in $Only) {
        if ($item -and $Id -eq $item.Trim()) { return $true }
    }
    return $false
}

# Menjalankan proses eksternal dengan argumen array (tanpa evaluasi shell) dan
# memeriksa exit code secara eksplisit.
function Invoke-Native {
    param(
        [Parameter(Mandatory)][string]$FilePath,
        [AllowEmptyCollection()][string[]]$Arguments = @(),
        [string]$Description = ''
    )
    $label = if ($Description) { $Description } else { "$FilePath $($Arguments -join ' ')" }
    Write-Host "    > $FilePath $($Arguments -join ' ')" -ForegroundColor DarkGray
    & $FilePath @Arguments
    $code = $LASTEXITCODE
    if ($null -eq $code) { $code = 0 }
    if ($code -ne 0) {
        Write-Fail "$label gagal (exit code $code)"
        return $false
    }
    return $true
}

# Mengunduh berkas dan mencatat SHA256-nya ke bin/_downloads.log (jejak audit).
function Save-OFDownload {
    param(
        [Parameter(Mandatory)][string]$Uri,
        [Parameter(Mandatory)][string]$OutFile
    )
    Write-Host "    > unduh $Uri" -ForegroundColor DarkGray
    $progress = $ProgressPreference
    $ProgressPreference = 'SilentlyContinue'
    try {
        Invoke-WebRequest -Uri $Uri -OutFile $OutFile -UseBasicParsing -UserAgent 'OpenForensic-Setup' -ErrorAction Stop
    } finally {
        $ProgressPreference = $progress
    }
    if (-not (Test-Path -LiteralPath $OutFile)) { throw "Unduhan gagal: $Uri" }
    $hash = (Get-FileHash -LiteralPath $OutFile -Algorithm SHA256).Hash
    $size = (Get-Item -LiteralPath $OutFile).Length
    $line = '{0}  SHA256={1}  bytes={2}  url={3}' -f (Get-Date -Format 'yyyy-MM-dd HH:mm:ss'), $hash, $size, $Uri
    Add-Content -LiteralPath $downloadLog -Value $line -Encoding UTF8
    Write-Host "      SHA256 $hash" -ForegroundColor DarkGray
    return $hash
}

# Mencari asset rilis terbaru pada repo GitHub berdasarkan pola nama.
function Resolve-OFGitHubAsset {
    param(
        [Parameter(Mandatory)][string]$Repo,
        [Parameter(Mandatory)][string]$AssetPattern
    )
    $api = "https://api.github.com/repos/$Repo/releases/latest"
    $headers = @{ 'User-Agent' = 'OpenForensic-Setup'; 'Accept' = 'application/vnd.github+json' }
    if ($env:GITHUB_TOKEN) { $headers['Authorization'] = "Bearer $($env:GITHUB_TOKEN)" }
    $release = Invoke-RestMethod -Uri $api -Headers $headers -UseBasicParsing -ErrorAction Stop
    $assets = @($release.assets | Where-Object { $_.name -match $AssetPattern })
    if ($assets.Count -eq 0) { return $null }
    $asset = $assets | Sort-Object -Property name -Descending | Select-Object -First 1
    return [pscustomobject]@{
        Tag  = $release.tag_name
        Name = $asset.name
        Url  = $asset.browser_download_url
    }
}

# Membuat shim .cmd di bin/ supaya tool yang butuh folder pendukung (rules, mappings, lib)
# tetap bisa dipanggil dengan satu nama. UsePushd dipakai untuk tool yang mencari resource
# relatif terhadap direktori kerja (Hayabusa, Chainsaw, jadx, rizin).
function New-OFShim {
    param(
        [Parameter(Mandatory)][string]$Name,
        [Parameter(Mandatory)][string]$RelativeTarget,
        [switch]$UsePushd,
        [string]$Interpreter
    )
    $shimPath = Join-Path $binDir ("$Name.cmd")
    $lines = New-Object System.Collections.ArrayList
    [void]$lines.Add('@echo off')
    [void]$lines.Add('setlocal')
    if ($UsePushd) {
        $dir = Split-Path -Path $RelativeTarget -Parent
        $leaf = Split-Path -Path $RelativeTarget -Leaf
        [void]$lines.Add("pushd \"%~dp0$dir\"")
        if ($Interpreter) {
            [void]$lines.Add("$Interpreter \"$leaf\" %*")
        } else {
            [void]$lines.Add("\"$leaf\" %*")
        }
        [void]$lines.Add('set OF_RC=%ERRORLEVEL%')
        [void]$lines.Add('popd')
        [void]$lines.Add('exit /b %OF_RC%')
    } else {
        if ($Interpreter) {
            [void]$lines.Add("$Interpreter \"%~dp0$RelativeTarget\" %*")
        } else {
            [void]$lines.Add("\"%~dp0$RelativeTarget\" %*")
        }
        [void]$lines.Add('exit /b %ERRORLEVEL%')
    }
    Set-Content -LiteralPath $shimPath -Value $lines -Encoding ASCII
    return $shimPath
}

Write-Host '==========================================' -ForegroundColor Cyan
Write-Host '   OpenForensic - Instalasi Dependensi    ' -ForegroundColor Cyan
Write-Host '==========================================' -ForegroundColor Cyan
if ($platformLoaded -and (Get-Command Get-OFPlatform -ErrorAction SilentlyContinue)) {
    $platform = Get-OFPlatform
    Write-Host "   Lingkungan: $($platform.Os) $($platform.Architecture) | PowerShell $($platform.PSVersion) $($platform.PSEdition)" -ForegroundColor DarkGray
}

# 1. Prasyarat
Write-Step 'Memeriksa prasyarat'
$pythonCmd = $null
foreach ($candidate in @('python', 'python3', 'py')) {
    if (Test-OFCommand $candidate) { $pythonCmd = $candidate; break }
}
if ($pythonCmd) {
    $pythonVersion = (& $pythonCmd --version 2>&1) -join ' '
    Write-Ok "Python ditemukan: $pythonVersion (perintah: $pythonCmd)"
} else {
    Write-Fail 'Python tidak ditemukan di PATH. Pasang Python 3.8+ lalu jalankan ulang.'
}
if (Test-OFCommand 'git') { Write-Ok 'Git ditemukan.' } else { Write-Warn 'Git tidak ditemukan - Volatility 3 tidak dapat di-clone.' }
if (Test-OFCommand 'winget') { Write-Ok 'winget ditemukan.' } else { Write-Warn 'winget tidak ditemukan - ExifTool/7-Zip/ClamAV harus dipasang manual.' }

# 2. Folder kerja
Write-Step 'Menyiapkan direktori bin/ dan rules/'
foreach ($dir in @($binDir, $rulesDir)) {
    if (-not (Test-Path -LiteralPath $dir)) {
        New-Item -ItemType Directory -Path $dir -Force | Out-Null
        Write-Ok "Folder $(Split-Path -Path $dir -Leaf)/ dibuat."
    } else {
        Write-Ok "Folder $(Split-Path -Path $dir -Leaf)/ sudah ada."
    }
}
$rulesReadme = Join-Path $rulesDir 'README.md'
if (-not (Test-Path -LiteralPath $rulesReadme)) {
    $rulesText = @(
        '# Folder rules YARA',
        '',
        'Letakkan berkas *.yar / *.yara di sini. Katalog tool (tools.json) membaca folder ini',
        'sebagai daftar plugin untuk tool `yara`.',
        '',
        'Sumber rule yang umum dipakai (periksa lisensinya sebelum dipakai komersial):',
        '',
        '- https://github.com/Neo23x0/signature-base (CC BY-NC 4.0)',
        '- https://github.com/Yara-Rules/rules',
        '- https://github.com/elastic/protections-artifacts',
        '',
        'Uji rule sebelum dipakai pada perkara nyata.'
    )
    Set-Content -LiteralPath $rulesReadme -Value $rulesText -Encoding UTF8
    Write-Ok 'rules/README.md dibuat.'
}

# 3. Volatility 3
if (-not $SkipVolatility -and $pythonCmd -and (Test-OFCommand 'git')) {
    Write-Step 'Memasang Volatility 3'
    $volatilityDir = Join-Path $root 'volatility3'
    $ready = $true
    if (-not (Test-Path -LiteralPath $volatilityDir)) {
        $ready = Invoke-Native -FilePath 'git' -Arguments @('clone', '--depth', '1', 'https://github.com/volatilityfoundation/volatility3.git', $volatilityDir) -Description 'git clone volatility3'
    } else {
        Write-Ok 'Folder volatility3 sudah ada, melanjutkan instalasi.'
    }
    if ($ready) {
        Push-Location -LiteralPath $volatilityDir
        try {
            if (Invoke-Native -FilePath $pythonCmd -Arguments @('-m', 'pip', 'install', '--upgrade', '.') -Description 'pip install volatility3') {
                Write-Ok 'Volatility 3 terpasang.'
            }
        } finally {
            Pop-Location
        }
    }
} elseif ($SkipVolatility) {
    Write-Step 'Volatility 3 dilewati (-SkipVolatility)'
}

# 4. Paket Python
if (-not $SkipPython -and $pythonCmd) {
    Write-Step 'Memasang paket Python'
    $packages = @(
        'oletools',
        'msoffcrypto-tool',
        'uncompyle6',
        'decompyle3',
        'pycryptodome',
        'pefile',
        'binwalk',
        'yara-python',
        'python-registry',
        'chardet'
    )
    if ($IncludeHeavy) {
        $packages += @('flare-capa', 'flare-floss')
    }
    foreach ($package in $packages) {
        if (Invoke-Native -FilePath $pythonCmd -Arguments @('-m', 'pip', 'install', '--upgrade', $package) -Description "pip install $package") {
            Write-Ok "$package terpasang."
        } else {
            Write-Warn "$package gagal dipasang - lanjut ke paket berikutnya."
        }
    }
} elseif ($SkipPython) {
    Write-Step 'Paket Python dilewati (-SkipPython)'
}

# 5. Tool via winget
if (-not $SkipWinget -and (Test-OFCommand 'winget')) {
    Write-Step 'Memasang tool eksternal via winget'
    $wingetPackages = @(
        @{ Id = 'OliverBetz.ExifTool'; Name = 'ExifTool' },
        @{ Id = '7zip.7zip'; Name = '7-Zip' },
        @{ Id = 'ClamAV.ClamAV'; Name = 'ClamAV (clamscan)' },
        @{ Id = 'SQLite.SQLite'; Name = 'SQLite tools (sqlite3)' }
    )
    if ($IncludeOptional) {
        $wingetPackages += @{ Id = 'WiresharkFoundation.Wireshark'; Name = 'Wireshark (tshark, capinfos)' }
    }
    foreach ($package in $wingetPackages) {
        $arguments = @('install', '--id', $package.Id, '--exact', '--accept-source-agreements', '--accept-package-agreements', '--silent', '--disable-interactivity')
        & winget @arguments | Out-Null
        $code = $LASTEXITCODE
        if ($null -eq $code) { $code = 0 }
        # -1978335189 = paket sudah terpasang / tidak ada update
        if ($code -eq 0 -or $code -eq -1978335189) {
            Write-Ok "$($package.Name) siap."
        } else {
            Write-Warn "$($package.Name) gagal dipasang (exit $code). Pasang manual bila diperlukan."
        }
    }
} elseif ($SkipWinget) {
    Write-Step 'winget dilewati (-SkipWinget)'
}

# 6. Unduhan rilis (GitHub releases + URL vendor)
$downloads = @(
    @{ Id = 'evtxdump'; Name = 'evtx_dump'; Repo = 'omerbenamram/evtx'; Asset = 'evtx_dump-.*pc-windows-msvc\\.exe$'; Type = 'exe'; TargetName = 'evtx_dump.exe'; Alias = @('evtxdump') },
    @{ Id = 'hayabusa'; Name = 'Hayabusa'; Repo = 'Yamato-Security/hayabusa'; Asset = 'hayabusa-.*win.*\\.zip$'; Type = 'zip'; Exe = 'hayabusa*.exe'; Pushd = $true },
    @{ Id = 'chainsaw'; Name = 'Chainsaw'; Repo = 'WithSecureLabs/chainsaw'; Asset = '(windows|all_platforms).*\\.zip$'; Type = 'zip'; Exe = 'chainsaw*.exe'; Pushd = $true },
    @{ Id = 'yara'; Name = 'YARA'; Repo = 'VirusTotal/yara'; Asset = 'yara-.*win64.*\\.zip$'; Type = 'zip'; Exe = 'yara*.exe' },
    @{ Id = 'capa'; Name = 'capa'; Repo = 'mandiant/capa'; Asset = 'capa-.*windows.*\\.zip$'; Type = 'zip'; Exe = 'capa.exe' },
    @{ Id = 'floss'; Name = 'FLOSS'; Repo = 'mandiant/flare-floss'; Asset = 'floss-.*windows.*\\.zip$'; Type = 'zip'; Exe = 'floss.exe' },
    @{ Id = 'rizin'; Name = 'rizin'; Repo = 'rizinorg/rizin'; Asset = 'rizin-.*w64.*\\.zip$'; Type = 'zip'; Exe = 'rizin.exe'; Pushd = $true },
    @{ Id = 'stegseek'; Name = 'Stegseek'; Repo = 'RickdeJager/stegseek'; Asset = '.*(windows|win64).*\\.zip$'; Type = 'zip'; Exe = 'stegseek.exe' },
    @{ Id = 'jadx'; Name = 'jadx'; Repo = 'skylot/jadx'; Asset = '^jadx-[0-9].*\\.zip$'; Type = 'zip'; Exe = 'jadx.bat'; Pushd = $true },
    @{ Id = 'mftecmd'; Name = 'MFTECmd'; Url = 'https://download.ericzimmermanstools.com/net9/MFTECmd.zip'; Type = 'zip'; Exe = 'MFTECmd.exe' },
    @{ Id = 'photorec'; Name = 'TestDisk/PhotoRec'; Url = 'https://www.cgsecurity.org/testdisk-7.2.win.zip'; Type = 'zip'; Exe = 'photorec_win.exe'; Alias = @('photorec'); Optional = $true },
    @{ Id = 'bulkextractor'; Name = 'bulk_extractor'; Repo = 'simsong/bulk_extractor'; Asset = '.*win.*\\.zip$'; Type = 'zip'; Exe = 'bulk_extractor*.exe'; Heavy = $true }
)

if (-not $SkipDownload) {
    Write-Step 'Mengunduh tool rilis (GitHub / vendor)'
    # Direktori sementara mengikuti lapisan platform (Get-OFTempDirectory), bukan
    # variabel environment khusus Windows.
    $tempDir = Join-Path (Get-OFSetupTempRoot) ('of_setup_' + [Guid]::NewGuid().ToString('N').Substring(0, 8))
    New-Item -ItemType Directory -Path $tempDir -Force | Out-Null
    Write-Host "    Staging: $tempDir" -ForegroundColor DarkGray
    try {
        foreach ($item in $downloads) {
            if (-not (Test-OFSelected -Id $item.Id)) { continue }
            if ($item.ContainsKey('Heavy') -and $item.Heavy -and -not $IncludeHeavy) {
                Write-Host "    [skip] $($item.Name) - gunakan -IncludeHeavy" -ForegroundColor DarkGray
                continue
            }
            if ($item.ContainsKey('Optional') -and $item.Optional -and -not $IncludeOptional) {
                Write-Host "    [skip] $($item.Name) - gunakan -IncludeOptional" -ForegroundColor DarkGray
                continue
            }

            $targetDir = Join-Path $binDir $item.Id
            if ((Test-Path -LiteralPath $targetDir) -and -not $Force) {
                Write-Ok "$($item.Name) sudah ada di bin/$($item.Id) (pakai -Force untuk pasang ulang)."
                continue
            }

            try {
                $url = $null
                $fileName = $null
                if ($item.ContainsKey('Repo')) {
                    $asset = Resolve-OFGitHubAsset -Repo $item.Repo -AssetPattern $item.Asset
                    if (-not $asset) {
                        Write-Warn "$($item.Name): tidak ada asset Windows pada rilis terbaru $($item.Repo). Unduh manual."
                        Add-ManualNote "$($item.Name) -> https://github.com/$($item.Repo)/releases"
                        continue
                    }
                    $url = $asset.Url
                    $fileName = $asset.Name
                    Write-Host "    $($item.Name) rilis $($asset.Tag): $fileName" -ForegroundColor Gray
                } else {
                    $url = $item.Url
                    $fileName = Split-Path -Path $item.Url -Leaf
                }

                $downloadPath = Join-Path $tempDir $fileName
                Save-OFDownload -Uri $url -OutFile $downloadPath | Out-Null

                if ($item.Type -eq 'exe') {
                    $destination = Join-Path $binDir $item.TargetName
                    Copy-Item -LiteralPath $downloadPath -Destination $destination -Force
                    if ($item.ContainsKey('Alias')) {
                        foreach ($alias in $item.Alias) {
                            New-OFShim -Name $alias -RelativeTarget $item.TargetName | Out-Null
                        }
                    }
                    Write-Ok "$($item.Name) siap: bin/$($item.TargetName)"
                    continue
                }

                if (Test-Path -LiteralPath $targetDir) { Remove-Item -LiteralPath $targetDir -Recurse -Force }
                New-Item -ItemType Directory -Path $targetDir -Force | Out-Null
                Expand-Archive -LiteralPath $downloadPath -DestinationPath $targetDir -Force

                # Jika arsip hanya berisi satu folder, naikkan isinya satu level.
                $entries = @(Get-ChildItem -LiteralPath $targetDir)
                if ($entries.Count -eq 1 -and $entries[0].PSIsContainer) {
                    $inner = $entries[0].FullName
                    Get-ChildItem -LiteralPath $inner -Force | ForEach-Object {
                        Move-Item -LiteralPath $_.FullName -Destination $targetDir -Force
                    }
                    Remove-Item -LiteralPath $inner -Recurse -Force
                }

                $exe = @(Get-ChildItem -LiteralPath $targetDir -Filter $item.Exe -File -Recurse -ErrorAction SilentlyContinue | Select-Object -First 1)
                if ($exe.Count -eq 0) {
                    Write-Warn "$($item.Name): executable '$($item.Exe)' tidak ditemukan setelah ekstraksi. Periksa bin/$($item.Id)."
                    continue
                }
                $separator = [string][IO.Path]::DirectorySeparatorChar
                $relative = $exe[0].FullName.Substring($binDir.Length).TrimStart($separator, '/')
                $usePushd = ($item.ContainsKey('Pushd') -and $item.Pushd)
                $shimNames = New-Object System.Collections.ArrayList
                [void]$shimNames.Add($item.Id)
                [void]$shimNames.Add([IO.Path]::GetFileNameWithoutExtension($exe[0].Name))
                if ($item.ContainsKey('Alias')) { foreach ($alias in $item.Alias) { [void]$shimNames.Add($alias) } }
                $uniqueShims = @($shimNames | Select-Object -Unique)
                foreach ($shimName in $uniqueShims) {
                    if ($usePushd) {
                        New-OFShim -Name $shimName -RelativeTarget $relative -UsePushd | Out-Null
                    } else {
                        New-OFShim -Name $shimName -RelativeTarget $relative | Out-Null
                    }
                }
                Write-Ok "$($item.Name) siap: bin/$relative (shim: $($uniqueShims -join ', '))"
            } catch {
                Write-Warn "$($item.Name) gagal dipasang: $($_.Exception.Message)"
            }
        }
    } finally {
        Remove-Item -LiteralPath $tempDir -Recurse -Force -ErrorAction SilentlyContinue
    }
} else {
    Write-Step 'Unduhan rilis dilewati (-SkipDownload)'
}

# 7. Skrip DidierStevensSuite (pdfid, pdf-parser, oledump, zipdump, base64dump)
$dsScripts = @(
    @{ Id = 'pdfid'; Script = 'pdfid.py' },
    @{ Id = 'pdfparser'; Script = 'pdf-parser.py' },
    @{ Id = 'oledump'; Script = 'oledump.py' },
    @{ Id = 'zipdump'; Script = 'zipdump.py' },
    @{ Id = 'base64dump'; Script = 'base64dump.py' }
)

if (-not $SkipDownload -and $pythonCmd) {
    Write-Step 'Mengunduh DidierStevensSuite'
    $dsBase = 'https://raw.githubusercontent.com/DidierStevens/DidierStevensSuite/master/'
    $dsDir = Join-Path $binDir 'didierstevens'
    if (-not (Test-Path -LiteralPath $dsDir)) { New-Item -ItemType Directory -Path $dsDir -Force | Out-Null }
    foreach ($item in $dsScripts) {
        if (-not (Test-OFSelected -Id $item.Id)) { continue }
        $scriptPath = Join-Path $dsDir $item.Script
        if ((Test-Path -LiteralPath $scriptPath) -and -not $Force) {
            Write-Ok "$($item.Script) sudah ada."
        } else {
            try {
                Save-OFDownload -Uri ($dsBase + $item.Script) -OutFile $scriptPath | Out-Null
            } catch {
                Write-Warn "$($item.Script) gagal diunduh: $($_.Exception.Message)"
                continue
            }
        }
        $relative = Join-Path 'didierstevens' $item.Script
        $shimNames = @($item.Id, [IO.Path]::GetFileNameWithoutExtension($item.Script)) | Select-Object -Unique
        foreach ($shimName in $shimNames) {
            New-OFShim -Name $shimName -RelativeTarget $relative -Interpreter $pythonCmd | Out-Null
        }
        Write-Ok "$($item.Script) siap (shim: $($shimNames -join ', '))"
    }
}

# 8. Menemukan direktori Scripts Python
$scriptDirs = New-Object System.Collections.ArrayList
if ($pythonCmd) {
    Write-Step 'Mencari direktori Scripts Python'
    $probe = 'import sysconfig, site, os' + "`n" +
             'paths = [sysconfig.get_path("scripts")]' + "`n" +
             'try:' + "`n" +
             '    paths.append(sysconfig.get_path("scripts", scheme="nt_user"))' + "`n" +
             'except Exception:' + "`n" +
             '    pass' + "`n" +
             'paths.append(os.path.join(site.USER_BASE, "Scripts"))' + "`n" +
             'print("|".join([p for p in paths if p]))'
    $probeOutput = (& $pythonCmd '-c' $probe 2>&1) -join ''
    if ($LASTEXITCODE -eq 0 -and $probeOutput) {
        foreach ($path in ($probeOutput -split '\\|')) {
            $trimmed = $path.Trim()
            if ($trimmed -and (Test-Path -LiteralPath $trimmed) -and -not $scriptDirs.Contains($trimmed)) {
                [void]$scriptDirs.Add($trimmed)
                Write-Ok "Ditemukan: $trimmed"
            }
        }
    }
    if ($scriptDirs.Count -eq 0) { Write-Fail 'Tidak ada direktori Scripts Python yang valid ditemukan.' }
}

# 9. Menyalin executable Python ke bin/
if ($scriptDirs.Count -gt 0) {
    Write-Step 'Menyalin executable tool ke bin/'
    $patterns = @(
        'vol.exe', 'volshell.exe',
        'ole*.exe', 'mraptor.exe', 'rtfobj.exe', 'msodde.exe',
        'msoffcrypto-tool.exe',
        'uncompyle6*.exe', 'decompyle3*.exe',
        'binwalk*.exe',
        'capa.exe', 'floss.exe'
    )
    $copied = 0
    foreach ($dir in $scriptDirs) {
        foreach ($pattern in $patterns) {
            $matched = @(Get-ChildItem -Path (Join-Path $dir $pattern) -File -ErrorAction SilentlyContinue)
            foreach ($file in $matched) {
                try {
                    Copy-Item -LiteralPath $file.FullName -Destination $binDir -Force
                    $copied++
                } catch {
                    Write-Warn "Gagal menyalin $($file.Name): $($_.Exception.Message)"
                }
            }
        }
    }
    if ($copied -gt 0) { Write-Ok "$copied executable disalin ke bin/." } else { Write-Fail 'Tidak ada executable yang berhasil disalin. Periksa apakah pip install berhasil.' }
}

# 10. Tool yang tetap perlu langkah manual
Add-ManualNote 'RegRipper 3.0 (regripper) -> https://github.com/keydet89/RegRipper3.0'
Add-ManualNote 'John the Ripper jumbo (john) -> https://www.openwall.com/john/ (taruh john.exe di bin/)'
Add-ManualNote 'pngcheck (pngcheck) -> http://www.libpng.org/pub/png/apps/pngcheck.html'
Add-ManualNote 'steghide (steghide) -> https://sourceforge.net/projects/steghide/'
Add-ManualNote 'zsteg (zsteg) -> butuh Ruby: gem install zsteg'
Add-ManualNote 'Rule YARA -> letakkan berkas .yar di folder rules/ (lihat rules/README.md)'

# 11. Verifikasi akhir lewat katalog tool
Write-Step 'Verifikasi ketersediaan tool'
try {
    Import-Module (Join-Path $root 'OpenForensic.psd1') -Force
    $status = @(Get-OFToolStatus)
    foreach ($tool in $status) {
        if ($tool.Available) {
            Write-Host ('    [ok] {0,-16} {1}' -f $tool.Id, $tool.Path) -ForegroundColor Green
        } else {
            Write-Host ('    [--] {0,-16} {1}' -f $tool.Id, $tool.InstallHint) -ForegroundColor DarkGray
        }
    }
    $availableCount = @($status | Where-Object { $_.Available }).Count
    Write-Host "    Total siap: $availableCount / $($status.Count)" -ForegroundColor Cyan
} catch {
    Write-Warn "Verifikasi lewat modul gagal: $($_.Exception.Message)"
}

Write-Host ''
Write-Host '==========================================' -ForegroundColor Cyan
if ($failures.Count -eq 0) {
    Write-Host '  Instalasi selesai tanpa error.           ' -ForegroundColor Green
} else {
    Write-Host "  Instalasi selesai dengan $($failures.Count) error:" -ForegroundColor Red
    foreach ($failure in $failures) { Write-Host "   - $failure" -ForegroundColor Red }
}
if ($warnings.Count -gt 0) {
    Write-Host "  Peringatan: $($warnings.Count)" -ForegroundColor DarkYellow
}
if ($manualNotes.Count -gt 0) {
    Write-Host ''
    Write-Host '  Perlu langkah manual:' -ForegroundColor DarkYellow
    foreach ($note in ($manualNotes | Select-Object -Unique)) { Write-Host "   - $note" -ForegroundColor DarkGray }
}
Write-Host ''
Write-Host "  Lokasi tool     : $binDir" -ForegroundColor Cyan
Write-Host "  Log unduhan     : $downloadLog" -ForegroundColor Cyan
Write-Host '  Jalankan alur   : .\case.ps1 -Path <bukti> -CaseName "<nama kasus>"' -ForegroundColor Cyan
Write-Host '  Menu interaktif : .\openforensic.bat' -ForegroundColor Cyan
Write-Host '  Diagnostik      : .\doctor.ps1' -ForegroundColor Cyan
Write-Host '==========================================' -ForegroundColor Cyan

if ($failures.Count -gt 0) { exit 1 }
exit 0
