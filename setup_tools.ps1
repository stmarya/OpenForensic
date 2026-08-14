#Requires -Version 5.1
<#
.SYNOPSIS
    Installer dependensi OpenForensic.
.DESCRIPTION
    Memasang Volatility 3, oletools, uncompyle6/decompyle3, pycryptodome, binwalk, pefile,
    lalu menyalin executable-nya ke folder bin/. Direktori Scripts Python dideteksi dari
    sysconfig DAN site.USER_BASE agar tetap bekerja pada instalasi global, --user, maupun venv.
    Setiap langkah memeriksa exit code sehingga kegagalan tidak lewat tanpa terdeteksi.
.EXAMPLE
    .\setup_tools.ps1
.EXAMPLE
    .\setup_tools.ps1 -SkipVolatility -SkipWinget
#>

[CmdletBinding()]
param(
    [switch]$SkipVolatility,
    [switch]$SkipPython,
    [switch]$SkipWinget,
    [switch]$IncludeOptional
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$root = $PSScriptRoot
$binDir = Join-Path $root 'bin'
$failures = New-Object System.Collections.ArrayList
$warnings = New-Object System.Collections.ArrayList

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

function Test-OFCommand {
    param([Parameter(Mandatory)][string]$Name)
    return [bool](Get-Command -Name $Name -ErrorAction SilentlyContinue)
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

Write-Host '==========================================' -ForegroundColor Cyan
Write-Host '   OpenForensic - Instalasi Dependensi    ' -ForegroundColor Cyan
Write-Host '==========================================' -ForegroundColor Cyan

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
if (Test-OFCommand 'winget') { Write-Ok 'winget ditemukan.' } else { Write-Warn 'winget tidak ditemukan - ExifTool/7-Zip harus dipasang manual.' }

# 2. Folder bin
Write-Step 'Menyiapkan direktori bin/'
if (-not (Test-Path -LiteralPath $binDir)) {
    New-Item -ItemType Directory -Path $binDir -Force | Out-Null
    Write-Ok 'Folder bin/ dibuat.'
} else {
    Write-Ok 'Folder bin/ sudah ada.'
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
    $packages = @('oletools', 'uncompyle6', 'decompyle3', 'pycryptodome', 'pefile', 'binwalk')
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
        @{ Id = '7zip.7zip'; Name = '7-Zip' }
    )
    if ($IncludeOptional) {
        $wingetPackages += @{ Id = 'WiresharkFoundation.Wireshark'; Name = 'Wireshark (tshark)' }
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

# 6. Menemukan direktori Scripts Python (perbaikan bug utama v0.1.0)
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
        foreach ($path in ($probeOutput -split '\|')) {
            $trimmed = $path.Trim()
            if ($trimmed -and (Test-Path -LiteralPath $trimmed) -and -not $scriptDirs.Contains($trimmed)) {
                [void]$scriptDirs.Add($trimmed)
                Write-Ok "Ditemukan: $trimmed"
            }
        }
    }
    if ($scriptDirs.Count -eq 0) { Write-Fail 'Tidak ada direktori Scripts Python yang valid ditemukan.' }
}

# 7. Menyalin executable ke bin/
if ($scriptDirs.Count -gt 0) {
    Write-Step 'Menyalin executable tool ke bin/'
    $patterns = @('vol.exe', 'volshell.exe', 'ole*.exe', 'mraptor.exe', 'rtfobj.exe', 'msodde.exe', 'uncompyle6*.exe', 'decompyle3*.exe', 'binwalk*.exe')
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

# 8. Verifikasi akhir lewat katalog tool
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
Write-Host "  Lokasi tool: $binDir" -ForegroundColor Cyan
Write-Host '  Jalankan: .\openforensic.bat            ' -ForegroundColor Cyan
Write-Host '==========================================' -ForegroundColor Cyan

if ($failures.Count -gt 0) { exit 1 }
exit 0
