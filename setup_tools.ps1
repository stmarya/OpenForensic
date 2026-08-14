# Script untuk instalasi otomatis alat-alat Digital Forensics CTF
# Dibuat untuk dijalankan melalui PowerShell

$ErrorActionPreference = "Stop"
$CTF_DIR = $PWD
$BIN_DIR = Join-Path $CTF_DIR "bin"

Write-Host "==========================================" -ForegroundColor Cyan
Write-Host "    Memulai Instalasi CTF Tools Otomatis   " -ForegroundColor Cyan
Write-Host "==========================================" -ForegroundColor Cyan

# 1. Membuat folder bin jika belum ada
Write-Host "`n[+] Menyiapkan direktori bin..." -ForegroundColor Yellow
if (-Not (Test-Path $BIN_DIR)) {
    New-Item -ItemType Directory -Force -Path $BIN_DIR | Out-Null
    Write-Host "    Folder bin berhasil dibuat." -ForegroundColor Green
} else {
    Write-Host "    Folder bin sudah ada." -ForegroundColor Green
}

# 2. Mengunduh dan Menginstal Volatility 3
Write-Host "`n[+] Mengunduh dan menginstal Volatility 3..." -ForegroundColor Yellow
if (-Not (Test-Path (Join-Path $CTF_DIR "volatility3"))) {
    git clone https://github.com/volatilityfoundation/volatility3.git
} else {
    Write-Host "    Folder volatility3 sudah ada, melanjutkan instalasi..." -ForegroundColor Green
}
Set-Location -Path "volatility3"
pip install . 
Set-Location -Path $CTF_DIR

# 3. Menginstal tools Python lainnya
Write-Host "`n[+] Menginstal Oletools, Uncompyle6, dan PyCryptodome..." -ForegroundColor Yellow
pip install oletools uncompyle6 pycryptodome

# 4. Menginstal ExifTool menggunakan Winget
Write-Host "`n[+] Menginstal ExifTool..." -ForegroundColor Yellow
if (Get-Command winget -ErrorAction SilentlyContinue) {
    Write-Host "    Winget ditemukan, mencoba menginstal ExifTool..."
    winget install "ExifTool" --accept-source-agreements --accept-package-agreements --silent | Out-Null
    Write-Host "    Proses instalasi ExifTool selesai." -ForegroundColor Green
} else {
    Write-Host "    [-] Winget tidak ditemukan. Silakan unduh ExifTool secara manual." -ForegroundColor Red
}

# 5. Mencari lokasi Scripts Python agar berjalan dinamis (walau versi Python beda)
Write-Host "`n[+] Menemukan lokasi Python Scripts..." -ForegroundColor Yellow
$PYTHON_USER_BASE = python -c "import site; print(site.USER_BASE)"
$PYTHON_SCRIPTS = Join-Path $PYTHON_USER_BASE "Scripts"

# 6. Memindahkan wrapper executable ke folder bin
Write-Host "`n[+] Menyalin executable tools ke folder bin..." -ForegroundColor Yellow
if (Test-Path $PYTHON_SCRIPTS) {
    # Menyalin semua tool yang relevan dan mengabaikan error jika file tidak ada
    $ErrorActionPreference = "SilentlyContinue"
    Copy-Item -Path (Join-Path $PYTHON_SCRIPTS "ole*.exe") -Destination $BIN_DIR -Force
    Copy-Item -Path (Join-Path $PYTHON_SCRIPTS "mraptor.exe") -Destination $BIN_DIR -Force
    Copy-Item -Path (Join-Path $PYTHON_SCRIPTS "rtfobj.exe") -Destination $BIN_DIR -Force
    Copy-Item -Path (Join-Path $PYTHON_SCRIPTS "uncompyle6*.exe") -Destination $BIN_DIR -Force
    Copy-Item -Path (Join-Path $PYTHON_SCRIPTS "vol.exe") -Destination $BIN_DIR -Force
    Copy-Item -Path (Join-Path $PYTHON_SCRIPTS "volshell.exe") -Destination $BIN_DIR -Force
    $ErrorActionPreference = "Stop"
    Write-Host "    Berhasil menyalin executable!" -ForegroundColor Green
} else {
    Write-Host "    [-] Gagal menemukan direktori Python Scripts di $PYTHON_SCRIPTS" -ForegroundColor Red
}

Write-Host "`n==========================================" -ForegroundColor Cyan
Write-Host "  Instalasi Selesai! Tools siap digunakan. " -ForegroundColor Cyan
Write-Host "  Lokasi tools Anda: $BIN_DIR              " -ForegroundColor Cyan
Write-Host "==========================================" -ForegroundColor Cyan
