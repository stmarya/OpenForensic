Add-Type -AssemblyName System.Windows.Forms

function Select-FileDialog {
    param([string]$Filter = "All Files (*.*)|*.*")
    $dialog = New-Object System.Windows.Forms.OpenFileDialog
    $dialog.Filter = $Filter
    $dialog.Title = "Pilih file target untuk dianalisis"
    $dialog.InitialDirectory = $PSScriptRoot
    if ($dialog.ShowDialog() -eq 'OK') {
        return $dialog.FileName
    }
    return $null
}

$BIN_DIR = Join-Path $PSScriptRoot "bin"
$REPORTS_DIR = Join-Path $PSScriptRoot "reports"
$CONFIG_FILE = Join-Path $PSScriptRoot ".ai_config"

if (-Not (Test-Path $REPORTS_DIR)) { New-Item -ItemType Directory -Force -Path $REPORTS_DIR | Out-Null }

while ($true) {
    Clear-Host
    Write-Host "==========================================================" -ForegroundColor Cyan
    Write-Host "   __ __            ___  ________   ____ __   " -ForegroundColor Cyan
    Write-Host "  / //_/___ _____  / _ \/ ___/ _ \ /_  // /__ " -ForegroundColor Cyan
    Write-Host " / ,< / __ `/ __ \/ // / /__/ , _/  / // //_/ " -ForegroundColor Cyan
    Write-Host "/_/|_|\__,_/_/ /_/\___/\___/_/|_|  /_//_/\_\  " -ForegroundColor Cyan
    Write-Host "==========================================================" -ForegroundColor Cyan
    Write-Host "        Interactive Digital Forensics Toolkit             " -ForegroundColor Yellow
    Write-Host "==========================================================" -ForegroundColor Cyan
    Write-Host ""
    Write-Host " [1] Volatility 3   (Analisis Memori / RAM)"
    Write-Host " [2] Uncompyle6     (Decompile File Python .pyc)"
    Write-Host " [3] Oleid          (Cek Indikator Bahaya Dokumen)"
    Write-Host " [4] Olevba         (Ekstrak Macro VBA dari Dokumen)"
    Write-Host " [5] Mraptor        (Deteksi Script Jahat pada Dokumen)"
    Write-Host " [6] ExifTool       (Metadata & Steganografi Dasar)"
    Write-Host " [7] ⚡ MAGIC TRIAGE (Auto-Analyze Berdasarkan Tipe File)"
    Write-Host " [8] 🤖 AI ANALYST  (Minta AI Menganalisis Log Report)"
    Write-Host " [99] Update Tools  (Perbarui versi semua tools)"
    Write-Host " [0] Keluar dari Kan9Ch3k"
    Write-Host ""
    
    $choice = Read-Host "Pilih menu (0-8, 99)"

    if ($choice -eq '0') {
        Write-Host "Terima kasih telah menggunakan Kan9Ch3k! Stay safe." -ForegroundColor Green
        break
    }

    if ($choice -eq '99') {
        Write-Host "`n[+] Memperbarui Tools..." -ForegroundColor Yellow
        Write-Host "    Mengupdate Volatility 3 dari GitHub..."
        if (Test-Path (Join-Path $PSScriptRoot "volatility3")) {
            Push-Location (Join-Path $PSScriptRoot "volatility3")
            git pull
            pip install --upgrade .
            Pop-Location
        }
        Write-Host "    Mengupdate pip packages (oletools, uncompyle6, dll)..."
        pip install --upgrade oletools uncompyle6 pycryptodome
        Write-Host "[+] Selesai memperbarui." -ForegroundColor Green
        Pause
        continue
    }

    if ($choice -eq '8') {
        $apiKey = ""
        if (Test-Path $CONFIG_FILE) {
            $apiKey = Get-Content $CONFIG_FILE
        } else {
            Write-Host "`n[!] Anda membutuhkan Gemini API Key untuk menggunakan fitur AI ini." -ForegroundColor Yellow
            Write-Host "    Dapatkan secara gratis di: https://aistudio.google.com/app/apikey"
            $apiKey = Read-Host "Masukkan Gemini API Key Anda"
            if (-not [string]::IsNullOrWhiteSpace($apiKey)) {
                Set-Content -Path $CONFIG_FILE -Value $apiKey
            } else {
                Write-Host "[-] API Key kosong. Dibatalkan." -ForegroundColor Red
                Pause
                continue
            }
        }

        $reports = Get-ChildItem -Path $REPORTS_DIR -Filter "*.txt" | Sort-Object LastWriteTime -Descending
        if ($reports.Count -eq 0) {
            Write-Host "[-] Belum ada report yang terbuat. Silakan jalankan analisis file terlebih dahulu!" -ForegroundColor Red
            Pause
            continue
        }

        Write-Host "`n[Pilih Report Terbaru untuk Dianalisis]" -ForegroundColor Cyan
        $i = 1
        foreach ($rep in $reports) {
            Write-Host " [$i] $($rep.Name)"
            $i++
            if ($i -gt 10) { break }
        }
        $repChoice = Read-Host "Masukkan nomor report (1-$($i-1))"
        $repChoiceInt = [int]$repChoice
        
        if ($repChoiceInt -ge 1 -and $repChoiceInt -lt $i) {
            $selectedReport = $reports[$repChoiceInt-1]
            Write-Host "`nMembaca isi report: $($selectedReport.Name)..." -ForegroundColor Yellow
            $reportContent = Get-Content $selectedReport.FullName -Raw
            
            if ($reportContent.Length -gt 100000) {
                $reportContent = $reportContent.Substring(0, 100000) + "`n...[TRUNCATED]"
            }

            $prompt = @"
Anda adalah Senior Digital Forensics Analyst. Tugas Anda adalah membantu menemukan malware, vulnerability, flag CTF tersembunyi, atau keanehan dari hasil log analisis tools di bawah ini.
Berikan kesimpulan tingkat bahaya, dan jelaskan temuan Anda dalam bahasa Indonesia secara rapi dengan poin-poin.

LOG ANALISIS:
$reportContent
"@
            
            Write-Host "Mengirim data ke Gemini AI untuk dianalisis... (Mohon tunggu)" -ForegroundColor Yellow
            
            $body = @{
                contents = @(
                    @{
                        parts = @(
                            @{ text = $prompt }
                        )
                    }
                )
            } | ConvertTo-Json -Depth 10

            try {
                $response = Invoke-RestMethod -Uri "https://generativelanguage.googleapis.com/v1beta/models/gemini-1.5-flash:generateContent?key=$apiKey" -Method Post -ContentType "application/json" -Body $body
                
                $aiText = $response.candidates[0].content.parts[0].text
                Write-Host "`n========================= 🤖 HASIL ANALISIS AI =========================" -ForegroundColor Magenta
                Write-Host $aiText -ForegroundColor White
                Write-Host "==========================================================================" -ForegroundColor Magenta
            } catch {
                Write-Host "[-] Gagal menghubungi API Gemini: $_" -ForegroundColor Red
                Write-Host "Pastikan API Key Anda valid dan koneksi internet stabil." -ForegroundColor Red
                $reset = Read-Host "Apakah Anda ingin mereset API Key? (y/n)"
                if ($reset -eq 'y') { Remove-Item $CONFIG_FILE -Force }
            }
        } else {
            Write-Host "[-] Pilihan tidak valid." -ForegroundColor Red
        }
        Pause
        continue
    }

    Write-Host "`n[+] Membuka jendela pemilihan file..." -ForegroundColor Yellow
    $file = Select-FileDialog
    if ([string]::IsNullOrEmpty($file)) {
        Write-Host "[-] Tidak ada file yang dipilih. Dibatalkan." -ForegroundColor Red
        Pause
        continue
    }
    
    $filename = Split-Path $file -Leaf
    $ext = (Get-Item $file).Extension.ToLower()

    # Siapkan Auto-Report
    $timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
    $reportFile = Join-Path $REPORTS_DIR "${timestamp}_${filename}_report.txt"

    Write-Host "`n========================= HASIL ANALISIS =========================" -ForegroundColor Magenta
    Write-Host "[Target File]: $file" -ForegroundColor Green
    Write-Host "[Report Disimpan ke]: $reportFile" -ForegroundColor Cyan
    Write-Host "------------------------------------------------------------------" -ForegroundColor Magenta

    # Fungsi untuk menjalankan perintah dan merekamnya ke file
    function Run-And-Log {
        param([string]$cmdPath, [string]$argsStr)
        Write-Host "`n> Menjalankan: $cmdPath $argsStr" -ForegroundColor DarkGray
        
        Add-Content -Path $reportFile -Value "`n======================================================="
        Add-Content -Path $reportFile -Value "COMMAND: $cmdPath $argsStr"
        Add-Content -Path $reportFile -Value "=======================================================`n"
        
        $fullCmd = "& `"$cmdPath`" $argsStr"
        Invoke-Expression $fullCmd | Tee-Object -FilePath $reportFile -Append
    }

    if ($choice -eq '7') {
        # MAGIC TRIAGE
        Write-Host "Memulai Magic Triage untuk $filename ..." -ForegroundColor Yellow
        if ($ext -match "\.dmp|\.raw|\.vmem|\.img|\.mem") {
            Run-And-Log (Join-Path $BIN_DIR "vol.exe") "-f `"$file`" windows.info"
            Run-And-Log (Join-Path $BIN_DIR "vol.exe") "-f `"$file`" windows.pslist"
        } elseif ($ext -match "\.pyc") {
            Run-And-Log (Join-Path $BIN_DIR "uncompyle6.exe") "`"$file`""
        } elseif ($ext -match "\.doc|\.xls|\.ppt|\.docx|\.xlsm|\.rtf") {
            Run-And-Log (Join-Path $BIN_DIR "oleid.exe") "`"$file`""
            Run-And-Log (Join-Path $BIN_DIR "olevba.exe") "`"$file`""
            Run-And-Log (Join-Path $BIN_DIR "mraptor.exe") "`"$file`""
        } else {
            if (Get-Command exiftool -ErrorAction SilentlyContinue) {
                Run-And-Log "exiftool" "`"$file`""
            } else {
                Write-Host "[-] File ini tidak dikenali spesifikasinya, dan ExifTool tidak terinstall." -ForegroundColor Red
            }
        }
    } else {
        $tool = ""
        switch ($choice) {
            '1' { $tool = Join-Path $BIN_DIR "vol.exe" }
            '2' { $tool = Join-Path $BIN_DIR "uncompyle6.exe" }
            '3' { $tool = Join-Path $BIN_DIR "oleid.exe" }
            '4' { $tool = Join-Path $BIN_DIR "olevba.exe" }
            '5' { $tool = Join-Path $BIN_DIR "mraptor.exe" }
            '6' { $tool = "exiftool" }
        }

        if ($choice -eq '1') {
            Write-Host "`n[Volatility Plugins]" -ForegroundColor Cyan
            Write-Host " [1] windows.info      (Menampilkan informasi OS)"
            Write-Host " [2] windows.pslist    (Daftar proses/program)"
            Write-Host " [3] windows.netscan   (Koneksi jaringan)"
            Write-Host " [4] windows.filescan  (Cari file)"
            Write-Host " [5] windows.cmdline   (Argumen program)"
            Write-Host " [6] *Manual input plugin lainnya*"
            
            $plugChoice = Read-Host "Pilih plugin (1-6)"
            $plugin = "windows.info"
            switch ($plugChoice) {
                '1' { $plugin = "windows.info" }
                '2' { $plugin = "windows.pslist" }
                '3' { $plugin = "windows.netscan" }
                '4' { $plugin = "windows.filescan" }
                '5' { $plugin = "windows.cmdline" }
                '6' { $plugin = Read-Host "Masukkan nama plugin (contoh: windows.malfind)" }
            }
            Run-And-Log $tool "-f `"$file`" $plugin"
        } elseif ($choice -eq '6') {
            if (Get-Command exiftool -ErrorAction SilentlyContinue) {
                Run-And-Log "exiftool" "`"$file`""
            } else {
                Write-Host "[-] ExifTool belum terinstall. Jalankan setup_tools.ps1 untuk mencoba mengunduhnya via winget." -ForegroundColor Red
            }
        } else {
            if (-Not (Test-Path $tool)) {
                Write-Host "[-] Error: executable $tool tidak ditemukan di folder bin!" -ForegroundColor Red
            } else {
                Run-And-Log $tool "`"$file`""
            }
        }
    }

    Write-Host "==================================================================" -ForegroundColor Magenta
    Write-Host "Analisis selesai. Hasil lengkap tersimpan di: $reportFile" -ForegroundColor Cyan
    Pause
}
