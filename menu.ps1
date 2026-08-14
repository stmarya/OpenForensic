#Requires -Version 5.1
<#
    OpenForensic - menu interaktif.
    Daftar tool dibangun otomatis dari tools.json, sehingga menambah tool tidak
    memerlukan perubahan kode di file ini.
#>

[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

Import-Module (Join-Path $PSScriptRoot 'OpenForensic.psd1') -Force
Initialize-OFWorkspace

function Wait-OFEnter {
    Write-Host ''
    [void](Read-Host 'Tekan Enter untuk melanjutkan')
}

function Show-OFBanner {
    Write-Host '  +----------------------------------------------------------+' -ForegroundColor Cyan
    Write-Host '  |   O P E N F O R E N S I C   ::   Kan9Ch3k   v0.2.0       |' -ForegroundColor Cyan
    Write-Host '  |   Interactive Digital Forensics & CTF Toolkit             |' -ForegroundColor Yellow
    Write-Host '  +----------------------------------------------------------+' -ForegroundColor Cyan
    Write-Host ''
}

function Show-OFReportSummary {
    param([Parameter(Mandatory)]$Report)
    Write-Host ''
    Write-Host '  Ringkasan bukti' -ForegroundColor Cyan
    Write-Host "    Target : $($Report.TargetPath)"
    Write-Host "    SHA256 : $($Report.Hashes.SHA256)"
    Write-Host "    Tipe   : $($Report.FileType.Kind) - $($Report.FileType.Description)"
    if ($Report.FileType.TypeMismatch) {
        Write-Host "    [!] Ekstensi '$($Report.FileType.Extension)' tidak cocok dengan isi file." -ForegroundColor Yellow
    }
    Write-Host "    Report : $($Report.TextPath)" -ForegroundColor DarkGray
    Write-Host ''
}

function Select-OFReportInteractive {
    $reports = @(Get-OFReportList -Limit 15)
    if ($reports.Count -eq 0) {
        Write-Host '[-] Belum ada report. Jalankan analisis terlebih dahulu.' -ForegroundColor Red
        return $null
    }
    Write-Host ''
    Write-Host '  Report terbaru:' -ForegroundColor Cyan
    for ($i = 0; $i -lt $reports.Count; $i++) {
        $size = [math]::Round($reports[$i].Length / 1KB, 1)
        Write-Host ('   [{0,2}] {1}  ({2} KB, {3})' -f ($i + 1), $reports[$i].Name, $size, $reports[$i].LastWriteTime.ToString('yyyy-MM-dd HH:mm'))
    }
    Write-Host ''
    $choice = Read-OFChoice -Prompt "Pilih report (1-$($reports.Count))" -MinValue 1 -MaxValue $reports.Count
    if ($null -eq $choice) { return $null }
    return $reports[[int]$choice - 1]
}

while ($true) {
    Clear-Host
    Show-OFBanner

    $catalog = Get-OFToolCatalog
    $menuMap = @{}
    $index = 1
    $currentCategory = ''

    foreach ($definition in $catalog) {
        if ($definition.category -ne $currentCategory) {
            $currentCategory = $definition.category
            Write-Host "  -- $($currentCategory.ToUpperInvariant()) --" -ForegroundColor DarkCyan
        }
        $tool = Resolve-OFTool -Id $definition.id -Catalog $catalog
        $marker = if ($tool.Available) { '[ok]' } else { '[--]' }
        $color = if ($tool.Available) { 'White' } else { 'DarkGray' }
        Write-Host ('   [{0,2}] {1} {2,-20} {3}' -f $index, $marker, $definition.name, $definition.description) -ForegroundColor $color
        $menuMap[[string]$index] = $tool
        $index++
    }

    Write-Host ''
    Write-Host '  -- AKSI --' -ForegroundColor DarkCyan
    Write-Host '   [ T] Magic Triage      (deteksi tipe via magic bytes + jalankan semua tool relevan)'
    Write-Host '   [ A] AI Analyst        (analisis report dengan LLM - mengirim data ke pihak ketiga)'
    Write-Host '   [ L] Daftar Report     (report terbaru di folder reports/)'
    Write-Host '   [ K] Kelola API Key    (hapus API key tersimpan)'
    Write-Host '   [ U] Update Tools      (perbarui Volatility 3 & paket Python)'
    Write-Host '   [ 0] Keluar'
    Write-Host ''

    $validChoices = @($menuMap.Keys) + @('T', 'A', 'L', 'K', 'U', '0')
    $choice = Read-OFChoice -Prompt 'Pilih menu' -Valid $validChoices

    if ($null -eq $choice -or $choice -eq '0') {
        Write-Host ''
        Write-Host '  Terima kasih telah menggunakan OpenForensic. Stay safe.' -ForegroundColor Green
        break
    }

    switch ($choice) {
        'L' {
            [void](Select-OFReportInteractive)
            Wait-OFEnter
            continue
        }
        'K' {
            Clear-OFApiKey
            Wait-OFEnter
            continue
        }
        'U' {
            Update-OFTool
            Wait-OFEnter
            continue
        }
        'A' {
            $report = Select-OFReportInteractive
            if ($report) {
                [void](Invoke-OFAiAnalysis -ReportPath $report.FullName)
            }
            Wait-OFEnter
            continue
        }
        'T' {
            $file = Select-OFTargetFile -Title 'Pilih file untuk Magic Triage'
            if ([string]::IsNullOrWhiteSpace($file)) {
                Write-Host '[-] Dibatalkan.' -ForegroundColor Red
                Wait-OFEnter
                continue
            }
            $report = New-OFReport -TargetPath $file
            Show-OFReportSummary -Report $report
            [void](Invoke-OFTriage -TargetPath $file -Report $report)
            [void](Save-OFReport -Report $report)
            Write-Host "[+] Selesai. Report: $($report.TextPath)" -ForegroundColor Green
            Write-Host "    JSON     : $($report.JsonPath)" -ForegroundColor DarkGray
            Wait-OFEnter
            continue
        }
    }

    $selectedTool = $menuMap[$choice]
    if (-not $selectedTool.Available) {
        Write-Host ''
        Write-Host "[-] $($selectedTool.Name) belum tersedia." -ForegroundColor Red
        Write-Host "    Cara memasang: $($selectedTool.InstallHint)" -ForegroundColor Yellow
        Wait-OFEnter
        continue
    }

    $file = Select-OFTargetFile -Filter $selectedTool.Definition.dialogFilter -Title "Pilih file target untuk $($selectedTool.Name)"
    if ([string]::IsNullOrWhiteSpace($file)) {
        Write-Host '[-] Tidak ada file dipilih. Dibatalkan.' -ForegroundColor Red
        Wait-OFEnter
        continue
    }

    $plugin = ''
    if ($selectedTool.Definition.requiresPlugin) {
        $plugins = @($selectedTool.Definition.plugins)
        Write-Host ''
        Write-Host "  Plugin $($selectedTool.Name):" -ForegroundColor Cyan
        for ($i = 0; $i -lt $plugins.Count; $i++) {
            Write-Host ('   [{0,2}] {1}' -f ($i + 1), $plugins[$i])
        }
        Write-Host ('   [{0,2}] *input manual*' -f ($plugins.Count + 1))
        Write-Host ''
        $pluginChoice = Read-OFChoice -Prompt "Pilih plugin (1-$($plugins.Count + 1))" -MinValue 1 -MaxValue ($plugins.Count + 1)
        $pluginIndex = [int]$pluginChoice
        if ($pluginIndex -eq ($plugins.Count + 1)) {
            $manual = Read-Host 'Nama plugin (contoh: windows.pstree)'
            $plugin = $manual.Trim()
            if ([string]::IsNullOrWhiteSpace($plugin)) {
                Write-Host '[-] Plugin kosong. Dibatalkan.' -ForegroundColor Red
                Wait-OFEnter
                continue
            }
        } else {
            $plugin = [string]$plugins[$pluginIndex - 1]
        }
    }

    $report = New-OFReport -TargetPath $file
    Show-OFReportSummary -Report $report
    Write-Host '================== HASIL ANALISIS ==================' -ForegroundColor Magenta
    [void](Invoke-OFToolById -ToolId $selectedTool.Id -TargetPath $file -Plugin $plugin -Report $report -Catalog $catalog)
    [void](Save-OFReport -Report $report)
    Write-Host '====================================================' -ForegroundColor Magenta
    Write-Host "[+] Report : $($report.TextPath)" -ForegroundColor Cyan
    Write-Host "[+] JSON   : $($report.JsonPath)" -ForegroundColor DarkGray
    Wait-OFEnter
}
