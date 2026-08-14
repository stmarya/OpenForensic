#Requires -Version 5.1
<#
    OpenForensic - menu interaktif berbasis kasus.

    Menu tipis: seluruh logika ada di modul (OpenForensic.psm1, .Workflow.psm1, .Ai.psm1)
    sehingga menu, CLI (run.ps1 / case.ps1), dan test memakai kode yang sama.
#>

[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'

$manifest = Join-Path $PSScriptRoot 'OpenForensic.psd1'
if (-not (Test-Path -LiteralPath $manifest)) {
    Write-Host '[-] OpenForensic.psd1 tidak ditemukan.' -ForegroundColor Red
    exit 2
}
Import-Module $manifest -Force -DisableNameChecking
Initialize-OFWorkspace

$script:ActiveCase = $null

function Show-OFBanner {
    Clear-Host
    Write-Host ''
    Write-Host '   ___                   _____                       _      ' -ForegroundColor Cyan
    Write-Host '  / _ \ _ __  ___ _ __  |  ___|__  _ __ ___ _ __  ___(_) ___ ' -ForegroundColor Cyan
    Write-Host ' | | | | .__|/ _ \ ._ \ | |_ / _ \| .__/ _ \ ._ \/ __| |/ __|' -ForegroundColor Cyan
    Write-Host ' | |_| | |  |  __/ | | ||  _| (_) | | |  __/ | | \__ \ | (__ ' -ForegroundColor Cyan
    Write-Host '  \___/|_|   \___|_| |_||_|  \___/|_|  \___|_| |_|___/_|\___|' -ForegroundColor Cyan
    Write-Host ''
    Write-Host '        Toolkit Forensik Digital - alur kerja end-to-end' -ForegroundColor DarkGray
    $config = Get-OFAiConfig
    Write-Host "        AI: $($config.provider) / $($config.model)" -ForegroundColor DarkGray
    if ($script:ActiveCase) {
        $summary = Get-OFCaseSummary -Case $script:ActiveCase
        Write-Host "        Kasus aktif: $($summary.CaseId)" -ForegroundColor Green
        Write-Host "        Bukti: $($summary.EvidenceCount) | Artefak: $($summary.ArtifactCount) | Temuan: $($summary.FindingCount) | $($summary.Verdict)" -ForegroundColor Green
    } else {
        Write-Host '        Kasus aktif: (belum ada)' -ForegroundColor DarkYellow
    }
    Write-Host ''
}

function Show-OFMenu {
    Write-Host ' ALUR KERJA KASUS' -ForegroundColor Yellow
    Write-Host '  1. Kasus baru + jalankan alur end-to-end (bukti -> tool -> temuan -> report)'
    Write-Host '  2. Buka / lanjutkan kasus yang ada'
    Write-Host '  3. Tambah bukti ke kasus aktif'
    Write-Host '  4. Analisa bukti pada kasus aktif (otomatis sesuai tipe file)'
    Write-Host '  5. Jalankan satu tool dari katalog pada bukti kasus aktif'
    Write-Host '  6. Lihat temuan / artefak / ringkasan kasus aktif'
    Write-Host '  7. Ekspor report kasus (Markdown + HTML)'
    Write-Host ''
    Write-Host ' AI ASSISTANCE' -ForegroundColor Yellow
    Write-Host '  8. AI analisa kasus (korelasi artefak -> temuan + ringkasan eksekutif)'
    Write-Host '  9. AI guided analysis (AI memilih tool berikutnya, Anda menyetujui)'
    Write-Host ' 10. AI assistant interaktif (tanya jawab + aksi)'
    Write-Host ' 11. AI buat report lengkap (analisa + ekspor)'
    Write-Host ' 12. Konfigurasi AI (provider, model, redaksi data)'
    Write-Host ''
    Write-Host ' UTILITAS' -ForegroundColor Yellow
    Write-Host ' 13. Analisa cepat satu file (tanpa kasus)'
    Write-Host ' 14. Status tool terpasang'
    Write-Host ' 15. Daftar report lama'
    Write-Host ' 16. Update tool & dependensi'
    Write-Host ' 17. Hapus API key tersimpan'
    Write-Host '  0. Keluar'
    Write-Host ''
}

function Get-OFActiveCase {
    if (-not $script:ActiveCase) {
        Write-Host '[-] Belum ada kasus aktif. Pilih menu 1 atau 2 terlebih dahulu.' -ForegroundColor Red
        return $null
    }
    return $script:ActiveCase
}

function Select-OFCaseEvidence {
    param([Parameter(Mandatory)]$Case)

    $evidence = @($Case.evidence)
    if ($evidence.Count -eq 0) {
        Write-Host '[-] Kasus ini belum memiliki bukti.' -ForegroundColor Red
        return $null
    }
    Write-Host ''
    for ($i = 0; $i -lt $evidence.Count; $i++) {
        Write-Host ("  {0}. {1} - {2} ({3}, {4} byte)" -f ($i + 1), $evidence[$i].id, $evidence[$i].name, $evidence[$i].kind, $evidence[$i].size)
    }
    Write-Host '  0. Semua bukti'
    $choice = Read-OFChoice -Prompt 'Pilih bukti' -MinValue 0 -MaxValue $evidence.Count
    if ($null -eq $choice) { return $null }
    if ([int]$choice -eq 0) { return $evidence }
    return @($evidence[[int]$choice - 1])
}

function Invoke-OFMenuNewCase {
    $name = Read-Host 'Nama kasus (mis. "Insiden Ransomware Workstation A")'
    if ([string]::IsNullOrWhiteSpace($name)) { Write-Host '[-] Dibatalkan.' -ForegroundColor Red; return }
    $description = Read-Host 'Deskripsi singkat perkara (opsional)'
    $reference = Read-Host 'Nomor referensi / tiket (opsional)'
    $classification = Read-OFChoice -Prompt 'Klasifikasi (public/internal/confidential/restricted)' `
        -Valid @('public', 'internal', 'confidential', 'restricted', 'PUBLIC', 'INTERNAL', 'CONFIDENTIAL', 'RESTRICTED')
    if (-not $classification) { $classification = 'internal' }

    $paths = New-Object System.Collections.ArrayList
    while ($true) {
        $file = Select-OFTargetFile -Title 'Pilih file bukti (Cancel untuk berhenti menambah)'
        if (-not $file) { break }
        [void]$paths.Add($file)
        Write-Host "    [+] $file" -ForegroundColor DarkGray
        $more = Read-Host 'Tambah bukti lain? (y/N)'
        if ($more -notmatch '^[yY]$') { break }
    }
    if ($paths.Count -eq 0) { Write-Host '[-] Tidak ada bukti dipilih.' -ForegroundColor Red; return }

    $copyAnswer = Read-Host 'Buat salinan bukti di folder kasus (disarankan)? (Y/n)'
    $useAiAnswer = Read-Host 'Jalankan analisa AI setelah tool selesai? (y/N)'

    $result = Invoke-OFWorkflow -Path @($paths) -CaseName $name -Description $description `
        -Reference $reference -Classification $classification.ToLowerInvariant() `
        -CopyEvidence:($copyAnswer -notmatch '^[nN]$') -UseAi:($useAiAnswer -match '^[yY]$')

    $script:ActiveCase = $result.Case
}

function Invoke-OFMenuOpenCase {
    $cases = @(Get-OFCaseList)
    if ($cases.Count -eq 0) { Write-Host '[i] Belum ada kasus tersimpan.' -ForegroundColor DarkGray; return }
    Write-Host ''
    for ($i = 0; $i -lt $cases.Count; $i++) {
        Write-Host ("  {0}. {1} | {2} | bukti {3} | temuan {4} | {5}" -f ($i + 1), $cases[$i].CaseId, $cases[$i].Name, $cases[$i].Evidence, $cases[$i].Findings, $cases[$i].UpdatedAt)
    }
    $choice = Read-OFChoice -Prompt 'Pilih kasus' -MinValue 1 -MaxValue $cases.Count
    if ($null -eq $choice) { return }
    $script:ActiveCase = Get-OFCase -CaseId $cases[[int]$choice - 1].CaseId
    Write-Host "[+] Kasus aktif: $($script:ActiveCase.caseId)" -ForegroundColor Green
}

function Invoke-OFMenuAddEvidence {
    $case = Get-OFActiveCase
    if (-not $case) { return }
    $file = Select-OFTargetFile -Title 'Pilih file bukti untuk ditambahkan'
    if (-not $file) { return }
    $description = Read-Host 'Keterangan bukti (opsional)'
    $copyAnswer = Read-Host 'Buat salinan di folder kasus? (Y/n)'
    $evidence = Add-OFCaseEvidence -Case $case -Path $file -Description $description -Copy:($copyAnswer -notmatch '^[nN]$')
    if ($evidence) {
        $analyze = Read-Host "Analisa $($evidence.id) sekarang? (Y/n)"
        if ($analyze -notmatch '^[nN]$') {
            Invoke-OFEvidenceAnalysis -Case $case -EvidenceId $evidence.id | Out-Null
        }
    }
}

function Invoke-OFMenuAnalyze {
    $case = Get-OFActiveCase
    if (-not $case) { return }
    $selected = Select-OFCaseEvidence -Case $case
    if (-not $selected) { return }
    $allTools = Read-Host 'Gunakan semua tool yang cocok (bukan hanya triage)? (y/N)'
    foreach ($evidence in $selected) {
        Invoke-OFEvidenceAnalysis -Case $case -EvidenceId $evidence.id -AllTools:($allTools -match '^[yY]$') | Out-Null
    }
}

function Invoke-OFMenuSingleTool {
    $case = Get-OFActiveCase
    if (-not $case) { return }
    $selected = Select-OFCaseEvidence -Case $case
    if (-not $selected -or $selected.Count -ne 1) {
        Write-Host '[-] Pilih tepat satu bukti untuk mode tool tunggal.' -ForegroundColor Red
        return
    }
    $evidence = $selected[0]

    $tools = @(Get-OFApplicableTool -Path $evidence.workingPath)
    Write-Host ''
    Write-Host " Tool yang cocok untuk tipe '$($evidence.kind)':" -ForegroundColor Yellow
    for ($i = 0; $i -lt $tools.Count; $i++) {
        $mark = if ($tools[$i].Available) { '[ok]' } else { '[--]' }
        Write-Host ("  {0}. {1} {2} - {3}" -f ($i + 1), $mark, $tools[$i].Name, $tools[$i].Description)
    }
    $choice = Read-OFChoice -Prompt 'Pilih tool' -MinValue 1 -MaxValue $tools.Count
    if ($null -eq $choice) { return }
    $tool = $tools[[int]$choice - 1]
    if (-not $tool.Available) {
        Write-Host "[-] Tool belum terpasang. $($tool.InstallHint)" -ForegroundColor Red
        return
    }

    $plugin = ''
    $plugins = @($tool.Definition.plugins)
    if ($tool.Definition.requiresPlugin -and $plugins.Count -gt 0) {
        Write-Host ''
        for ($i = 0; $i -lt $plugins.Count; $i++) {
            Write-Host ("  {0}. {1}" -f ($i + 1), $plugins[$i])
        }
        $pluginChoice = Read-OFChoice -Prompt 'Pilih plugin' -MinValue 1 -MaxValue $plugins.Count
        if ($null -ne $pluginChoice) { $plugin = [string]$plugins[[int]$pluginChoice - 1] }
    }

    Invoke-OFEvidenceAnalysis -Case $case -EvidenceId $evidence.id -ToolIds @($tool.Id) -Plugin $plugin | Out-Null
}

function Invoke-OFMenuShowCase {
    $case = Get-OFActiveCase
    if (-not $case) { return }
    Get-OFCaseSummary -Case $case | Format-List | Out-Host
    Write-Host ' TEMUAN' -ForegroundColor Yellow
    $findings = @(Get-OFCaseFinding -Case $case)
    if ($findings.Count -eq 0) {
        Write-Host '  (belum ada temuan)' -ForegroundColor DarkGray
    } else {
        $findings | Select-Object id, severity, category, title, evidenceId, origin | Format-Table -AutoSize | Out-Host
    }
    Write-Host ' ARTEFAK (20 teratas)' -ForegroundColor Yellow
    @($case.artifacts) | Select-Object -First 20 id, type, severity, value, count, evidenceId | Format-Table -AutoSize | Out-Host
}

function Invoke-OFMenuAiConfig {
    $config = Get-OFAiConfig
    Write-Host ''
    Write-Host " Provider saat ini : $($config.provider)" -ForegroundColor Cyan
    Write-Host " Model             : $($config.model)" -ForegroundColor Cyan
    Write-Host " Endpoint          : $(if ($config.endpoint) { $config.endpoint } else { '(default)' })" -ForegroundColor Cyan
    Write-Host " Redaksi data      : $($config.redact)" -ForegroundColor Cyan
    Write-Host ''
    Write-Host '  1. Gemini (cloud, gratis dengan API key)'
    Write-Host '  2. OpenAI-compatible (OpenAI, Azure, OpenRouter, LM Studio)'
    Write-Host '  3. Ollama (LOKAL - data bukti tidak keluar dari mesin, disarankan untuk bukti sensitif)'
    Write-Host '  4. Aktif/nonaktifkan redaksi data sensitif sebelum dikirim'
    Write-Host '  0. Kembali'
    $choice = Read-OFChoice -Prompt 'Pilihan' -MinValue 0 -MaxValue 4
    switch ([int]$choice) {
        1 {
            $model = Read-Host 'Model Gemini (default: gemini-1.5-flash)'
            if (-not $model) { $model = 'gemini-1.5-flash' }
            Set-OFAiConfig -Provider gemini -Model $model | Out-Null
        }
        2 {
            $endpoint = Read-Host 'Base URL (default: https://api.openai.com/v1)'
            $model = Read-Host 'Model (mis. gpt-4o-mini)'
            if (-not $model) { $model = 'gpt-4o-mini' }
            if ($endpoint) { Set-OFAiConfig -Provider openai -Model $model -Endpoint $endpoint | Out-Null }
            else { Set-OFAiConfig -Provider openai -Model $model | Out-Null }
        }
        3 {
            $model = Read-Host 'Model Ollama (mis. llama3.1, qwen2.5)'
            if (-not $model) { $model = 'llama3.1' }
            Set-OFAiConfig -Provider ollama -Model $model | Out-Null
        }
        4 {
            $current = (Get-OFAiConfig).redact
            Set-OFAiConfig -Redact (-not $current) | Out-Null
        }
        default { return }
    }
}

function Invoke-OFMenuQuickScan {
    $file = Select-OFTargetFile -Title 'Pilih file untuk analisa cepat (tanpa kasus)'
    if (-not $file) { return }
    $report = New-OFReport -TargetPath $file
    Invoke-OFTriage -TargetPath $file -Report $report | Out-Null
    Save-OFReport -Report $report | Out-Null
    Write-Host "[+] Report: $($report.TextPath)" -ForegroundColor Green
    $ai = Read-Host 'Analisa report ini dengan AI? (y/N)'
    if ($ai -match '^[yY]$') { Invoke-OFAiAnalysis -ReportPath $report.TextPath | Out-Null }
}

while ($true) {
    Show-OFBanner
    Show-OFMenu
    $selection = Read-OFChoice -Prompt 'Pilih menu' -MinValue 0 -MaxValue 17
    if ($null -eq $selection) { break }

    try {
        switch ([int]$selection) {
            0 {
                Write-Host ''
                Write-Host '[i] Selesai. Ingat: verifikasi manual tetap wajib sebelum menarik kesimpulan.' -ForegroundColor DarkGray
                exit 0
            }
            1 { Invoke-OFMenuNewCase }
            2 { Invoke-OFMenuOpenCase }
            3 { Invoke-OFMenuAddEvidence }
            4 { Invoke-OFMenuAnalyze }
            5 { Invoke-OFMenuSingleTool }
            6 { Invoke-OFMenuShowCase }
            7 {
                $case = Get-OFActiveCase
                if ($case) { Export-OFCaseReport -Case $case -Format Both -IncludeArtifacts | Out-Null }
            }
            8 {
                $case = Get-OFActiveCase
                if ($case) { Invoke-OFAiCaseAnalysis -Case $case | Out-Null }
            }
            9 {
                $case = Get-OFActiveCase
                if ($case) {
                    $selected = Select-OFCaseEvidence -Case $case
                    foreach ($evidence in @($selected)) {
                        Invoke-OFAiGuidedAnalysis -Case $case -EvidenceId $evidence.id | Out-Null
                    }
                }
            }
            10 {
                $case = Get-OFActiveCase
                if ($case) { Start-OFAiAssistant -Case $case }
            }
            11 {
                $case = Get-OFActiveCase
                if ($case) { New-OFAiCaseReport -Case $case -Format Both | Out-Null }
            }
            12 { Invoke-OFMenuAiConfig }
            13 { Invoke-OFMenuQuickScan }
            14 {
                Get-OFToolStatus | Select-Object Id, Name, Category, Available, Path |
                    Format-Table -AutoSize | Out-Host
            }
            15 { Get-OFReportList | Select-Object Name, LastWriteTime, Length | Format-Table -AutoSize | Out-Host }
            16 { Update-OFTool }
            17 { Clear-OFApiKey }
        }
    } catch {
        Write-Host "[-] Terjadi kesalahan: $($_.Exception.Message)" -ForegroundColor Red
    }

    Write-Host ''
    Read-Host 'Tekan Enter untuk kembali ke menu' | Out-Null
}
