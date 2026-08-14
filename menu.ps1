#Requires -Version 5.1
<#
    OpenForensic - menu interaktif berbasis kasus.

    Menu tipis: seluruh logika ada di modul (OpenForensic.psm1, .Workflow.psm1, .Ai.psm1,
    .Integrity.psm1, .Timeline.psm1, .Models.psm1) sehingga menu, CLI (run.ps1 / case.ps1),
    dan test memakai kode yang sama.
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
    $activeModel = @(Get-OFAiModelList | Where-Object { $_.Active })
    $modelLabel = if ($activeModel.Count -gt 0) { " [profil: $($activeModel[0].Name)]" } else { '' }
    Write-Host "        AI: $($config.provider) / $($config.model)$modelLabel" -ForegroundColor DarkGray
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
    Write-Host '  3. Tambah bukti ke kasus aktif (duplikat dilewati otomatis)'
    Write-Host '  4. Analisa bukti pada kasus aktif (otomatis sesuai tipe file)'
    Write-Host '  5. Jalankan satu tool dari katalog pada bukti kasus aktif'
    Write-Host '  6. Lihat temuan / artefak / ringkasan kasus aktif'
    Write-Host '  7. Ekspor report kasus (Markdown + HTML)'
    Write-Host '  8. ALUR LENGKAP satu langkah: analisa -> timeline -> MITRE -> AI -> report -> segel' -ForegroundColor Green
    Write-Host ''
    Write-Host ' TIMELINE, IOC, DAN INTEGRITAS' -ForegroundColor Yellow
    Write-Host '  9. Bangun timeline ternormalisasi + pemetaan MITRE ATT&CK'
    Write-Host ' 10. Ekspor IOC (CSV / JSON / STIX 2.1 / MISP)'
    Write-Host ' 11. Integritas kasus (manifest, segel, verifikasi, versi tool)'
    Write-Host ''
    Write-Host ' AI ASSISTANCE' -ForegroundColor Yellow
    Write-Host ' 12. AI analisa kasus (korelasi artefak -> temuan + ringkasan eksekutif)'
    Write-Host ' 13. AI analisa MENDALAM (memakai timeline, MITRE, dan status integritas)' -ForegroundColor Green
    Write-Host ' 14. AI guided analysis (AI memilih tool berikutnya, Anda menyetujui)'
    Write-Host ' 15. AI assistant interaktif (tanya jawab + aksi)'
    Write-Host ' 16. AI buat report lengkap (analisa + ekspor)'
    Write-Host ' 17. Manajer model AI (tambah model sendiri, uji, aktifkan)' -ForegroundColor Green
    Write-Host ' 18. Konfigurasi AI (provider, model, redaksi data)'
    Write-Host ''
    Write-Host ' UTILITAS' -ForegroundColor Yellow
    Write-Host ' 19. Analisa cepat satu file (tanpa kasus)'
    Write-Host ' 20. Status tool terpasang'
    Write-Host ' 21. Daftar report lama'
    Write-Host ' 22. Update tool & dependensi'
    Write-Host ' 23. Hapus API key tersimpan'
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

    $duplicate = Test-OFEvidenceDuplicate -Case $case -Path $file
    if ($duplicate -and $duplicate.IsDuplicate) {
        Write-Host "[i] Berkas ini identik dengan bukti $($duplicate.ExistingEvidenceId) yang sudah terdaftar." -ForegroundColor DarkYellow
        $anyway = Read-Host 'Tambahkan juga? (y/N)'
        if ($anyway -notmatch '^[yY]$') { return }
    }

    $description = Read-Host 'Keterangan bukti (opsional)'
    $copyAnswer = Read-Host 'Buat salinan di folder kasus? (Y/n)'
    $evidence = Add-OFCaseEvidence -Case $case -Path $file -Description $description -Copy:($copyAnswer -notmatch '^[nN]$')
    if ($evidence) {
        $protect = Read-Host 'Set bukti asli menjadi read-only (write-block lunak)? (Y/n)'
        if ($protect -notmatch '^[nN]$') { Protect-OFEvidenceFile -Path $file | Out-Null }
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
    $mitre = @(Get-OFMitreSummary -Case $case)
    if ($mitre.Count -gt 0) {
        Write-Host ' MITRE ATT&CK' -ForegroundColor Yellow
        foreach ($tactic in $mitre) {
            Write-Host ("  {0}: {1}" -f $tactic.tactic, ((@($tactic.techniques)) -join '; '))
        }
    }
}

function Invoke-OFMenuComplete {
    $case = Get-OFActiveCase
    if (-not $case) { return }
    Write-Host ''
    Write-Host ' Alur lengkap akan menjalankan: analisa bukti yang belum diperiksa, timeline' -ForegroundColor DarkGray
    Write-Host ' ternormalisasi, pemetaan MITRE, snapshot versi tool, report, ekspor timeline' -ForegroundColor DarkGray
    Write-Host ' dan IOC, lalu manifest + segel kasus.' -ForegroundColor DarkGray
    $useAi = Read-Host 'Sertakan analisa AI mendalam? (y/N)'
    $seal = Read-Host 'Segel kasus di akhir? (Y/n)'
    $passphrase = $null
    if ($seal -notmatch '^[nN]$') {
        $mode = Read-Host 'Mode kunci segel: [1] DPAPI mesin ini (default) atau [2] passphrase'
        if ($mode -eq '2') { $passphrase = Read-Host 'Passphrase segel (ingat baik-baik)' -AsSecureString }
    }

    if ($passphrase) {
        Invoke-OFCompleteWorkflow -Case $case -SkipAnalysis:$false -UseAi:($useAi -match '^[yY]$') `
            -SkipSeal:($seal -match '^[nN]$') -SealPassphrase $passphrase | Out-Null
    } else {
        Invoke-OFCompleteWorkflow -Case $case -SkipAnalysis:$false -UseAi:($useAi -match '^[yY]$') `
            -SkipSeal:($seal -match '^[nN]$') | Out-Null
    }
}

function Invoke-OFMenuTimeline {
    $case = Get-OFActiveCase
    if (-not $case) { return }
    Write-Host ''
    Write-Host '  1. Bangun timeline (state kasus + CSV di folder artifacts) + pemetaan MITRE'
    Write-Host '  2. Impor satu berkas CSV tool (Hayabusa / Chainsaw / MFTECmd / lain)'
    Write-Host '  3. Tampilkan timeline (severity medium ke atas)'
    Write-Host '  4. Ekspor timeline (CSV / JSON / Markdown)'
    Write-Host '  0. Kembali'
    $choice = Read-OFChoice -Prompt 'Pilihan' -MinValue 0 -MaxValue 4
    switch ([int]$choice) {
        1 { Invoke-OFTimelineWorkflow -Case $case -IncludeExaminerActions | Out-Null }
        2 {
            $file = Select-OFTargetFile -Title 'Pilih CSV keluaran tool'
            if ($file) { Import-OFTimelineCsv -Case $case -Path $file | Out-Null }
        }
        3 {
            $events = @(Get-OFTimeline -Case $case -MinSeverity medium -Deduplicate)
            if ($events.Count -eq 0) {
                Write-Host '[i] Belum ada kejadian. Jalankan opsi 1 dulu.' -ForegroundColor DarkGray
            } else {
                $events | Select-Object timestamp, source, severity, actor, action, target |
                    Format-Table -AutoSize | Out-Host
            }
        }
        4 {
            $format = Read-OFChoice -Prompt 'Format (Csv/Json/Markdown)' -Valid @('Csv', 'Json', 'Markdown', 'csv', 'json', 'markdown')
            if ($format) {
                $normalized = (Get-Culture).TextInfo.ToTitleCase($format.ToLowerInvariant())
                Export-OFTimeline -Case $case -Format $normalized | Out-Null
            }
        }
        default { return }
    }
}

function Invoke-OFMenuIoc {
    $case = Get-OFActiveCase
    if (-not $case) { return }
    $format = Read-OFChoice -Prompt 'Format IOC (Csv/Json/Stix/Misp)' -Valid @('Csv', 'Json', 'Stix', 'Misp', 'csv', 'json', 'stix', 'misp')
    if (-not $format) { return }
    $normalized = (Get-Culture).TextInfo.ToTitleCase($format.ToLowerInvariant())
    Export-OFCaseIoc -Case $case -Format $normalized | Out-Null
}

function Invoke-OFMenuIntegrity {
    $case = Get-OFActiveCase
    if (-not $case) { return }
    Write-Host ''
    Write-Host '  1. Segel kasus (versi tool -> manifest -> segel -> verifikasi)'
    Write-Host '  2. Verifikasi integritas kasus sekarang'
    Write-Host '  3. Perbarui snapshot versi tool saja'
    Write-Host '  4. Impor allowlist hash (mis. subset NSRL)'
    Write-Host '  0. Kembali'
    $choice = Read-OFChoice -Prompt 'Pilihan' -MinValue 0 -MaxValue 4
    switch ([int]$choice) {
        1 {
            $mode = Read-Host 'Mode kunci: [1] DPAPI mesin ini (default) atau [2] passphrase lintas mesin'
            if ($mode -eq '2') {
                $passphrase = Read-Host 'Passphrase segel (tidak dapat dipulihkan bila lupa)' -AsSecureString
                Invoke-OFCaseSealWorkflow -Case $case -Passphrase $passphrase | Out-Null
            } else {
                Invoke-OFCaseSealWorkflow -Case $case | Out-Null
            }
        }
        2 {
            $usePass = Read-Host 'Segel memakai passphrase? (y/N)'
            $status = if ($usePass -match '^[yY]$') {
                Get-OFIntegrityStatus -Case $case -Passphrase (Read-Host 'Passphrase segel' -AsSecureString)
            } else {
                Get-OFIntegrityStatus -Case $case
            }
            Write-Host ''
            Write-Host (Format-OFIntegritySummary -Status $status)
        }
        3 {
            $all = Read-Host 'Periksa seluruh katalog tool (bukan hanya yang dipakai)? (y/N)'
            Update-OFCaseToolVersions -Case $case -AllTools:($all -match '^[yY]$') | Out-Null
        }
        4 {
            $file = Select-OFTargetFile -Title 'Pilih berkas daftar hash SHA256'
            if ($file) { Import-OFHashAllowlist -Path $file | Out-Null }
        }
        default { return }
    }
}

function Invoke-OFMenuAiModels {
    while ($true) {
        Write-Host ''
        Write-Host ' MANAJER MODEL AI' -ForegroundColor Yellow
        $models = @(Get-OFAiModelList)
        if ($models.Count -eq 0) {
            Write-Host '  (belum ada model terdaftar)' -ForegroundColor DarkGray
        } else {
            $models | Select-Object Name, Active, BaseProvider, Model, Local, KeyEnvVar, KeyReady |
                Format-Table -AutoSize | Out-Host
        }
        Write-Host '  1. Tambah model dari preset (OpenAI, OpenRouter, Groq, Ollama, LM Studio, dll.)'
        Write-Host '  2. Tambah model manual (endpoint sendiri)'
        Write-Host '  3. Aktifkan model'
        Write-Host '  4. Uji model (ping + latensi, tanpa mengirim data bukti)'
        Write-Host '  5. Uji semua model terdaftar'
        Write-Host '  6. Hapus model'
        Write-Host '  7. Daftarkan preset dasar (gemini, openai, ollama)'
        Write-Host '  0. Kembali'
        $choice = Read-OFChoice -Prompt 'Pilihan' -MinValue 0 -MaxValue 7
        if ($null -eq $choice -or [int]$choice -eq 0) { return }

        switch ([int]$choice) {
            1 {
                $presets = @(Get-OFAiModelPreset)
                Write-Host ''
                for ($i = 0; $i -lt $presets.Count; $i++) {
                    $localMark = if ($presets[$i].Local) { 'LOKAL' } else { 'cloud' }
                    Write-Host ("  {0}. {1} [{2}] - {3} ({4})" -f ($i + 1), $presets[$i].Preset, $localMark, $presets[$i].Model, $presets[$i].Notes)
                }
                $presetChoice = Read-OFChoice -Prompt 'Pilih preset' -MinValue 1 -MaxValue $presets.Count
                if ($null -eq $presetChoice) { continue }
                $preset = $presets[[int]$presetChoice - 1]
                $name = Read-Host "Nama profil (default: $($preset.Preset))"
                if (-not $name) { $name = $preset.Preset }
                $model = Read-Host "Nama model (default: $($preset.Model))"
                if (-not $model) { $model = $preset.Model }
                Register-OFAiModel -Name $name -Preset $preset.Preset -Model $model -Force | Out-Null
            }
            2 {
                $name = Read-Host 'Nama profil (mis. internal)'
                if (-not $name) { continue }
                $provider = Read-OFChoice -Prompt 'Protokol dasar (openai/gemini/ollama)' -Valid @('openai', 'gemini', 'ollama')
                if (-not $provider) { continue }
                $model = Read-Host 'Nama model (mis. qwen2.5-72b-instruct)'
                $endpoint = Read-Host 'Endpoint (mis. https://ai.perusahaan.local/v1; kosong untuk default provider)'
                $keyEnv = Read-Host 'Nama variabel environment API key (kosong bila model lokal)'
                $isLocal = Read-Host 'Model ini berjalan lokal? (y/N)'
                $arguments = @{
                    Name         = $name
                    BaseProvider = $provider
                    Model        = $model
                    KeyEnvVar    = $keyEnv
                    Force        = $true
                }
                if ($endpoint) { $arguments['Endpoint'] = $endpoint }
                if ($isLocal -match '^[yY]$') { $arguments['Local'] = $true }
                Register-OFAiModel @arguments | Out-Null
            }
            3 {
                if ($models.Count -eq 0) { continue }
                $name = Read-Host 'Nama profil yang ingin diaktifkan'
                if ($name) { Use-OFAiModel -Name $name | Out-Null }
            }
            4 {
                $name = Read-Host 'Nama profil yang ingin diuji (kosong = konfigurasi aktif)'
                if ($name) { Test-OFAiModel -Name $name | Format-List | Out-Host }
                else { Test-OFAiModel | Format-List | Out-Host }
            }
            5 { Test-OFAiModelAll | Format-Table Name, Provider, Model, Ok, LatencySeconds -AutoSize | Out-Host }
            6 {
                $name = Read-Host 'Nama profil yang ingin dihapus'
                if ($name) { Remove-OFAiModel -Name $name | Out-Null }
            }
            7 { Initialize-OFAiModelDefaults | Out-Null }
        }
    }
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
    Write-Host '  5. Buka manajer model AI (profil model sendiri)'
    Write-Host '  0. Kembali'
    $choice = Read-OFChoice -Prompt 'Pilihan' -MinValue 0 -MaxValue 5
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
        5 { Invoke-OFMenuAiModels }
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
    $selection = Read-OFChoice -Prompt 'Pilih menu' -MinValue 0 -MaxValue 23
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
            8 { Invoke-OFMenuComplete }
            9 { Invoke-OFMenuTimeline }
            10 { Invoke-OFMenuIoc }
            11 { Invoke-OFMenuIntegrity }
            12 {
                $case = Get-OFActiveCase
                if ($case) { Invoke-OFAiCaseAnalysis -Case $case | Out-Null }
            }
            13 {
                $case = Get-OFActiveCase
                if ($case) { Invoke-OFAiDeepAnalysis -Case $case | Out-Null }
            }
            14 {
                $case = Get-OFActiveCase
                if ($case) {
                    $selected = Select-OFCaseEvidence -Case $case
                    foreach ($evidence in @($selected)) {
                        Invoke-OFAiGuidedAnalysis -Case $case -EvidenceId $evidence.id | Out-Null
                    }
                }
            }
            15 {
                $case = Get-OFActiveCase
                if ($case) { Start-OFAiAssistant -Case $case }
            }
            16 {
                $case = Get-OFActiveCase
                if ($case) { New-OFAiCaseReport -Case $case -Format Both | Out-Null }
            }
            17 { Invoke-OFMenuAiModels }
            18 { Invoke-OFMenuAiConfig }
            19 { Invoke-OFMenuQuickScan }
            20 {
                Get-OFToolStatus | Select-Object Id, Name, Category, Available, Path |
                    Format-Table -AutoSize | Out-Host
            }
            21 { Get-OFReportList | Select-Object Name, LastWriteTime, Length | Format-Table -AutoSize | Out-Host }
            22 { Update-OFTool }
            23 { Clear-OFApiKey }
        }
    } catch {
        Write-Host "[-] Terjadi kesalahan: $($_.Exception.Message)" -ForegroundColor Red
    }

    Write-Host ''
    Read-Host 'Tekan Enter untuk kembali ke menu' | Out-Null
}
