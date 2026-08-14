#Requires -Version 5.1
<#
.SYNOPSIS
    CLI alur kerja kasus OpenForensic (end-to-end, non-interaktif).

.DESCRIPTION
    Satu perintah untuk seluruh siklus: buat kasus, daftarkan bukti (hash + chain of
    custody), jalankan tool sesuai tipe file, ekstrak artefak, bangun timeline
    ternormalisasi + pemetaan MITRE ATT&CK, analisis AI opsional, ekspor report /
    timeline / IOC, lalu segel kasus secara kriptografis.

.EXAMPLE
    .\case.ps1 -Path .\bukti\dump.raw -CaseName "Insiden Workstation A" -Complete

.EXAMPLE
    .\case.ps1 -Path .\bukti\*.docx -CaseName "Phishing Batch" -CopyEvidence -Complete -UseAi -Model lokal

.EXAMPLE
    .\case.ps1 -CaseId CASE-20260814-231500-Insiden -Timeline -ExportIoc Csv -Seal
    .\case.ps1 -CaseId CASE-20260814-231500-Insiden -VerifyIntegrity

.EXAMPLE
    .\case.ps1 -ListModels
    .\case.ps1 -TestModels
#>
[CmdletBinding(DefaultParameterSetName = 'Run')]
param(
    [Parameter(ParameterSetName = 'Run', Position = 0)][string[]]$Path = @(),
    [Parameter(ParameterSetName = 'Run')][string]$CaseName = '',
    [Parameter(ParameterSetName = 'Run')][string]$Examiner = $env:USERNAME,
    [Parameter(ParameterSetName = 'Run')][string]$Description = '',
    [Parameter(ParameterSetName = 'Run')][string]$Reference = '',
    [Parameter(ParameterSetName = 'Run')]
    [ValidateSet('public', 'internal', 'confidential', 'restricted')][string]$Classification = 'internal',
    [Parameter(ParameterSetName = 'Run')][switch]$CopyEvidence,
    [Parameter(ParameterSetName = 'Run')][switch]$AllTools,
    [Parameter(ParameterSetName = 'Run')][switch]$GuidedAi,
    [Parameter(ParameterSetName = 'Run')][switch]$NoReport,
    [Parameter(ParameterSetName = 'Run')][switch]$Complete,

    [Parameter(ParameterSetName = 'Existing', Mandatory)][string]$CaseId,
    [Parameter(ParameterSetName = 'Existing')][string[]]$AddEvidence = @(),
    [Parameter(ParameterSetName = 'Existing')][switch]$Analyze,
    [Parameter(ParameterSetName = 'Existing')][switch]$AiAnalyze,
    [Parameter(ParameterSetName = 'Existing')][switch]$Assistant,
    [Parameter(ParameterSetName = 'Existing')][switch]$Report,
    [Parameter(ParameterSetName = 'Existing')][switch]$Summary,
    [Parameter(ParameterSetName = 'Existing')][switch]$Timeline,
    [Parameter(ParameterSetName = 'Existing')][ValidateSet('Csv', 'Json', 'Markdown')][string]$ExportTimeline,
    [Parameter(ParameterSetName = 'Existing')][ValidateSet('Csv', 'Json', 'Stix', 'Misp')][string]$ExportIoc,
    [Parameter(ParameterSetName = 'Existing')][switch]$VerifyIntegrity,
    [Parameter(ParameterSetName = 'Existing')][switch]$CompleteExisting,

    # Berlaku untuk Run maupun Existing.
    [Parameter(ParameterSetName = 'Run')][Parameter(ParameterSetName = 'Existing')][switch]$UseAi,
    [Parameter(ParameterSetName = 'Run')][Parameter(ParameterSetName = 'Existing')][switch]$DeepAi,
    [Parameter(ParameterSetName = 'Run')][Parameter(ParameterSetName = 'Existing')][string]$Model = '',
    [Parameter(ParameterSetName = 'Run')][Parameter(ParameterSetName = 'Existing')][switch]$Seal,
    [Parameter(ParameterSetName = 'Run')][Parameter(ParameterSetName = 'Existing')][securestring]$SealPassphrase,
    [Parameter(ParameterSetName = 'Run')][Parameter(ParameterSetName = 'Existing')][switch]$Quiet,

    [Parameter(ParameterSetName = 'List', Mandatory)][switch]$List,

    [Parameter(ParameterSetName = 'Models', Mandatory)][switch]$ListModels,
    [Parameter(ParameterSetName = 'ModelsTest', Mandatory)][switch]$TestModels
)

$ErrorActionPreference = 'Stop'

$manifest = Join-Path $PSScriptRoot 'OpenForensic.psd1'
if (-not (Test-Path -LiteralPath $manifest)) {
    Write-Host '[-] OpenForensic.psd1 tidak ditemukan di folder skrip.' -ForegroundColor Red
    exit 2
}
Import-Module $manifest -Force -DisableNameChecking

function Invoke-OFCliSeal {
    param($Case, [securestring]$Passphrase, [switch]$Quiet)
    if ($Passphrase) {
        return (Invoke-OFCaseSealWorkflow -Case $Case -Passphrase $Passphrase -Quiet:$Quiet)
    }
    return (Invoke-OFCaseSealWorkflow -Case $Case -Quiet:$Quiet)
}

try {
    # Aktifkan model AI pilihan pengguna sebelum aksi apa pun yang memakai AI.
    if ($Model) { Use-OFAiModel -Name $Model -Quiet:$Quiet | Out-Null }

    switch ($PSCmdlet.ParameterSetName) {
        'Models' {
            $models = @(Get-OFAiModelList)
            if ($models.Count -eq 0) {
                Write-Host '[i] Belum ada model AI terdaftar.' -ForegroundColor DarkGray
                Write-Host '    Lihat preset : Get-OFAiModelPreset' -ForegroundColor DarkGray
                Write-Host '    Daftar cepat : Initialize-OFAiModelDefaults' -ForegroundColor DarkGray
                Write-Host '    Manual       : Register-OFAiModel -Name saya -BaseProvider openai -Model gpt-4o-mini -Endpoint https://api.openai.com/v1 -KeyEnvVar OPENAI_API_KEY' -ForegroundColor DarkGray
            } else {
                $models | Format-Table Name, Active, BaseProvider, Model, Local, KeyEnvVar, KeyReady -AutoSize | Out-Host
            }
            exit 0
        }

        'ModelsTest' {
            $results = @(Test-OFAiModelAll)
            if ($results.Count -eq 0) {
                Write-Host '[i] Belum ada model AI terdaftar.' -ForegroundColor DarkGray
            } else {
                $results | Format-Table Name, Provider, Model, Ok, LatencySeconds -AutoSize | Out-Host
            }
            exit 0
        }

        'List' {
            $cases = @(Get-OFCaseList)
            if ($cases.Count -eq 0) {
                Write-Host '[i] Belum ada kasus. Buat dengan: .\case.ps1 -Path <file> -CaseName "..."' -ForegroundColor DarkGray
            } else {
                $cases | Format-Table CaseId, Name, Examiner, Status, Evidence, Findings, UpdatedAt -AutoSize | Out-Host
            }
            exit 0
        }

        'Existing' {
            $case = Get-OFCase -CaseId $CaseId

            foreach ($item in $AddEvidence) {
                foreach ($resolved in @(Get-ChildItem -Path $item -File -ErrorAction Stop)) {
                    $duplicate = Test-OFEvidenceDuplicate -Case $case -Path $resolved.FullName
                    if ($duplicate -and $duplicate.IsDuplicate) {
                        Write-Host "[i] Dilewati (duplikat $($duplicate.ExistingEvidenceId)): $($resolved.Name)" -ForegroundColor DarkYellow
                        continue
                    }
                    $evidence = Add-OFCaseEvidence -Case $case -Path $resolved.FullName
                    if ($evidence -and $Analyze) {
                        Invoke-OFEvidenceAnalysis -Case $case -EvidenceId $evidence.id | Out-Null
                    }
                }
            }

            if ($Analyze -and $AddEvidence.Count -eq 0) {
                foreach ($evidence in @($case.evidence)) {
                    Invoke-OFEvidenceAnalysis -Case $case -EvidenceId $evidence.id | Out-Null
                }
            }

            if ($CompleteExisting) {
                Invoke-OFCompleteWorkflow -Case $case -SkipAnalysis:(-not $Analyze) -UseAi:($UseAi -or $DeepAi) `
                    -SkipSeal:(-not $Seal) -SealPassphrase $SealPassphrase -Quiet:$Quiet | Out-Null
                exit 0
            }

            if ($Timeline) { Invoke-OFTimelineWorkflow -Case $case -IncludeExaminerActions -Quiet:$Quiet | Out-Null }
            if ($ExportTimeline) { Export-OFTimeline -Case $case -Format $ExportTimeline -Quiet:$Quiet | Out-Null }
            if ($DeepAi) { Invoke-OFAiDeepAnalysis -Case $case | Out-Null }
            elseif ($AiAnalyze) { Invoke-OFAiCaseAnalysis -Case $case | Out-Null }
            if ($Assistant) { Start-OFAiAssistant -Case $case }
            if ($Report) { Export-OFCaseReport -Case $case -Format Both -IncludeArtifacts | Out-Null }
            if ($ExportIoc) { Export-OFCaseIoc -Case $case -Format $ExportIoc -Quiet:$Quiet | Out-Null }
            if ($Seal) { Invoke-OFCliSeal -Case $case -Passphrase $SealPassphrase -Quiet:$Quiet | Out-Null }

            if ($VerifyIntegrity) {
                $status = if ($SealPassphrase) {
                    Get-OFIntegrityStatus -Case $case -Passphrase $SealPassphrase
                } else {
                    Get-OFIntegrityStatus -Case $case
                }
                Write-Host (Format-OFIntegritySummary -Status $status) | Out-Host
                if (-not $status.OverallOk) { exit 3 }
            }

            $noAction = -not ($AddEvidence.Count -or $Analyze -or $AiAnalyze -or $DeepAi -or $Assistant -or
                $Report -or $Timeline -or $ExportTimeline -or $ExportIoc -or $Seal -or $VerifyIntegrity)
            if ($Summary -or $noAction) {
                Get-OFCaseSummary -Case $case | Format-List | Out-Host
            }
            exit 0
        }

        default {
            if ($Path.Count -eq 0) {
                Write-Host 'Pemakaian:' -ForegroundColor Cyan
                Write-Host '  .\case.ps1 -Path <file...> [-CaseName "..."] [-CopyEvidence] [-AllTools] [-Complete] [-UseAi|-DeepAi] [-Model <nama>] [-Seal]' -ForegroundColor Cyan
                Write-Host '  .\case.ps1 -List' -ForegroundColor Cyan
                Write-Host '  .\case.ps1 -CaseId <id> [-AddEvidence <file...>] [-Analyze] [-Timeline] [-ExportTimeline Csv]' -ForegroundColor Cyan
                Write-Host '             [-DeepAi] [-Report] [-ExportIoc Csv|Json|Stix|Misp] [-Seal] [-VerifyIntegrity] [-CompleteExisting]' -ForegroundColor Cyan
                Write-Host '  .\case.ps1 -ListModels | -TestModels' -ForegroundColor Cyan
                exit 2
            }

            $resolvedPaths = New-Object System.Collections.ArrayList
            foreach ($item in $Path) {
                $found = @(Get-ChildItem -Path $item -File -ErrorAction SilentlyContinue)
                if ($found.Count -eq 0) {
                    Write-Host "[-] Tidak ada file yang cocok: $item" -ForegroundColor Red
                    continue
                }
                foreach ($file in $found) { [void]$resolvedPaths.Add($file.FullName) }
            }
            if ($resolvedPaths.Count -eq 0) { exit 2 }

            $result = Invoke-OFWorkflow -Path @($resolvedPaths) -CaseName $CaseName -Examiner $Examiner `
                -Description $Description -Reference $Reference -Classification $Classification `
                -CopyEvidence:$CopyEvidence -AllTools:$AllTools -UseAi:$UseAi -NoReport:$NoReport -Quiet:$Quiet

            $case = $result.Case

            if ($GuidedAi) {
                foreach ($evidence in @($case.evidence)) {
                    Invoke-OFAiGuidedAnalysis -Case $case -EvidenceId $evidence.id | Out-Null
                }
            }

            if ($Complete) {
                # Analisis bukti sudah dilakukan Invoke-OFWorkflow, jadi dilewati di sini.
                Invoke-OFCompleteWorkflow -Case $case -SkipAnalysis -UseAi:($UseAi -or $DeepAi) `
                    -SkipSeal:(-not $Seal) -SealPassphrase $SealPassphrase -Quiet:$Quiet | Out-Null
            } else {
                if ($DeepAi) { Invoke-OFAiDeepAnalysis -Case $case | Out-Null }
                if ($Seal) { Invoke-OFCliSeal -Case $case -Passphrase $SealPassphrase -Quiet:$Quiet | Out-Null }
            }

            Write-Host ''
            Write-Host "[+] Kasus: $($case.caseId)" -ForegroundColor Green
            Write-Host "    Folder: $($case.caseDir)" -ForegroundColor DarkGray
            exit 0
        }
    }
} catch {
    Write-Host "[-] Gagal: $($_.Exception.Message)" -ForegroundColor Red
    exit 1
}
