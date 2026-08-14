#Requires -Version 5.1
<#
.SYNOPSIS
    CLI alur kerja kasus OpenForensic (end-to-end, non-interaktif).

.DESCRIPTION
    Satu perintah untuk seluruh siklus: buat kasus, daftarkan bukti (hash + chain of
    custody), jalankan tool sesuai tipe file, ekstrak artefak, buat temuan, analisis AI
    opsional, lalu ekspor report Markdown + HTML.

.EXAMPLE
    .\case.ps1 -Path .\bukti\dump.raw -CaseName "Insiden Workstation A"

.EXAMPLE
    .\case.ps1 -Path .\bukti\*.docx -CaseName "Phishing Batch" -CopyEvidence -UseAi

.EXAMPLE
    .\case.ps1 -List
    .\case.ps1 -CaseId CASE-20260814-231500-Insiden -Report
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
    [Parameter(ParameterSetName = 'Run')][switch]$UseAi,
    [Parameter(ParameterSetName = 'Run')][switch]$GuidedAi,
    [Parameter(ParameterSetName = 'Run')][switch]$NoReport,
    [Parameter(ParameterSetName = 'Run')][switch]$Quiet,

    [Parameter(ParameterSetName = 'Existing', Mandatory)][string]$CaseId,
    [Parameter(ParameterSetName = 'Existing')][string[]]$AddEvidence = @(),
    [Parameter(ParameterSetName = 'Existing')][switch]$Analyze,
    [Parameter(ParameterSetName = 'Existing')][switch]$AiAnalyze,
    [Parameter(ParameterSetName = 'Existing')][switch]$Assistant,
    [Parameter(ParameterSetName = 'Existing')][switch]$Report,
    [Parameter(ParameterSetName = 'Existing')][switch]$Summary,

    [Parameter(ParameterSetName = 'List', Mandatory)][switch]$List
)

$ErrorActionPreference = 'Stop'

$manifest = Join-Path $PSScriptRoot 'OpenForensic.psd1'
if (-not (Test-Path -LiteralPath $manifest)) {
    Write-Host '[-] OpenForensic.psd1 tidak ditemukan di folder skrip.' -ForegroundColor Red
    exit 2
}
Import-Module $manifest -Force -DisableNameChecking

try {
    switch ($PSCmdlet.ParameterSetName) {
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

            if ($AiAnalyze) { Invoke-OFAiCaseAnalysis -Case $case | Out-Null }
            if ($Assistant) { Start-OFAiAssistant -Case $case }
            if ($Report) { Export-OFCaseReport -Case $case -Format Both -IncludeArtifacts | Out-Null }
            if ($Summary -or -not ($AddEvidence.Count -or $Analyze -or $AiAnalyze -or $Assistant -or $Report)) {
                Get-OFCaseSummary -Case $case | Format-List | Out-Host
            }
            exit 0
        }

        default {
            if ($Path.Count -eq 0) {
                Write-Host 'Pemakaian:' -ForegroundColor Cyan
                Write-Host '  .\case.ps1 -Path <file...> [-CaseName "..."] [-CopyEvidence] [-AllTools] [-UseAi] [-GuidedAi]' -ForegroundColor Cyan
                Write-Host '  .\case.ps1 -List' -ForegroundColor Cyan
                Write-Host '  .\case.ps1 -CaseId <id> [-AddEvidence <file...>] [-Analyze] [-AiAnalyze] [-Assistant] [-Report]' -ForegroundColor Cyan
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

            if ($GuidedAi) {
                foreach ($evidence in @($result.Case.evidence)) {
                    Invoke-OFAiGuidedAnalysis -Case $result.Case -EvidenceId $evidence.id | Out-Null
                }
                Invoke-OFAiCaseAnalysis -Case $result.Case | Out-Null
                if (-not $NoReport) { Export-OFCaseReport -Case $result.Case -Format Both -IncludeArtifacts | Out-Null }
            }

            Write-Host ''
            Write-Host "[+] Kasus: $($result.Case.caseId)" -ForegroundColor Green
            Write-Host "    Folder: $($result.Case.caseDir)" -ForegroundColor DarkGray
            exit 0
        }
    }
} catch {
    Write-Host "[-] Gagal: $($_.Exception.Message)" -ForegroundColor Red
    exit 1
}
