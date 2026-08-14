@{
    RootModule           = 'OpenForensic.psm1'
    NestedModules        = @(
        'OpenForensic.Workflow.psm1',
        'OpenForensic.Ai.psm1',
        'OpenForensic.Integrity.psm1',
        'OpenForensic.Timeline.psm1',
        'OpenForensic.Models.psm1'
    )
    ModuleVersion        = '0.4.0'
    GUID                 = 'b3f1c2d4-5a6b-4c7d-8e9f-0a1b2c3d4e5f'
    Author               = 'stmarya'
    CompanyName          = 'OpenForensic'
    Copyright            = '(c) 2026 stmarya. MIT License.'
    Description          = 'OpenForensic: toolkit forensik digital berbasis PowerShell dengan alur kerja end-to-end berbasis kasus (bukti -> tool -> artefak -> timeline -> temuan -> report), integritas bukti (manifest + segel kriptografis), pemetaan MITRE ATT&CK, ekspor IOC (CSV/JSON/STIX/MISP), eksekusi tool yang aman tanpa shell evaluation, serta lapisan AI multi-provider dengan registry model milik pengguna sendiri.'
    PowerShellVersion    = '5.1'
    CompatiblePSEditions = @('Desktop', 'Core')
    FunctionsToExport    = @(
        'Get-OFPath',
        'Initialize-OFWorkspace',
        'Get-OFToolCatalog',
        'Resolve-OFTool',
        'Get-OFToolStatus',
        'Get-OFEvidenceHash',
        'Get-OFFileType',
        'Select-OFTargetFile',
        'Read-OFChoice',
        'New-OFReport',
        'Add-OFReportEntry',
        'Save-OFReport',
        'Get-OFReportList',
        'Invoke-OFTool',
        'Invoke-OFToolById',
        'Invoke-OFTriage',
        'Invoke-OFStrings',
        'Get-OFApiKey',
        'Set-OFApiKey',
        'Clear-OFApiKey',
        'Invoke-OFAiAnalysis',
        'Update-OFTool',
        'Get-OFCaseRoot',
        'New-OFCase',
        'Save-OFCase',
        'Get-OFCase',
        'Get-OFCaseList',
        'Add-OFCaseEvidence',
        'Get-OFCaseEvidence',
        'Add-OFCaseFinding',
        'Get-OFCaseFinding',
        'Add-OFCaseTimelineEntry',
        'Find-OFArtifact',
        'Get-OFApplicableTool',
        'Invoke-OFEvidenceAnalysis',
        'Get-OFCaseSummary',
        'Export-OFCaseReport',
        'Invoke-OFWorkflow',
        'Get-OFAiConfig',
        'Set-OFAiConfig',
        'Get-OFAiKey',
        'Confirm-OFAiConsent',
        'Protect-OFEvidenceText',
        'Invoke-OFAiCompletion',
        'Get-OFAiToolMenu',
        'Invoke-OFAiToolPlan',
        'Invoke-OFAiGuidedAnalysis',
        'Invoke-OFAiCaseAnalysis',
        'New-OFAiCaseReport',
        'Start-OFAiAssistant',
        'Invoke-OFProcessWithTimeout',
        'Get-OFToolVersion',
        'Update-OFCaseToolVersions',
        'Protect-OFEvidenceFile',
        'Test-OFEvidenceLock',
        'Get-OFHashAllowlist',
        'Test-OFHashAllowlist',
        'Add-OFHashToAllowlist',
        'Import-OFHashAllowlist',
        'Test-OFEvidenceDuplicate',
        'New-OFCaseManifest',
        'Test-OFCaseManifest',
        'New-OFCaseSeal',
        'Test-OFCaseSeal',
        'Get-OFIntegrityStatus',
        'Format-OFIntegritySummary',
        'Invoke-OFCaseSealWorkflow',
        'New-OFTimelineEvent',
        'Get-OFMitreTechnique',
        'Update-OFCaseMitre',
        'Get-OFMitreSummary',
        'Import-OFTimelineCsv',
        'Import-OFTimelineFromCase',
        'Get-OFTimeline',
        'Get-OFTimelineContext',
        'Export-OFTimeline',
        'Export-OFCaseIoc',
        'Invoke-OFTimelineWorkflow',
        'Get-OFAiModelPreset',
        'Register-OFAiModel',
        'Get-OFAiModelList',
        'Remove-OFAiModel',
        'Use-OFAiModel',
        'Test-OFAiModel',
        'Test-OFAiModelAll',
        'Initialize-OFAiModelDefaults',
        'Get-OFAiCaseContext',
        'Invoke-OFAiDeepAnalysis',
        'Invoke-OFCompleteWorkflow'
    )
    CmdletsToExport      = @()
    VariablesToExport    = @()
    AliasesToExport      = @()
    PrivateData          = @{
        PSData = @{
            Tags         = @('forensics', 'ctf', 'dfir', 'security', 'volatility', 'ai', 'incident-response', 'mitre-attack', 'timeline', 'ioc')
            LicenseUri   = 'https://github.com/stmarya/OpenForensic/blob/main/LICENSE'
            ProjectUri   = 'https://github.com/stmarya/OpenForensic'
            ReleaseNotes = 'Lihat CHANGELOG.md'
        }
    }
}
