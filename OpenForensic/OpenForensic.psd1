@{
    RootModule        = 'OpenForensic.psm1'
    ModuleVersion     = '0.1.0'
    GUID              = '3f2b8c94-1d67-4a52-9e0b-7c6a5d4e8f31'
    Author            = 'stmarya'
    CompanyName       = 'OpenForensic'
    Copyright         = '(c) 2026 stmarya. MIT License.'
    Description       = 'OpenForensic / Kan9Ch3k - interactive digital forensics & CTF triage toolkit for Windows.'
    PowerShellVersion = '5.1'

    FunctionsToExport = @(
        'Get-OFPaths',
        'Get-OFToolCatalog',
        'Resolve-OFTool',
        'Get-OFToolStatus',
        'Get-OFFileType',
        'Get-OFEvidenceHash',
        'Get-OFStrings',
        'New-OFReport',
        'Complete-OFReport',
        'Write-OFCustodyLog',
        'Invoke-OFTool',
        'Invoke-OFTriage',
        'Get-OFAiApiKey',
        'Set-OFAiApiKey',
        'Clear-OFAiApiKey',
        'Invoke-OFAiAnalysis',
        'Show-OFMenu'
    )
    CmdletsToExport   = @()
    VariablesToExport = @()
    AliasesToExport   = @()

    PrivateData = @{
        PSData = @{
            Tags         = @('Forensics', 'CTF', 'Security', 'DFIR', 'Volatility')
            LicenseUri   = 'https://github.com/stmarya/OpenForensic/blob/main/LICENSE'
            ProjectUri   = 'https://github.com/stmarya/OpenForensic'
            ReleaseNotes = 'v0.1.0 - refactor ke module, eksekusi aman tanpa Invoke-Expression, magic-byte triage, evidence hashing + chain of custody, guardrail AI.'
        }
    }
}
