@{
    RootModule           = 'OpenForensic.psm1'
    ModuleVersion        = '0.2.0'
    GUID                 = 'b3f1c2d4-5a6b-4c7d-8e9f-0a1b2c3d4e5f'
    Author               = 'stmarya'
    CompanyName          = 'OpenForensic'
    Copyright            = '(c) 2026 stmarya. MIT License.'
    Description          = 'Core module untuk OpenForensic: katalog tool, hashing bukti, deteksi tipe file via magic bytes, eksekusi tool yang aman, report TXT/JSON, dan analisis LLM opsional.'
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
        'Update-OFTool'
    )
    CmdletsToExport      = @()
    VariablesToExport    = @()
    AliasesToExport      = @()
    PrivateData          = @{
        PSData = @{
            Tags         = @('forensics', 'ctf', 'dfir', 'security', 'volatility')
            LicenseUri   = 'https://github.com/stmarya/OpenForensic/blob/main/LICENSE'
            ProjectUri   = 'https://github.com/stmarya/OpenForensic'
            ReleaseNotes = 'Lihat CHANGELOG.md'
        }
    }
}
