#Requires -Version 5.1
<#
    OpenForensic workflow module.

    Menyatukan seluruh siklus pemeriksaan dalam satu alur kerja berbasis KASUS:

      New-OFCase -> Add-OFCaseEvidence -> Invoke-OFEvidenceAnalysis
                 -> Find-OFArtifact  -> Add-OFCaseFinding
                 -> Export-OFCaseReport

    Semua state kasus disimpan di cases/<CaseId>/case.json sehingga pemeriksaan
    dapat dilanjutkan kapan saja dan report selalu dapat dibangun ulang.
#>

Set-StrictMode -Version Latest

$script:CaseRoot          = Join-Path $PSScriptRoot 'cases'
$script:CaseSchemaVersion = 1
$script:WfUtf8            = New-Object System.Text.UTF8Encoding($false)
$script:WfToolkitVersion  = 'OpenForensic 0.3.0'
$script:MaxArtifactPerType = 25
$script:MaxLogLines        = 20000

$script:SeverityRank = @{ 'info' = 0; 'low' = 1; 'medium' = 2; 'high' = 3; 'critical' = 4 }

# Kind tambahan yang tidak dideteksi lewat magic bytes modul inti.
$script:ExtraExtensionKinds = @{
    '.evtx' = 'evtx'
    '.db' = 'sqlite'; '.sqlite' = 'sqlite'; '.sqlite3' = 'sqlite'; '.db3' = 'sqlite'
    '.apk' = 'apk'; '.dex' = 'apk'; '.jar' = 'apk'
    '.hiv' = 'registry'; '.hive' = 'registry'; '.dat' = 'registry'
    '.mft' = 'mft'
    '.dd' = 'diskimage'; '.e01' = 'diskimage'; '.vhd' = 'diskimage'; '.vhdx' = 'diskimage'
}

# Detektor artefak: regex dijalankan atas output tool (data tak terpercaya).
$script:ArtifactDetectors = @(
    @{ Name = 'url';             Category = 'network';    Severity = 'medium';   Pattern = '(?i)\b(?:https?|ftp)://[^\s<>"'']{4,}' }
    @{ Name = 'onion_address';   Category = 'network';    Severity = 'high';     Pattern = '(?i)\b[a-z2-7]{16,56}\.onion\b' }
    @{ Name = 'ipv4';            Category = 'network';    Severity = 'low';      Pattern = '\b(?:\d{1,3}\.){3}\d{1,3}\b' }
    @{ Name = 'domain';          Category = 'network';    Severity = 'low';      Pattern = '(?i)\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+(?:com|net|org|ru|cn|info|biz|xyz|top|tk|io|co|id|me|pw|su|onion)\b' }
    @{ Name = 'email';           Category = 'identity';   Severity = 'low';      Pattern = '\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b' }
    @{ Name = 'windows_path';    Category = 'filesystem'; Severity = 'info';     Pattern = '(?i)\b[a-z]:\\(?:[^\\/:*?<>|\r\n]+\\)+[^\\/:*?<>|\r\n]*' }
    @{ Name = 'unc_path';        Category = 'filesystem'; Severity = 'medium';   Pattern = '\\\\[A-Za-z0-9._-]{2,}\\[^\s<>"'']{2,}' }
    @{ Name = 'registry_autorun'; Category = 'persistence'; Severity = 'high';   Pattern = '(?i)(?:HKEY_[A-Z_]+|HKLM|HKCU|HKU)[\\][^\s<>"'']*Run[^\s<>"'']*' }
    @{ Name = 'service_create';  Category = 'persistence'; Severity = 'high';    Pattern = '(?i)\bsc(?:\.exe)?\s+(?:create|config)\b' }
    @{ Name = 'scheduled_task';  Category = 'persistence'; Severity = 'high';    Pattern = '(?i)\b(?:schtasks(?:\.exe)?|Register-ScheduledTask)\b' }
    @{ Name = 'powershell_encoded'; Category = 'execution'; Severity = 'critical'; Pattern = '(?i)(?:-enc(?:oded)?command|-ec|frombase64string)\b' }
    @{ Name = 'powershell_download'; Category = 'execution'; Severity = 'critical'; Pattern = '(?i)(?:downloadstring|downloadfile|invoke-webrequest|invoke-restmethod|net\.webclient|start-bitstransfer)' }
    @{ Name = 'lolbin';          Category = 'execution';  Severity = 'high';     Pattern = '(?i)\b(?:certutil|bitsadmin|mshta|regsvr32|rundll32|wmic|cscript|wscript|msiexec|installutil|odbcconf)(?:\.exe)?\b' }
    @{ Name = 'vba_autoexec';    Category = 'macro';      Severity = 'critical'; Pattern = '(?i)\b(?:AutoOpen|AutoExec|Auto_Open|Auto_Close|Document_Open|Workbook_Open|DocumentOpen)\b' }
    @{ Name = 'vba_suspicious';  Category = 'macro';      Severity = 'high';     Pattern = '(?i)\b(?:WScript\.Shell|Shell\s*\(|CreateObject|GetObject|VirtualAlloc|CallByName|Environ|Chr\s*\()' }
    @{ Name = 'pdf_active_content'; Category = 'document'; Severity = 'high';    Pattern = '/(?:JavaScript|JS|OpenAction|Launch|EmbeddedFile|AcroForm|RichMedia)\b' }
    @{ Name = 'embedded_pe';     Category = 'embedded';   Severity = 'high';     Pattern = 'This program cannot be run in DOS mode' }
    @{ Name = 'base64_blob';     Category = 'encoding';   Severity = 'medium';   Pattern = '[A-Za-z0-9+/]{100,}={0,2}' }
    @{ Name = 'private_key';     Category = 'credential'; Severity = 'critical'; Pattern = '-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY-----' }
    @{ Name = 'aws_access_key';  Category = 'credential'; Severity = 'critical'; Pattern = '\b(?:AKIA|ASIA)[0-9A-Z]{16}\b' }
    @{ Name = 'jwt';             Category = 'credential'; Severity = 'high';     Pattern = '\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}' }
    @{ Name = 'credential_pair'; Category = 'credential'; Severity = 'high';     Pattern = '(?i)\b(?:password|passwd|pwd|api[_-]?key|secret|token|credential)\s*[:=]\s*\S{4,}' }
    @{ Name = 'ntlm_hash_line';  Category = 'credential'; Severity = 'high';     Pattern = '(?i)^[^:\r\n]{1,64}:\d{3,6}:[a-f0-9]{32}:[a-f0-9]{32}:::' }
    @{ Name = 'bitcoin_address'; Category = 'crypto';     Severity = 'high';     Pattern = '\b(?:bc1[a-z0-9]{20,60}|[13][a-km-zA-HJ-NP-Z1-9]{25,34})\b' }
    @{ Name = 'ethereum_address'; Category = 'crypto';    Severity = 'medium';   Pattern = '\b0x[a-fA-F0-9]{40}\b' }
    @{ Name = 'ransom_note_hint'; Category = 'malware';   Severity = 'critical'; Pattern = '(?i)\b(?:your files (?:have been|are) encrypted|decrypt(?:or|ion) key|pay(?:ment)? in bitcoin|readme_?to_?decrypt)\b' }
    @{ Name = 'offensive_tool';  Category = 'malware';    Severity = 'critical'; Pattern = '(?i)\b(?:mimikatz|sekurlsa|lsadump|procdump|psexec|cobalt\s?strike|meterpreter|beacon\.dll|empire|sharphound|bloodhound|rubeus)\b' }
    @{ Name = 'ctf_flag';        Category = 'ctf';        Severity = 'critical'; Pattern = '(?i)\b(?:flag|ctf|key|htb|pico)\{[^}\r\n]{2,120}\}' }
    @{ Name = 'md5_hash';        Category = 'hash';       Severity = 'info';     Pattern = '\b[a-fA-F0-9]{32}\b' }
    @{ Name = 'sha256_hash';     Category = 'hash';       Severity = 'info';     Pattern = '\b[a-fA-F0-9]{64}\b' }
    @{ Name = 'prompt_injection'; Category = 'antiforensic'; Severity = 'high';  Pattern = '(?i)(?:ignore (?:all )?(?:previous|prior) instructions|you are now|system prompt|abaikan instruksi sebelumnya)' }
)

#region Helper privat

function ConvertTo-OFList {
    param($Value)
    $list = New-Object System.Collections.ArrayList
    if ($null -ne $Value) {
        foreach ($item in @($Value)) {
            if ($null -ne $item) { [void]$list.Add($item) }
        }
    }
    return , $list
}

function Get-OFProperty {
    param($Object, [string]$Name, $Default = $null)
    if ($null -eq $Object) { return $Default }
    if ($Object -is [System.Collections.IDictionary]) {
        if ($Object.Contains($Name)) { return $Object[$Name] }
        return $Default
    }
    if ($Object.PSObject.Properties.Name -contains $Name) {
        $value = $Object.PSObject.Properties[$Name].Value
        if ($null -eq $value) { return $Default }
        return $value
    }
    return $Default
}

function Get-OFNextId {
    param([Parameter(Mandatory)]$Collection, [Parameter(Mandatory)][string]$Prefix)
    return ('{0}{1:d3}' -f $Prefix, ($Collection.Count + 1))
}

function ConvertTo-OFHtmlText {
    param([string]$Text)
    if ([string]::IsNullOrEmpty($Text)) { return '' }
    return $Text.Replace('&', '&amp;').Replace('<', '&lt;').Replace('>', '&gt;').Replace('"', '&quot;')
}

function Add-OFCustody {
    param(
        [Parameter(Mandatory)]$Case,
        [Parameter(Mandatory)][string]$Action,
        [string]$Detail = ''
    )
    [void]$Case.chainOfCustody.Add([pscustomobject]@{
        at     = (Get-Date).ToString('o')
        actor  = $env:USERNAME
        host   = $env:COMPUTERNAME
        action = $Action
        detail = $Detail
    })
}

function Get-OFEvidenceKind {
    param([Parameter(Mandatory)][string]$Path)
    $type = Get-OFFileType -Path $Path
    $kind = $type.Kind
    if ($kind -eq 'unknown' -or $kind -eq 'zip') {
        $extension = $type.Extension
        if ($script:ExtraExtensionKinds.ContainsKey($extension)) {
            $kind = $script:ExtraExtensionKinds[$extension]
        }
    }
    return [pscustomobject]@{
        Kind        = $kind
        MagicKind   = $type.Kind
        Extension   = $type.Extension
        Description = $type.Description
        HexPrefix   = $type.HexPrefix
        TypeMismatch = $type.TypeMismatch
        ExpectedFromExtension = $type.ExpectedFromExtension
        Size        = $type.Size
    }
}

#endregion

function Get-OFCaseRoot {
    [CmdletBinding()]
    [OutputType([string])]
    param()
    if (-not (Test-Path -LiteralPath $script:CaseRoot)) {
        New-Item -ItemType Directory -Path $script:CaseRoot -Force | Out-Null
    }
    return $script:CaseRoot
}

function New-OFCase {
    [CmdletBinding(SupportsShouldProcess)]
    [OutputType([psobject])]
    param(
        [Parameter(Mandatory)][string]$Name,
        [string]$Examiner = $env:USERNAME,
        [string]$Description = '',
        [string]$Reference = '',
        [ValidateSet('public', 'internal', 'confidential', 'restricted')][string]$Classification = 'internal'
    )

    $root = Get-OFCaseRoot
    $slug = ($Name -replace '[^\w\-]', '_')
    if ($slug.Length -gt 40) { $slug = $slug.Substring(0, 40) }
    $caseId = 'CASE-{0}-{1}' -f (Get-Date -Format 'yyyyMMdd-HHmmss'), $slug
    $caseDir = Join-Path $root $caseId

    if (-not $PSCmdlet.ShouldProcess($caseDir, 'Buat kasus baru')) { return $null }

    foreach ($sub in @('', 'logs', 'artifacts', 'ai', 'exports', 'evidence')) {
        $path = if ($sub) { Join-Path $caseDir $sub } else { $caseDir }
        New-Item -ItemType Directory -Path $path -Force | Out-Null
    }

    $case = [pscustomobject]@{
        schemaVersion  = $script:CaseSchemaVersion
        caseId         = $caseId
        name           = $Name
        description    = $Description
        reference      = $Reference
        classification = $Classification
        examiner       = $Examiner
        status         = 'open'
        toolkit        = $script:WfToolkitVersion
        createdAt      = (Get-Date).ToString('o')
        updatedAt      = (Get-Date).ToString('o')
        caseDir        = $caseDir
        evidence       = (New-Object System.Collections.ArrayList)
        findings       = (New-Object System.Collections.ArrayList)
        artifacts      = (New-Object System.Collections.ArrayList)
        timeline       = (New-Object System.Collections.ArrayList)
        chainOfCustody = (New-Object System.Collections.ArrayList)
        ai             = [pscustomobject]@{
            enabled   = $false
            provider  = ''
            model     = ''
            summary   = ''
            narrative = ''
            runs      = @()
        }
    }

    Add-OFCustody -Case $case -Action 'case_created' -Detail "Kasus '$Name' dibuat (klasifikasi: $Classification)"
    Save-OFCase -Case $case | Out-Null

    Write-Host "[+] Kasus dibuat: $caseId" -ForegroundColor Green
    Write-Host "    Folder: $caseDir" -ForegroundColor DarkGray
    return $case
}

function Save-OFCase {
    [CmdletBinding()]
    [OutputType([psobject])]
    param([Parameter(Mandatory)]$Case)

    $Case.updatedAt = (Get-Date).ToString('o')
    $path = Join-Path $Case.caseDir 'case.json'
    $json = $Case | ConvertTo-Json -Depth 12
    [System.IO.File]::WriteAllText($path, $json, $script:WfUtf8)
    return $Case
}

function Get-OFCaseList {
    [CmdletBinding()]
    [OutputType([psobject])]
    param([ValidateRange(1, 500)][int]$Limit = 25)

    $root = Get-OFCaseRoot
    Get-ChildItem -LiteralPath $root -Directory -ErrorAction SilentlyContinue |
        Sort-Object LastWriteTime -Descending |
        Select-Object -First $Limit |
        ForEach-Object {
            $manifest = Join-Path $_.FullName 'case.json'
            if (Test-Path -LiteralPath $manifest) {
                try {
                    $data = Get-Content -LiteralPath $manifest -Raw -Encoding UTF8 | ConvertFrom-Json
                    [pscustomobject]@{
                        CaseId    = $data.caseId
                        Name      = $data.name
                        Examiner  = $data.examiner
                        Status    = $data.status
                        Evidence  = @(Get-OFProperty $data 'evidence' @()).Count
                        Findings  = @(Get-OFProperty $data 'findings' @()).Count
                        UpdatedAt = $data.updatedAt
                        Path      = $_.FullName
                    }
                } catch {
                    Write-Warning "case.json tidak dapat dibaca di $($_.FullName)"
                }
            }
        }
}

function Get-OFCase {
    [CmdletBinding(DefaultParameterSetName = 'ById')]
    [OutputType([psobject])]
    param(
        [Parameter(Mandatory, ParameterSetName = 'ById', Position = 0)][string]$CaseId,
        [Parameter(Mandatory, ParameterSetName = 'ByPath')][string]$Path
    )

    if ($PSCmdlet.ParameterSetName -eq 'ById') {
        $caseDir = Join-Path (Get-OFCaseRoot) $CaseId
    } else {
        $caseDir = (Resolve-Path -LiteralPath $Path).Path
    }

    $manifest = Join-Path $caseDir 'case.json'
    if (-not (Test-Path -LiteralPath $manifest)) { throw "Kasus tidak ditemukan: $manifest" }

    $case = Get-Content -LiteralPath $manifest -Raw -Encoding UTF8 | ConvertFrom-Json
    $case.caseDir = $caseDir
    $case.evidence = ConvertTo-OFList (Get-OFProperty $case 'evidence' @())
    $case.findings = ConvertTo-OFList (Get-OFProperty $case 'findings' @())
    $case.artifacts = ConvertTo-OFList (Get-OFProperty $case 'artifacts' @())
    $case.timeline = ConvertTo-OFList (Get-OFProperty $case 'timeline' @())
    $case.chainOfCustody = ConvertTo-OFList (Get-OFProperty $case 'chainOfCustody' @())
    foreach ($evidence in $case.evidence) {
        $evidence.analyses = ConvertTo-OFList (Get-OFProperty $evidence 'analyses' @())
    }
    return $case
}

function Add-OFCaseEvidence {
    [CmdletBinding(SupportsShouldProcess)]
    [OutputType([psobject])]
    param(
        [Parameter(Mandatory)]$Case,
        [Parameter(Mandatory)][string]$Path,
        [string]$Description = '',
        [string]$Source = '',
        [switch]$Copy
    )

    $item = Get-Item -LiteralPath $Path -ErrorAction Stop
    if (-not $PSCmdlet.ShouldProcess($item.FullName, 'Tambahkan bukti ke kasus')) { return $null }

    $hash = Get-OFEvidenceHash -Path $item.FullName
    $existing = $Case.evidence | Where-Object { $_.sha256 -eq $hash.SHA256 } | Select-Object -First 1
    if ($existing) {
        Write-Host "[i] Bukti dengan SHA256 sama sudah terdaftar sebagai $($existing.id)." -ForegroundColor DarkYellow
        return $existing
    }

    $workingPath = $item.FullName
    if ($Copy) {
        $destination = Join-Path (Join-Path $Case.caseDir 'evidence') $item.Name
        Copy-Item -LiteralPath $item.FullName -Destination $destination -Force
        $copyHash = Get-OFEvidenceHash -Path $destination
        if ($copyHash.SHA256 -ne $hash.SHA256) { throw 'Verifikasi salinan bukti GAGAL: SHA256 salinan berbeda dari aslinya.' }
        $workingPath = $destination
        Write-Host '[+] Salinan bukti dibuat dan diverifikasi (SHA256 identik).' -ForegroundColor Green
    }

    $type = Get-OFEvidenceKind -Path $workingPath
    $id = Get-OFNextId -Collection $Case.evidence -Prefix 'E'

    $evidence = [pscustomobject]@{
        id             = $id
        name           = $item.Name
        originalPath   = $item.FullName
        workingPath    = $workingPath
        isCopy         = [bool]$Copy
        size           = $hash.Size
        md5            = $hash.MD5
        sha1           = $hash.SHA1
        sha256         = $hash.SHA256
        kind           = $type.Kind
        magicKind      = $type.MagicKind
        extension      = $type.Extension
        magicHex       = $type.HexPrefix
        typeDescription = $type.Description
        typeMismatch   = $type.TypeMismatch
        description    = $Description
        source         = $Source
        modifiedAt     = $item.LastWriteTime.ToString('o')
        addedAt        = (Get-Date).ToString('o')
        addedBy        = $env:USERNAME
        integrityVerified = $null
        analyses       = (New-Object System.Collections.ArrayList)
    }

    [void]$Case.evidence.Add($evidence)
    Add-OFCustody -Case $Case -Action 'evidence_added' -Detail "$id $($item.Name) SHA256=$($hash.SHA256)"
    Add-OFCaseTimelineEntry -Case $Case -Timestamp $evidence.modifiedAt -Event "File bukti terakhir dimodifikasi: $($item.Name)" -Source 'filesystem' -EvidenceId $id | Out-Null

    if ($type.TypeMismatch) {
        Add-OFCaseFinding -Case $Case -Title "Ekstensi file tidak sesuai isi: $($item.Name)" `
            -Severity 'medium' -Category 'antiforensic' -EvidenceId $id -ToolId 'builtin:filetype' `
            -Indicator "ekstensi $($type.Extension) vs isi $($type.Kind)" `
            -Description 'Magic bytes tidak cocok dengan ekstensi file. Ini indikasi upaya penyamaran tipe file.' `
            -Confidence 'high' | Out-Null
    }

    Save-OFCase -Case $Case | Out-Null
    Write-Host "[+] Bukti $id ditambahkan: $($item.Name) ($($type.Kind), $($hash.Size) byte)" -ForegroundColor Green
    return $evidence
}

function Get-OFCaseEvidence {
    [CmdletBinding()]
    [OutputType([psobject])]
    param(
        [Parameter(Mandatory)]$Case,
        [string]$EvidenceId = ''
    )
    if ([string]::IsNullOrWhiteSpace($EvidenceId)) { return $Case.evidence }
    $evidence = $Case.evidence | Where-Object { $_.id -eq $EvidenceId } | Select-Object -First 1
    if (-not $evidence) { throw "Bukti '$EvidenceId' tidak ada dalam kasus $($Case.caseId)" }
    return $evidence
}

function Add-OFCaseFinding {
    [CmdletBinding()]
    [OutputType([psobject])]
    param(
        [Parameter(Mandatory)]$Case,
        [Parameter(Mandatory)][string]$Title,
        [ValidateSet('info', 'low', 'medium', 'high', 'critical')][string]$Severity = 'medium',
        [string]$Category = 'general',
        [string]$EvidenceId = '',
        [string]$ToolId = '',
        [string]$Indicator = '',
        [string]$Description = '',
        [ValidateSet('low', 'medium', 'high')][string]$Confidence = 'medium',
        [string]$Mitre = '',
        [ValidateSet('tool', 'detector', 'ai', 'analyst')][string]$Origin = 'detector',
        [switch]$PassThru
    )

    $duplicate = $Case.findings | Where-Object {
        $_.title -eq $Title -and $_.evidenceId -eq $EvidenceId -and $_.indicator -eq $Indicator
    } | Select-Object -First 1
    if ($duplicate) { return $duplicate }

    $finding = [pscustomobject]@{
        id          = Get-OFNextId -Collection $Case.findings -Prefix 'F'
        title       = $Title
        severity    = $Severity
        severityRank = $script:SeverityRank[$Severity]
        category    = $Category
        evidenceId  = $EvidenceId
        toolId      = $ToolId
        indicator   = $Indicator
        description = $Description
        confidence  = $Confidence
        mitre       = $Mitre
        origin      = $Origin
        status      = 'open'
        createdAt   = (Get-Date).ToString('o')
        createdBy   = $env:USERNAME
    }

    [void]$Case.findings.Add($finding)
    if ($PassThru) { return $finding }
    return $finding
}

function Get-OFCaseFinding {
    [CmdletBinding()]
    [OutputType([psobject])]
    param(
        [Parameter(Mandatory)]$Case,
        [ValidateSet('info', 'low', 'medium', 'high', 'critical')][string]$MinSeverity = 'info',
        [string]$EvidenceId = ''
    )
    $threshold = $script:SeverityRank[$MinSeverity]
    $Case.findings |
        Where-Object { $script:SeverityRank[[string]$_.severity] -ge $threshold } |
        Where-Object { -not $EvidenceId -or $_.evidenceId -eq $EvidenceId } |
        Sort-Object -Property @{ Expression = { $script:SeverityRank[[string]$_.severity] }; Descending = $true }, id
}

function Add-OFCaseTimelineEntry {
    [CmdletBinding()]
    [OutputType([psobject])]
    param(
        [Parameter(Mandatory)]$Case,
        [Parameter(Mandatory)][string]$Timestamp,
        [Parameter(Mandatory)][string]$Event,
        [string]$Source = '',
        [string]$EvidenceId = ''
    )
    $entry = [pscustomobject]@{
        timestamp  = $Timestamp
        event      = $Event
        source     = $Source
        evidenceId = $EvidenceId
        addedAt    = (Get-Date).ToString('o')
    }
    [void]$Case.timeline.Add($entry)
    return $entry
}

function Find-OFArtifact {
    [CmdletBinding()]
    [OutputType([psobject])]
    param(
        [Parameter(Mandatory)][AllowEmptyCollection()][string[]]$Text,
        [string]$ToolId = '',
        [string]$EvidenceId = '',
        [ValidateRange(1, 500)][int]$MaxPerType = $script:MaxArtifactPerType,
        [string[]]$DetectorName = @()
    )

    $detectors = $script:ArtifactDetectors
    if ($DetectorName.Count -gt 0) {
        $detectors = @($detectors | Where-Object { $DetectorName -contains $_.Name })
    }

    $blob = ($Text -join "`n")
    if ([string]::IsNullOrWhiteSpace($blob)) { return @() }

    $results = New-Object System.Collections.ArrayList
    foreach ($detector in $detectors) {
        $seen = New-Object 'System.Collections.Generic.Dictionary[string,int]'
        $hits = [regex]::Matches($blob, $detector.Pattern, [System.Text.RegularExpressions.RegexOptions]::Multiline)
        foreach ($hit in $hits) {
            $value = $hit.Value.Trim()
            if ($value.Length -gt 300) { $value = $value.Substring(0, 300) + '...' }
            if ($seen.ContainsKey($value)) {
                $seen[$value] = $seen[$value] + 1
            } elseif ($seen.Count -lt $MaxPerType) {
                $seen[$value] = 1
            }
        }
        foreach ($key in $seen.Keys) {
            [void]$results.Add([pscustomobject]@{
                type       = $detector.Name
                category   = $detector.Category
                severity   = $detector.Severity
                value      = $key
                count      = $seen[$key]
                toolId     = $ToolId
                evidenceId = $EvidenceId
                foundAt    = (Get-Date).ToString('o')
            })
        }
        if ($hits.Count -gt $MaxPerType) {
            Write-Verbose "Detector $($detector.Name): $($hits.Count) hit, dipotong pada $MaxPerType nilai unik."
        }
    }
    return $results
}

function Get-OFApplicableTool {
    [CmdletBinding()]
    [OutputType([psobject])]
    param(
        [Parameter(Mandatory)][string]$Path,
        $Catalog,
        [switch]$TriageOnly,
        [switch]$AvailableOnly
    )

    if (-not $Catalog) { $Catalog = Get-OFToolCatalog }
    $type = Get-OFEvidenceKind -Path $Path

    $matched = @($Catalog | Where-Object {
        $kinds = @(Get-OFProperty $_ 'kinds' @())
        $extensions = @(Get-OFProperty $_ 'extensions' @())
        ($kinds -contains $type.Kind) -or ($kinds -contains $type.MagicKind) -or ($extensions -contains $type.Extension)
    })

    if ($TriageOnly) { $matched = @($matched | Where-Object { $_.triage }) }

    if ($matched.Count -eq 0) {
        $matched = @($Catalog | Where-Object { $_.id -in @('strings', 'exiftool') })
    }

    $resolved = foreach ($definition in $matched) { Resolve-OFTool -Id $definition.id -Catalog $Catalog }
    if ($AvailableOnly) { $resolved = @($resolved | Where-Object { $_.Available }) }
    return @($resolved)
}

function Invoke-OFEvidenceAnalysis {
    [CmdletBinding()]
    [OutputType([psobject])]
    param(
        [Parameter(Mandatory)]$Case,
        [Parameter(Mandatory)][string]$EvidenceId,
        [string[]]$ToolIds = @(),
        [string]$Plugin = '',
        [switch]$AllTools,
        [switch]$Quiet
    )

    $evidence = Get-OFCaseEvidence -Case $Case -EvidenceId $EvidenceId
    $targetPath = $evidence.workingPath
    if (-not (Test-Path -LiteralPath $targetPath)) { throw "File bukti tidak ditemukan lagi: $targetPath" }

    $catalog = Get-OFToolCatalog
    if ($ToolIds.Count -gt 0) {
        $tools = foreach ($id in $ToolIds) { Resolve-OFTool -Id $id -Catalog $catalog }
        $tools = @($tools)
    } elseif ($AllTools) {
        $tools = Get-OFApplicableTool -Path $targetPath -Catalog $catalog -AvailableOnly
    } else {
        $tools = Get-OFApplicableTool -Path $targetPath -Catalog $catalog -TriageOnly -AvailableOnly
    }

    Write-Host ''
    Write-Host "[*] Menganalisis $($evidence.id) - $($evidence.name) (tipe: $($evidence.kind))" -ForegroundColor Cyan
    Write-Host "    Tool terpilih: $((@($tools | ForEach-Object { $_.Id })) -join ', ')" -ForegroundColor DarkGray

    $collected = New-Object System.Collections.ArrayList
    $executed = 0

    foreach ($tool in $tools) {
        if (-not $tool.Available) {
            Write-Host "[-] Lewati $($tool.Name): belum terpasang. $($tool.InstallHint)" -ForegroundColor DarkYellow
            continue
        }

        $argumentSets = @()
        $triageArgs = @(Get-OFProperty $tool.Definition 'triageArgs' @())
        if ($triageArgs.Count -gt 0 -and $ToolIds.Count -eq 0) {
            $argumentSets = $triageArgs
        } else {
            $argumentSets = @(, @(Get-OFProperty $tool.Definition 'argTemplate' @()))
        }

        foreach ($argumentSet in $argumentSets) {
            Write-Host "[+] Menjalankan $($tool.Name)..." -ForegroundColor Green
            $logName = '{0}_{1}_{2}.log' -f $evidence.id, $tool.Id, (Get-Date -Format 'HHmmss')
            $logPath = Join-Path (Join-Path $Case.caseDir 'logs') $logName

            $result = Invoke-OFToolById -ToolId $tool.Id -TargetPath $targetPath -Plugin $Plugin `
                -ArgumentTemplate @($argumentSet) -Catalog $catalog -Quiet:$Quiet

            if (-not $result) { continue }
            $executed++

            $lines = @($result.Output)
            if ($lines.Count -gt $script:MaxLogLines) {
                $lines = @($lines[0..($script:MaxLogLines - 1)]) + @("--- output dipotong pada $($script:MaxLogLines) baris ---")
            }
            $header = @(
                '# OpenForensic tool log',
                "# Kasus    : $($Case.caseId)",
                "# Bukti    : $($evidence.id) $($evidence.name)",
                "# SHA256   : $($evidence.sha256)",
                "# Tool     : $($tool.Id) ($($tool.Name))",
                "# Command  : $($result.Command)",
                "# Argumen  : $((@($result.Arguments | ForEach-Object { '[' + $_ + ']' })) -join ' ')",
                "# ExitCode : $($result.ExitCode)",
                "# Waktu    : $(Get-Date -Format o)",
                '#' + ('-' * 66)
            )
            [System.IO.File]::WriteAllText($logPath, (($header + $lines) -join [Environment]::NewLine), $script:WfUtf8)

            [void]$evidence.analyses.Add([pscustomobject]@{
                toolId          = $tool.Id
                toolName        = $tool.Name
                phase           = [string](Get-OFProperty $tool.Definition 'phase' 'analyze')
                command         = $result.Command
                arguments       = @($result.Arguments)
                exitCode        = $result.ExitCode
                success         = $result.Success
                durationSeconds = [math]::Round($result.DurationSeconds, 3)
                outputLines     = @($result.Output).Count
                logPath         = ('logs/' + $logName)
                executedAt      = (Get-Date).ToString('o')
                error           = $result.Error
            })

            foreach ($line in $result.Output) { [void]$collected.Add([string]$line) }

            if (-not $result.Success -and $result.Error) {
                Write-Host "    [!] $($tool.Name) melaporkan error: $($result.Error)" -ForegroundColor DarkYellow
            }
        }
    }

    # Ekstraksi artefak dari seluruh output tool.
    $artifacts = @(Find-OFArtifact -Text @($collected) -EvidenceId $evidence.id)
    $newArtifacts = 0
    foreach ($artifact in $artifacts) {
        $exists = $Case.artifacts | Where-Object {
            $_.type -eq $artifact.type -and $_.value -eq $artifact.value -and $_.evidenceId -eq $artifact.evidenceId
        } | Select-Object -First 1
        if ($exists) { continue }
        $artifact | Add-Member -NotePropertyName 'id' -NotePropertyValue (Get-OFNextId -Collection $Case.artifacts -Prefix 'A') -Force
        [void]$Case.artifacts.Add($artifact)
        $newArtifacts++
    }

    # Artefak severity tinggi otomatis menjadi finding.
    $promoted = 0
    $groups = $artifacts | Where-Object { $script:SeverityRank[[string]$_.severity] -ge 3 } | Group-Object -Property type
    foreach ($group in $groups) {
        $sample = @($group.Group | Select-Object -First 3 | ForEach-Object { $_.value })
        $severity = [string]$group.Group[0].severity
        $category = [string]$group.Group[0].category
        $finding = Add-OFCaseFinding -Case $Case `
            -Title ("Artefak {0} terdeteksi pada {1}" -f $group.Name, $evidence.name) `
            -Severity $severity -Category $category -EvidenceId $evidence.id -ToolId 'detector' `
            -Indicator ($sample -join ' | ') `
            -Description ("Detector '{0}' menemukan {1} nilai unik pada output tool. Contoh: {2}" -f $group.Name, $group.Count, ($sample -join ', ')) `
            -Confidence 'medium' -Origin 'detector'
        if ($finding) { $promoted++ }
    }

    # Verifikasi integritas bukti setelah analisis.
    $after = Get-OFEvidenceHash -Path $targetPath
    $evidence.integrityVerified = ($after.SHA256 -eq $evidence.sha256)
    if (-not $evidence.integrityVerified) {
        Add-OFCaseFinding -Case $Case -Title "Integritas bukti $($evidence.id) GAGAL diverifikasi" `
            -Severity 'critical' -Category 'integrity' -EvidenceId $evidence.id -ToolId 'builtin:hash' `
            -Indicator "SHA256 awal $($evidence.sha256) menjadi $($after.SHA256)" `
            -Description 'Hash file bukti berubah selama proses analisis. Chain of custody terancam.' `
            -Confidence 'high' | Out-Null
    }

    Add-OFCustody -Case $Case -Action 'evidence_analyzed' `
        -Detail "$($evidence.id): $executed eksekusi tool, $newArtifacts artefak baru, $promoted finding baru"
    Save-OFCase -Case $Case | Out-Null

    Write-Host "[+] Selesai: $executed eksekusi tool, $newArtifacts artefak, $promoted finding." -ForegroundColor Cyan

    return [pscustomobject]@{
        EvidenceId    = $evidence.id
        ToolsExecuted = $executed
        OutputLines   = $collected.Count
        Artifacts     = $artifacts
        NewArtifacts  = $newArtifacts
        NewFindings   = $promoted
        IntegrityOk   = $evidence.integrityVerified
        Output        = @($collected)
    }
}

function Get-OFCaseSummary {
    [CmdletBinding()]
    [OutputType([psobject])]
    param([Parameter(Mandatory)]$Case)

    $counts = @{}
    foreach ($level in @('critical', 'high', 'medium', 'low', 'info')) {
        $counts[$level] = @($Case.findings | Where-Object { $_.severity -eq $level }).Count
    }
    $verdict = 'BERSIH / TIDAK ADA INDIKASI'
    if ($counts['critical'] -gt 0) { $verdict = 'BERBAHAYA' }
    elseif ($counts['high'] -gt 0) { $verdict = 'MENCURIGAKAN (PRIORITAS TINGGI)' }
    elseif ($counts['medium'] -gt 0) { $verdict = 'PERLU PEMERIKSAAN LANJUTAN' }

    [pscustomobject]@{
        CaseId        = $Case.caseId
        Name          = $Case.name
        Examiner      = $Case.examiner
        Status        = $Case.status
        EvidenceCount = $Case.evidence.Count
        ToolRuns      = @($Case.evidence | ForEach-Object { $_.analyses.Count } | Measure-Object -Sum).Sum
        ArtifactCount = $Case.artifacts.Count
        FindingCount  = $Case.findings.Count
        Critical      = $counts['critical']
        High          = $counts['high']
        Medium        = $counts['medium']
        Low           = $counts['low']
        Info          = $counts['info']
        Verdict       = $verdict
    }
}

function Export-OFCaseReport {
    [CmdletBinding()]
    [OutputType([psobject])]
    param(
        [Parameter(Mandatory)]$Case,
        [ValidateSet('Markdown', 'Html', 'Both')][string]$Format = 'Both',
        [switch]$IncludeArtifacts
    )

    $summary = Get-OFCaseSummary -Case $Case
    $exportDir = Join-Path $Case.caseDir 'exports'
    if (-not (Test-Path -LiteralPath $exportDir)) { New-Item -ItemType Directory -Path $exportDir -Force | Out-Null }

    $aiSummary = [string](Get-OFProperty $Case.ai 'summary' '')
    $aiNarrative = [string](Get-OFProperty $Case.ai 'narrative' '')

    $lines = New-Object System.Collections.ArrayList
    function Add-Line { param([string]$Text = '') [void]$lines.Add($Text) }

    Add-Line "# Laporan Forensik Digital - $($Case.name)"
    Add-Line
    Add-Line "| | |"
    Add-Line "|---|---|"
    Add-Line "| Case ID | $($Case.caseId) |"
    Add-Line "| Referensi | $($Case.reference) |"
    Add-Line "| Klasifikasi | $($Case.classification) |"
    Add-Line "| Pemeriksa | $($Case.examiner) |"
    Add-Line "| Status | $($Case.status) |"
    Add-Line "| Dibuat | $($Case.createdAt) |"
    Add-Line "| Laporan dibuat | $(Get-Date -Format o) |"
    Add-Line "| Toolkit | $($Case.toolkit) |"
    Add-Line
    Add-Line '## 1. Ringkasan Eksekutif'
    Add-Line
    Add-Line "**Kesimpulan awal otomatis: $($summary.Verdict)**"
    Add-Line
    Add-Line "- Bukti diperiksa: $($summary.EvidenceCount)"
    Add-Line "- Eksekusi tool: $($summary.ToolRuns)"
    Add-Line "- Artefak terkumpul: $($summary.ArtifactCount)"
    Add-Line "- Temuan: $($summary.FindingCount) (critical $($summary.Critical), high $($summary.High), medium $($summary.Medium), low $($summary.Low), info $($summary.Info))"
    Add-Line
    if ($Case.description) {
        Add-Line '### Latar belakang perkara'
        Add-Line
        Add-Line $Case.description
        Add-Line
    }
    if ($aiSummary) {
        Add-Line '### Ringkasan hasil analisis AI'
        Add-Line
        Add-Line $aiSummary
        Add-Line
        Add-Line '> Ringkasan AI bersifat indikatif dan telah/harus diverifikasi oleh pemeriksa.'
        Add-Line
    }

    Add-Line '## 2. Daftar Bukti (Evidence)'
    Add-Line
    Add-Line '| ID | Nama | Ukuran | Tipe | SHA256 | Integritas |'
    Add-Line '|---|---|---|---|---|---|'
    foreach ($evidence in $Case.evidence) {
        $integrity = switch ([string](Get-OFProperty $evidence 'integrityVerified' '')) {
            'True' { 'OK' }
            'False' { 'GAGAL' }
            default { 'belum diverifikasi' }
        }
        Add-Line "| $($evidence.id) | $($evidence.name) | $($evidence.size) B | $($evidence.kind) | ``$($evidence.sha256)`` | $integrity |"
    }
    Add-Line
    foreach ($evidence in $Case.evidence) {
        Add-Line "### $($evidence.id) - $($evidence.name)"
        Add-Line
        Add-Line "- Path asal: ``$($evidence.originalPath)``"
        Add-Line "- Path kerja: ``$($evidence.workingPath)`` (salinan: $($evidence.isCopy))"
        Add-Line "- MD5: ``$($evidence.md5)``"
        Add-Line "- SHA1: ``$($evidence.sha1)``"
        Add-Line "- SHA256: ``$($evidence.sha256)``"
        Add-Line "- Magic bytes: ``$($evidence.magicHex)`` ($($evidence.typeDescription))"
        if ($evidence.typeMismatch) { Add-Line "- **Peringatan:** ekstensi $($evidence.extension) tidak sesuai isi file." }
        if ($evidence.description) { Add-Line "- Keterangan: $($evidence.description)" }
        Add-Line
    }

    Add-Line '## 3. Metode dan Tool yang Digunakan'
    Add-Line
    Add-Line '| Bukti | Tool | Fase | Exit code | Durasi (s) | Baris output | Log |'
    Add-Line '|---|---|---|---|---|---|---|'
    foreach ($evidence in $Case.evidence) {
        foreach ($analysis in $evidence.analyses) {
            Add-Line "| $($evidence.id) | $($analysis.toolName) | $($analysis.phase) | $($analysis.exitCode) | $($analysis.durationSeconds) | $($analysis.outputLines) | ``$($analysis.logPath)`` |"
        }
    }
    Add-Line

    Add-Line '## 4. Temuan (Findings)'
    Add-Line
    $findings = @(Get-OFCaseFinding -Case $Case)
    if ($findings.Count -eq 0) {
        Add-Line 'Tidak ada temuan yang tercatat.'
        Add-Line
    } else {
        Add-Line '| ID | Severity | Kategori | Judul | Bukti | Sumber | Keyakinan |'
        Add-Line '|---|---|---|---|---|---|---|'
        foreach ($finding in $findings) {
            Add-Line "| $($finding.id) | $($finding.severity.ToUpperInvariant()) | $($finding.category) | $($finding.title) | $($finding.evidenceId) | $($finding.origin) | $($finding.confidence) |"
        }
        Add-Line
        foreach ($finding in $findings) {
            Add-Line "### $($finding.id) - $($finding.title)"
            Add-Line
            Add-Line "- Severity: **$($finding.severity.ToUpperInvariant())** | Keyakinan: $($finding.confidence) | Kategori: $($finding.category)"
            Add-Line "- Bukti terkait: $($finding.evidenceId) | Sumber: $($finding.origin) | Tool: $($finding.toolId)"
            if ($finding.mitre) { Add-Line "- MITRE ATT&CK: $($finding.mitre)" }
            if ($finding.indicator) {
                Add-Line '- Indikator:'
                Add-Line
                Add-Line '```'
                Add-Line ([string]$finding.indicator)
                Add-Line '```'
            }
            if ($finding.description) {
                Add-Line
                Add-Line ([string]$finding.description)
            }
            Add-Line
        }
    }

    if ($IncludeArtifacts -and $Case.artifacts.Count -gt 0) {
        Add-Line '## 5. Artefak Terekstraksi'
        Add-Line
        Add-Line '| ID | Tipe | Kategori | Severity | Nilai | Jumlah | Bukti |'
        Add-Line '|---|---|---|---|---|---|---|'
        foreach ($artifact in ($Case.artifacts | Sort-Object -Property @{ Expression = { $script:SeverityRank[[string]$_.severity] }; Descending = $true })) {
            $value = ([string]$artifact.value).Replace('|', '\|')
            Add-Line "| $($artifact.id) | $($artifact.type) | $($artifact.category) | $($artifact.severity) | ``$value`` | $($artifact.count) | $($artifact.evidenceId) |"
        }
        Add-Line
    }

    Add-Line '## 6. Timeline'
    Add-Line
    if ($Case.timeline.Count -eq 0) {
        Add-Line 'Belum ada entri timeline.'
    } else {
        Add-Line '| Waktu | Peristiwa | Sumber | Bukti |'
        Add-Line '|---|---|---|---|'
        foreach ($entry in ($Case.timeline | Sort-Object timestamp)) {
            Add-Line "| $($entry.timestamp) | $($entry.event) | $($entry.source) | $($entry.evidenceId) |"
        }
    }
    Add-Line

    Add-Line '## 7. Chain of Custody'
    Add-Line
    Add-Line '| Waktu | Aktor | Host | Aksi | Detail |'
    Add-Line '|---|---|---|---|---|'
    foreach ($entry in $Case.chainOfCustody) {
        Add-Line "| $($entry.at) | $($entry.actor) | $($entry.host) | $($entry.action) | $($entry.detail) |"
    }
    Add-Line

    if ($aiNarrative) {
        Add-Line '## 8. Analisis Naratif (dibantu AI)'
        Add-Line
        Add-Line $aiNarrative
        Add-Line
        Add-Line '> Bagian ini dihasilkan dengan bantuan LLM berdasarkan artefak dan temuan di atas.'
        Add-Line '> Setiap pernyataan harus divalidasi terhadap log tool sebelum dipakai sebagai kesimpulan resmi.'
        Add-Line
    }

    Add-Line '## 9. Keterbatasan dan Pernyataan'
    Add-Line
    Add-Line '- Analisis otomatis tidak menggantikan pemeriksaan manual oleh pemeriksa bersertifikat.'
    Add-Line '- Deteksi berbasis pola dapat menghasilkan positif palsu; setiap temuan wajib diverifikasi pada log tool.'
    Add-Line '- Hash bukti dicatat sebelum dan sesudah analisis untuk membuktikan bukti tidak berubah.'
    Add-Line '- Semua eksekusi tool dilakukan dengan argumen terisolasi (tanpa evaluasi shell).'
    Add-Line
    Add-Line "_Dokumen ini dihasilkan otomatis oleh $($Case.toolkit) pada $(Get-Date -Format o)._"

    $markdown = ($lines -join [Environment]::NewLine)
    $result = [pscustomobject]@{ MarkdownPath = ''; HtmlPath = ''; Summary = $summary }

    if ($Format -in @('Markdown', 'Both')) {
        $markdownPath = Join-Path $exportDir ('report_' + (Get-Date -Format 'yyyyMMdd_HHmmss') + '.md')
        [System.IO.File]::WriteAllText($markdownPath, $markdown, $script:WfUtf8)
        $result.MarkdownPath = $markdownPath
    }

    if ($Format -in @('Html', 'Both')) {
        $htmlPath = Join-Path $exportDir ('report_' + (Get-Date -Format 'yyyyMMdd_HHmmss') + '.html')
        $style = 'body{font-family:Segoe UI,Arial,sans-serif;margin:2rem auto;max-width:1000px;color:#1f2328;line-height:1.55}' +
                 'pre{background:#f6f8fa;padding:12px;border-radius:6px;overflow-x:auto;white-space:pre-wrap}' +
                 'h1{border-bottom:2px solid #d0d7de;padding-bottom:.3em}'
        $html = @(
            '<!DOCTYPE html>',
            '<html lang="id"><head><meta charset="utf-8">',
            "<title>Laporan Forensik - $(ConvertTo-OFHtmlText $Case.caseId)</title>",
            "<style>$style</style></head><body>",
            "<h1>Laporan Forensik Digital</h1>",
            "<p><strong>$(ConvertTo-OFHtmlText $Case.name)</strong> - $(ConvertTo-OFHtmlText $Case.caseId)</p>",
            '<pre>',
            (ConvertTo-OFHtmlText $markdown),
            '</pre>',
            '</body></html>'
        ) -join [Environment]::NewLine
        [System.IO.File]::WriteAllText($htmlPath, $html, $script:WfUtf8)
        $result.HtmlPath = $htmlPath
    }

    Add-OFCustody -Case $Case -Action 'report_exported' -Detail "Format: $Format"
    Save-OFCase -Case $Case | Out-Null

    Write-Host "[+] Report kasus diekspor:" -ForegroundColor Green
    if ($result.MarkdownPath) { Write-Host "    Markdown: $($result.MarkdownPath)" -ForegroundColor Cyan }
    if ($result.HtmlPath) { Write-Host "    HTML    : $($result.HtmlPath)" -ForegroundColor Cyan }
    return $result
}

function Invoke-OFWorkflow {
    [CmdletBinding()]
    [OutputType([psobject])]
    param(
        [Parameter(Mandatory)][string[]]$Path,
        [string]$CaseName = '',
        [string]$Examiner = $env:USERNAME,
        [string]$Description = '',
        [string]$Reference = '',
        [ValidateSet('public', 'internal', 'confidential', 'restricted')][string]$Classification = 'internal',
        $Case,
        [switch]$CopyEvidence,
        [switch]$AllTools,
        [switch]$UseAi,
        [switch]$NoReport,
        [switch]$Quiet
    )

    Initialize-OFWorkspace

    if (-not $Case) {
        if ([string]::IsNullOrWhiteSpace($CaseName)) {
            $CaseName = 'Pemeriksaan ' + (Split-Path -Leaf $Path[0])
        }
        $Case = New-OFCase -Name $CaseName -Examiner $Examiner -Description $Description `
            -Reference $Reference -Classification $Classification
    }

    Write-Host ''
    Write-Host '=============== ALUR KERJA OPENFORENSIC ===============' -ForegroundColor Magenta
    Write-Host " Kasus  : $($Case.caseId)" -ForegroundColor Magenta
    Write-Host " Bukti  : $($Path.Count) file" -ForegroundColor Magenta
    Write-Host '=======================================================' -ForegroundColor Magenta

    $analysisResults = New-Object System.Collections.ArrayList

    foreach ($item in $Path) {
        if (-not (Test-Path -LiteralPath $item)) {
            Write-Host "[-] Dilewati (tidak ditemukan): $item" -ForegroundColor Red
            continue
        }
        $evidence = Add-OFCaseEvidence -Case $Case -Path $item -Copy:$CopyEvidence
        if (-not $evidence) { continue }
        $result = Invoke-OFEvidenceAnalysis -Case $Case -EvidenceId $evidence.id -AllTools:$AllTools -Quiet:$Quiet
        [void]$analysisResults.Add($result)
    }

    if ($UseAi) {
        if (Get-Command -Name 'Invoke-OFAiCaseAnalysis' -ErrorAction SilentlyContinue) {
            Write-Host ''
            Write-Host '[*] Menjalankan tahap analisis AI...' -ForegroundColor Yellow
            Invoke-OFAiCaseAnalysis -Case $Case | Out-Null
        } else {
            Write-Warning 'Modul AI tidak tersedia; tahap AI dilewati.'
        }
    }

    $report = $null
    if (-not $NoReport) {
        $report = Export-OFCaseReport -Case $Case -Format Both -IncludeArtifacts
    }

    $summary = Get-OFCaseSummary -Case $Case
    Write-Host ''
    Write-Host '===================== RINGKASAN =======================' -ForegroundColor Magenta
    Write-Host " Verdict  : $($summary.Verdict)" -ForegroundColor Magenta
    Write-Host " Bukti    : $($summary.EvidenceCount) | Tool run: $($summary.ToolRuns)" -ForegroundColor Magenta
    Write-Host " Artefak  : $($summary.ArtifactCount) | Findings: $($summary.FindingCount)" -ForegroundColor Magenta
    Write-Host " Severity : critical $($summary.Critical), high $($summary.High), medium $($summary.Medium)" -ForegroundColor Magenta
    Write-Host '=======================================================' -ForegroundColor Magenta

    return [pscustomobject]@{
        Case     = $Case
        Summary  = $summary
        Analyses = @($analysisResults)
        Report   = $report
    }
}

Export-ModuleMember -Function @(
    'Get-OFCaseRoot', 'New-OFCase', 'Save-OFCase', 'Get-OFCase', 'Get-OFCaseList',
    'Add-OFCaseEvidence', 'Get-OFCaseEvidence', 'Add-OFCaseFinding', 'Get-OFCaseFinding',
    'Add-OFCaseTimelineEntry', 'Find-OFArtifact', 'Get-OFApplicableTool',
    'Invoke-OFEvidenceAnalysis', 'Get-OFCaseSummary', 'Export-OFCaseReport', 'Invoke-OFWorkflow'
)
