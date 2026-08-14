#Requires -Version 5.1
<#
    OpenForensic.Timeline - normalisasi timeline lintas sumber, pemetaan MITRE ATT&CK,
    dan ekspor IOC.

    Tujuan modul ini: mengubah kumpulan output tool menjadi satu urutan kejadian
    (timestamp | source | actor | action | target) sehingga pemeriksa maupun AI
    melihat rangkaian peristiwa, bukan potongan output yang terpisah-pisah.

    Dimuat sebagai NestedModule oleh OpenForensic.psd1.
#>

Set-StrictMode -Version Latest

$script:TlUtf8 = New-Object System.Text.UTF8Encoding($false)
$script:TlMaxAiEvents = 400
$script:TlSeverityRank = @{ info = 0; low = 1; medium = 2; high = 3; critical = 4 }

# Kolom waktu yang dikenal dari tool-tool umum.
$script:TlTimeColumns = @(
    'Timestamp', 'timestamp', 'datetime', 'DateTime', 'Date', 'date',
    'TimeCreated', 'time_created', 'event_time', 'EventTime', 'utc_time',
    'Created0x10', 'LastModified0x10', 'LastRecordChange0x10', 'LastAccess0x10',
    'First Seen', 'FirstSeen', '_time', 'AccessTime', 'WriteTime'
)

# Pemetaan detektor artefak / kata kunci -> teknik MITRE ATT&CK.
$script:TlMitreMap = @(
    @{ Pattern = 'registry_autorun|run key|currentversion\\\\run';   Id = 'T1547.001'; Name = 'Boot or Logon Autostart Execution: Registry Run Keys'; Tactic = 'Persistence' },
    @{ Pattern = 'service_create|sc\\s+create|new-service';            Id = 'T1543.003'; Name = 'Create or Modify System Process: Windows Service'; Tactic = 'Persistence' },
    @{ Pattern = 'scheduled_task|schtasks|register-scheduledtask';    Id = 'T1053.005'; Name = 'Scheduled Task/Job: Scheduled Task'; Tactic = 'Execution' },
    @{ Pattern = 'powershell_encoded|-enc |encodedcommand';           Id = 'T1027.010'; Name = 'Obfuscated Files or Information: Command Obfuscation'; Tactic = 'Defense Evasion' },
    @{ Pattern = 'powershell_download|downloadstring|invoke-webrequest'; Id = 'T1105'; Name = 'Ingress Tool Transfer'; Tactic = 'Command and Control' },
    @{ Pattern = 'lolbin|rundll32|regsvr32|mshta|certutil';           Id = 'T1218';     Name = 'System Binary Proxy Execution'; Tactic = 'Defense Evasion' },
    @{ Pattern = 'vba_autoexec|autoopen|document_open';               Id = 'T1204.002'; Name = 'User Execution: Malicious File'; Tactic = 'Execution' },
    @{ Pattern = 'vba_suspicious|shell\\(|createobject';               Id = 'T1059.005'; Name = 'Command and Scripting Interpreter: Visual Basic'; Tactic = 'Execution' },
    @{ Pattern = 'pdf_active_content|/javascript|/openaction';        Id = 'T1204.002'; Name = 'User Execution: Malicious File'; Tactic = 'Execution' },
    @{ Pattern = 'embedded_pe|embedded executable';                   Id = 'T1027.009'; Name = 'Obfuscated Files or Information: Embedded Payloads'; Tactic = 'Defense Evasion' },
    @{ Pattern = 'base64_blob|base64 encoded';                        Id = 'T1132.001'; Name = 'Data Encoding: Standard Encoding'; Tactic = 'Command and Control' },
    @{ Pattern = 'private_key|aws_access_key|credential_pair';        Id = 'T1552.001'; Name = 'Unsecured Credentials: Credentials In Files'; Tactic = 'Credential Access' },
    @{ Pattern = 'ntlm_hash_line|sam dump|lsass';                     Id = 'T1003.001'; Name = 'OS Credential Dumping: LSASS Memory'; Tactic = 'Credential Access' },
    @{ Pattern = 'jwt|bearer token';                                  Id = 'T1550.001'; Name = 'Use Alternate Authentication Material: Application Access Token'; Tactic = 'Lateral Movement' },
    @{ Pattern = 'ransom_note_hint|your files have been encrypted';   Id = 'T1486';     Name = 'Data Encrypted for Impact'; Tactic = 'Impact' },
    @{ Pattern = 'offensive_tool|mimikatz|cobalt strike|meterpreter'; Id = 'T1588.002'; Name = 'Obtain Capabilities: Tool'; Tactic = 'Resource Development' },
    @{ Pattern = 'onion_address|tor2web';                             Id = 'T1090.003'; Name = 'Proxy: Multi-hop Proxy'; Tactic = 'Command and Control' },
    @{ Pattern = 'bitcoin_address|ethereum_address';                  Id = 'T1657';     Name = 'Financial Theft'; Tactic = 'Impact' },
    @{ Pattern = 'url|domain|ipv4|http request';                       Id = 'T1071.001'; Name = 'Application Layer Protocol: Web Protocols'; Tactic = 'Command and Control' },
    @{ Pattern = 'unc_path|net use|admin\\$';                          Id = 'T1021.002'; Name = 'Remote Services: SMB/Windows Admin Shares'; Tactic = 'Lateral Movement' },
    @{ Pattern = 'prompt_injection';                                  Id = 'AML.T0051'; Name = 'LLM Prompt Injection (MITRE ATLAS)'; Tactic = 'AI Attack Surface' }
)

# ---------------------------------------------------------------------------
# Helper privat
# ---------------------------------------------------------------------------

function Test-OFTlProperty {
    param($InputObject, [Parameter(Mandatory)][string]$Name)
    if ($null -eq $InputObject) { return $false }
    if ($InputObject -is [hashtable]) { return $InputObject.ContainsKey($Name) }
    return [bool]($InputObject.PSObject.Properties.Name -contains $Name)
}

function Set-OFTlProperty {
    param([Parameter(Mandatory)]$InputObject, [Parameter(Mandatory)][string]$Name, $Value)
    if (Test-OFTlProperty -InputObject $InputObject -Name $Name) {
        $InputObject.$Name = $Value
    } else {
        Add-Member -InputObject $InputObject -MemberType NoteProperty -Name $Name -Value $Value -Force
    }
}

function ConvertTo-OFTlTimestamp {
    param($Value)
    if ($null -eq $Value -or [string]::IsNullOrWhiteSpace([string]$Value)) { return $null }
    $text = ([string]$Value).Trim()
    $parsed = [datetime]::MinValue
    $styles = [System.Globalization.DateTimeStyles]::AdjustToUniversal -bor [System.Globalization.DateTimeStyles]::AssumeUniversal
    if ([datetime]::TryParse($text, [System.Globalization.CultureInfo]::InvariantCulture, $styles, [ref]$parsed)) {
        return $parsed.ToString('o')
    }
    if ([datetime]::TryParse($text, [ref]$parsed)) { return $parsed.ToUniversalTime().ToString('o') }
    return $null
}

function Get-OFTlSeverityRank {
    param([string]$Severity)
    if (-not $Severity) { return 0 }
    $key = $Severity.ToLowerInvariant()
    if ($script:TlSeverityRank.ContainsKey($key)) { return $script:TlSeverityRank[$key] }
    switch -Regex ($key) {
        'crit|emerg'      { return 4 }
        'high|sev1|alert' { return 3 }
        'med|warn'        { return 2 }
        'low|notice'      { return 1 }
        default           { return 0 }
    }
}

# ---------------------------------------------------------------------------
# Skema kejadian ternormalisasi
# ---------------------------------------------------------------------------

function New-OFTimelineEvent {
    <#
    .SYNOPSIS
        Membuat satu kejadian timeline dengan skema ternormalisasi.
    .DESCRIPTION
        Skema: timestamp | source | sourceType | actor | action | target | detail |
        severity | evidenceId | mitre. Semua sumber (EVTX, MFT, Hayabusa, Chainsaw,
        pcap, SQLite browser, tindakan pemeriksa) dipetakan ke bentuk yang sama.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][AllowNull()]$Timestamp,
        [Parameter(Mandatory)][string]$Source,
        [string]$SourceType = 'tool',
        [string]$Actor = '',
        [string]$Action = '',
        [string]$Target = '',
        [string]$Detail = '',
        [ValidateSet('info', 'low', 'medium', 'high', 'critical')][string]$Severity = 'info',
        [string]$EvidenceId = '',
        [string[]]$Mitre = @()
    )

    $iso = ConvertTo-OFTlTimestamp -Value $Timestamp
    return [pscustomobject]@{
        timestamp    = $iso
        rawTimestamp = if ($null -ne $Timestamp) { [string]$Timestamp } else { '' }
        source       = $Source
        sourceType   = $SourceType
        actor        = $Actor
        action       = $Action
        target       = $Target
        detail       = $Detail
        severity     = $Severity
        severityRank = Get-OFTlSeverityRank -Severity $Severity
        evidenceId   = $EvidenceId
        mitre        = @($Mitre)
    }
}

# ---------------------------------------------------------------------------
# Pemetaan MITRE ATT&CK
# ---------------------------------------------------------------------------

function Get-OFMitreTechnique {
    <#
    .SYNOPSIS
        Memetakan teks (nama detektor, judul temuan, nama rule) ke teknik MITRE ATT&CK.
    .DESCRIPTION
        Pemetaan berbasis kata kunci deterministik - bukan hasil tebakan AI - sehingga
        dapat diaudit dan direproduksi.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)][AllowEmptyString()][string]$Text)

    $result = New-Object System.Collections.ArrayList
    if ([string]::IsNullOrWhiteSpace($Text)) { return @() }
    $haystack = $Text.ToLowerInvariant()

    foreach ($entry in $script:TlMitreMap) {
        if ($haystack -match $entry.Pattern) {
            [void]$result.Add([pscustomobject]@{
                id     = $entry.Id
                name   = $entry.Name
                tactic = $entry.Tactic
            })
        }
    }

    # Teknik yang disebut eksplisit oleh tool (capa, Sigma/Hayabusa, Chainsaw).
    foreach ($match in [regex]::Matches($Text, 'T\\d{4}(\\.\\d{3})?')) {
        $id = $match.Value
        if (-not ($result | Where-Object { $_.id -eq $id })) {
            [void]$result.Add([pscustomobject]@{
                id     = $id
                name   = 'Teknik dilaporkan langsung oleh tool'
                tactic = 'tidak dipetakan'
            })
        }
    }

    return @($result | Sort-Object -Property id -Unique)
}

function Update-OFCaseMitre {
    <#
    .SYNOPSIS
        Menempelkan teknik MITRE ATT&CK pada setiap temuan dan merangkumnya di kasus.
    .DESCRIPTION
        Sumber pemetaan: nama detektor artefak, judul/kategori temuan, dan teknik yang
        disebut langsung pada log tool (capa, Hayabusa, Chainsaw).
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]$Case,
        [switch]$Quiet
    )

    $caseDir = $Case.caseDir
    $summary = @{}

    if (Test-OFTlProperty -InputObject $Case -Name 'findings') {
        foreach ($finding in @($Case.findings)) {
            $parts = New-Object System.Collections.ArrayList
            foreach ($field in @('title', 'category', 'indicator', 'description')) {
                if ((Test-OFTlProperty -InputObject $finding -Name $field) -and $finding.$field) {
                    [void]$parts.Add([string]$finding.$field)
                }
            }
            $techniques = Get-OFMitreTechnique -Text ($parts -join ' ')
            if (@($techniques).Count -gt 0) {
                Set-OFTlProperty -InputObject $finding -Name 'mitre' -Value @($techniques | ForEach-Object { $_.id })
                Set-OFTlProperty -InputObject $finding -Name 'mitreDetail' -Value @($techniques)
                foreach ($technique in $techniques) {
                    if (-not $summary.ContainsKey($technique.id)) {
                        $summary[$technique.id] = [pscustomobject]@{
                            id       = $technique.id
                            name     = $technique.name
                            tactic   = $technique.tactic
                            findings = New-Object System.Collections.ArrayList
                        }
                    }
                    [void]$summary[$technique.id].findings.Add($finding.id)
                }
            }
        }
    }

    # Teknik yang dilaporkan langsung oleh capa / Hayabusa / Chainsaw pada log.
    if ($caseDir -and (Test-Path -LiteralPath (Join-Path $caseDir 'logs'))) {
        $logFiles = @(Get-ChildItem -LiteralPath (Join-Path $caseDir 'logs') -Filter '*.log' -File -ErrorAction SilentlyContinue |
            Where-Object { $_.Name -match '_(capa|hayabusa|chainsaw|floss)_' })
        foreach ($logFile in $logFiles) {
            $content = Get-Content -LiteralPath $logFile.FullName -Raw -ErrorAction SilentlyContinue
            if (-not $content) { continue }
            foreach ($technique in (Get-OFMitreTechnique -Text $content)) {
                if (-not $summary.ContainsKey($technique.id)) {
                    $summary[$technique.id] = [pscustomobject]@{
                        id       = $technique.id
                        name     = $technique.name
                        tactic   = $technique.tactic
                        findings = New-Object System.Collections.ArrayList
                    }
                }
                [void]$summary[$technique.id].findings.Add("log:$($logFile.Name)")
            }
        }
    }

    $flat = @($summary.Values | ForEach-Object {
        [pscustomobject]@{
            id       = $_.id
            name     = $_.name
            tactic   = $_.tactic
            findings = @($_.findings | Select-Object -Unique)
        }
    } | Sort-Object -Property id)

    Set-OFTlProperty -InputObject $Case -Name 'mitre' -Value $flat
    Save-OFCase -Case $Case | Out-Null
    if (-not $Quiet) { Write-Host "    [mitre] $($flat.Count) teknik dipetakan" -ForegroundColor DarkGray }
    return $flat
}

# ---------------------------------------------------------------------------
# Impor timeline dari output tool
# ---------------------------------------------------------------------------

function Import-OFTimelineCsv {
    <#
    .SYNOPSIS
        Mengimpor CSV hasil Hayabusa / Chainsaw / MFTECmd / tool lain ke timeline kasus.
    .DESCRIPTION
        Kolom waktu dideteksi otomatis dari daftar nama kolom yang dikenal, sehingga
        satu fungsi dapat menerima berbagai format tanpa konfigurasi.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]$Case,
        [Parameter(Mandatory)][string]$Path,
        [ValidateSet('auto', 'hayabusa', 'chainsaw', 'mftecmd', 'evtx', 'generic')][string]$Source = 'auto',
        [string]$EvidenceId = '',
        [ValidateRange(1, 200000)][int]$MaxRows = 20000,
        [switch]$Quiet
    )

    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) { throw "Berkas CSV tidak ditemukan: $Path" }

    $rows = @(Import-Csv -LiteralPath $Path -ErrorAction Stop | Select-Object -First $MaxRows)
    if ($rows.Count -eq 0) {
        if (-not $Quiet) { Write-Host '    [timeline] CSV kosong.' -ForegroundColor DarkGray }
        return @()
    }

    $columns = @($rows[0].PSObject.Properties.Name)
    $detectedSource = $Source
    if ($Source -eq 'auto') {
        $joined = ($columns -join ' ').ToLowerInvariant()
        $detectedSource = switch -Regex ($joined) {
            'ruletitle|rulepath|eventid.*channel.*level' { 'hayabusa' }
            'detections|group|kind.*document'            { 'chainsaw' }
            'created0x10|parentpath|insize'              { 'mftecmd' }
            'eventrecordid|providername'                 { 'evtx' }
            default                                      { 'generic' }
        }
    }

    $timeColumn = $null
    foreach ($candidate in $script:TlTimeColumns) {
        if ($columns -contains $candidate) { $timeColumn = $candidate; break }
    }
    if (-not $timeColumn) {
        $timeColumn = $columns | Where-Object { $_ -match '(?i)time|date' } | Select-Object -First 1
    }
    if (-not $timeColumn) { throw "Tidak menemukan kolom waktu pada $Path. Kolom tersedia: $($columns -join ', ')" }

    $severityColumn = $columns | Where-Object { $_ -match '(?i)^level$|severity|risk' } | Select-Object -First 1
    $actorColumn = $columns | Where-Object { $_ -match '(?i)computer|host|user|account|source ?ip' } | Select-Object -First 1
    $actionColumn = $columns | Where-Object { $_ -match '(?i)ruletitle|rule|detection|eventid|name|type' } | Select-Object -First 1
    $targetColumn = $columns | Where-Object { $_ -match '(?i)path|target|file|process|destination' } | Select-Object -First 1
    $detailColumn = $columns | Where-Object { $_ -match '(?i)details|message|payload|extrafield|record' } | Select-Object -First 1

    $events = New-Object System.Collections.ArrayList
    foreach ($row in $rows) {
        $severityText = if ($severityColumn) { [string]$row.$severityColumn } else { 'info' }
        $rank = Get-OFTlSeverityRank -Severity $severityText
        $severity = switch ($rank) {
            4 { 'critical' } 3 { 'high' } 2 { 'medium' } 1 { 'low' } default { 'info' }
        }
        $actionText = if ($actionColumn) { [string]$row.$actionColumn } else { $detectedSource }
        $detailText = if ($detailColumn) { [string]$row.$detailColumn } else { '' }
        $mitre = @(Get-OFMitreTechnique -Text ("$actionText $detailText") | ForEach-Object { $_.id })

        $event = New-OFTimelineEvent -Timestamp $row.$timeColumn -Source $detectedSource -SourceType 'tool' `
            -Actor $(if ($actorColumn) { [string]$row.$actorColumn } else { '' }) `
            -Action $actionText `
            -Target $(if ($targetColumn) { [string]$row.$targetColumn } else { '' }) `
            -Detail $(if ($detailText.Length -gt 500) { $detailText.Substring(0, 500) + '...' } else { $detailText }) `
            -Severity $severity -EvidenceId $EvidenceId -Mitre $mitre
        if ($event.timestamp) { [void]$events.Add($event) }
    }

    $existing = if (Test-OFTlProperty -InputObject $Case -Name 'normalizedTimeline') { @($Case.normalizedTimeline) } else { @() }
    Set-OFTlProperty -InputObject $Case -Name 'normalizedTimeline' -Value @($existing + @($events))
    Save-OFCase -Case $Case | Out-Null

    if (-not $Quiet) {
        Write-Host "    [timeline] $($events.Count) kejadian diimpor dari $detectedSource (kolom waktu: $timeColumn)" -ForegroundColor DarkGray
    }
    return @($events)
}

function Import-OFTimelineFromCase {
    <#
    .SYNOPSIS
        Membangun kejadian timeline dari state kasus itu sendiri.
    .DESCRIPTION
        Menghasilkan tiga lapis kejadian:
          - bukti: waktu modifikasi berkas dan waktu bukti didaftarkan
          - pemeriksaan: setiap eksekusi tool (tindakan pemeriksa, untuk audit)
          - temuan: waktu temuan dibuat, lengkap dengan severity dan MITRE
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]$Case,
        [switch]$IncludeExaminerActions,
        [switch]$Quiet
    )

    $events = New-Object System.Collections.ArrayList

    if (Test-OFTlProperty -InputObject $Case -Name 'evidence') {
        foreach ($evidence in @($Case.evidence)) {
            if ((Test-OFTlProperty -InputObject $evidence -Name 'modifiedAt') -and $evidence.modifiedAt) {
                [void]$events.Add((New-OFTimelineEvent -Timestamp $evidence.modifiedAt -Source 'filesystem' -SourceType 'evidence' `
                    -Actor '' -Action 'Berkas terakhir dimodifikasi' -Target $evidence.name `
                    -Detail "kind=$($evidence.kind) size=$($evidence.size) sha256=$($evidence.sha256)" `
                    -Severity 'info' -EvidenceId $evidence.id))
            }
            if ((Test-OFTlProperty -InputObject $evidence -Name 'addedAt') -and $evidence.addedAt) {
                [void]$events.Add((New-OFTimelineEvent -Timestamp $evidence.addedAt -Source 'openforensic' -SourceType 'custody' `
                    -Actor $(if (Test-OFTlProperty -InputObject $evidence -Name 'addedBy') { [string]$evidence.addedBy } else { '' }) `
                    -Action 'Bukti didaftarkan ke kasus' -Target $evidence.name `
                    -Detail "sha256=$($evidence.sha256)" -Severity 'info' -EvidenceId $evidence.id))
            }
            if ($IncludeExaminerActions -and (Test-OFTlProperty -InputObject $evidence -Name 'analyses')) {
                foreach ($analysis in @($evidence.analyses)) {
                    if (-not $analysis.executedAt) { continue }
                    [void]$events.Add((New-OFTimelineEvent -Timestamp $analysis.executedAt -Source 'openforensic' -SourceType 'examiner' `
                        -Actor $env:USERNAME -Action "Menjalankan tool $($analysis.toolId)" -Target $evidence.name `
                        -Detail "exit=$($analysis.exitCode) durasi=$($analysis.durationSeconds)s log=$($analysis.logPath)" `
                        -Severity 'info' -EvidenceId $evidence.id))
                }
            }
        }
    }

    if (Test-OFTlProperty -InputObject $Case -Name 'findings') {
        foreach ($finding in @($Case.findings)) {
            if (-not $finding.createdAt) { continue }
            $mitre = if ((Test-OFTlProperty -InputObject $finding -Name 'mitre') -and $finding.mitre) { @($finding.mitre) } else { @() }
            [void]$events.Add((New-OFTimelineEvent -Timestamp $finding.createdAt -Source 'openforensic' -SourceType 'finding' `
                -Actor $(if (Test-OFTlProperty -InputObject $finding -Name 'createdBy') { [string]$finding.createdBy } else { '' }) `
                -Action "Temuan $($finding.id): $($finding.title)" -Target $(if ($finding.evidenceId) { [string]$finding.evidenceId } else { '' }) `
                -Detail $(if ($finding.indicator) { [string]$finding.indicator } else { '' }) `
                -Severity $(if ($finding.severity) { [string]$finding.severity } else { 'info' }) `
                -EvidenceId $(if ($finding.evidenceId) { [string]$finding.evidenceId } else { '' }) -Mitre $mitre))
        }
    }

    $existing = if (Test-OFTlProperty -InputObject $Case -Name 'normalizedTimeline') { @($Case.normalizedTimeline) } else { @() }
    Set-OFTlProperty -InputObject $Case -Name 'normalizedTimeline' -Value @($existing + @($events))
    Save-OFCase -Case $Case | Out-Null
    if (-not $Quiet) { Write-Host "    [timeline] $($events.Count) kejadian dibangun dari state kasus" -ForegroundColor DarkGray }
    return @($events)
}

function Get-OFTimeline {
    <#
    .SYNOPSIS
        Mengambil timeline ternormalisasi kasus, terurut waktu, dengan filter opsional.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]$Case,
        [datetime]$From,
        [datetime]$To,
        [string]$Source,
        [ValidateSet('info', 'low', 'medium', 'high', 'critical')][string]$MinSeverity = 'info',
        [ValidateRange(1, 100000)][int]$Limit = 5000,
        [switch]$Deduplicate
    )

    if (-not (Test-OFTlProperty -InputObject $Case -Name 'normalizedTimeline')) { return @() }
    $events = @($Case.normalizedTimeline | Where-Object { $_.timestamp })
    $minRank = Get-OFTlSeverityRank -Severity $MinSeverity

    if ($PSBoundParameters.ContainsKey('From')) {
        $events = @($events | Where-Object { [datetime]::Parse($_.timestamp) -ge $From })
    }
    if ($PSBoundParameters.ContainsKey('To')) {
        $events = @($events | Where-Object { [datetime]::Parse($_.timestamp) -le $To })
    }
    if ($Source) {
        $events = @($events | Where-Object { $_.source -eq $Source -or $_.sourceType -eq $Source })
    }
    if ($minRank -gt 0) {
        $events = @($events | Where-Object { (Get-OFTlSeverityRank -Severity $_.severity) -ge $minRank })
    }
    if ($Deduplicate) {
        $seen = @{}
        $unique = New-Object System.Collections.ArrayList
        foreach ($event in $events) {
            $key = '{0}|{1}|{2}|{3}' -f $event.timestamp, $event.source, $event.action, $event.target
            if ($seen.ContainsKey($key)) { continue }
            $seen[$key] = $true
            [void]$unique.Add($event)
        }
        $events = @($unique)
    }

    return @($events | Sort-Object -Property timestamp | Select-Object -First $Limit)
}

function Export-OFTimeline {
    <#
    .SYNOPSIS
        Mengekspor timeline ternormalisasi ke CSV, JSON, atau Markdown.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]$Case,
        [ValidateSet('Csv', 'Json', 'Markdown')][string]$Format = 'Csv',
        [ValidateSet('info', 'low', 'medium', 'high', 'critical')][string]$MinSeverity = 'info',
        [string]$OutputPath,
        [switch]$Quiet
    )

    $events = Get-OFTimeline -Case $Case -MinSeverity $MinSeverity -Deduplicate
    if (@($events).Count -eq 0) { throw 'Timeline kosong. Jalankan Import-OFTimelineFromCase atau Import-OFTimelineCsv lebih dulu.' }

    $exportDir = Join-Path $Case.caseDir 'exports'
    if (-not (Test-Path -LiteralPath $exportDir)) { New-Item -ItemType Directory -Path $exportDir -Force | Out-Null }
    $stamp = Get-Date -Format 'yyyyMMdd_HHmmss'
    $extension = switch ($Format) { 'Csv' { 'csv' } 'Json' { 'json' } 'Markdown' { 'md' } }
    if (-not $OutputPath) { $OutputPath = Join-Path $exportDir "timeline_$stamp.$extension" }

    switch ($Format) {
        'Csv' {
            $events |
                Select-Object timestamp, source, sourceType, actor, action, target, severity, evidenceId,
                    @{ Name = 'mitre'; Expression = { (@($_.mitre) -join ';') } }, detail |
                Export-Csv -LiteralPath $OutputPath -NoTypeInformation -Encoding UTF8
        }
        'Json' {
            [System.IO.File]::WriteAllText($OutputPath, (@($events) | ConvertTo-Json -Depth 6), $script:TlUtf8)
        }
        'Markdown' {
            $lines = New-Object System.Collections.ArrayList
            [void]$lines.Add("# Timeline - $($Case.caseId)")
            [void]$lines.Add('')
            [void]$lines.Add('| Waktu (UTC) | Sumber | Aktor | Aksi | Target | Severity | MITRE |')
            [void]$lines.Add('| --- | --- | --- | --- | --- | --- | --- |')
            foreach ($event in $events) {
                [void]$lines.Add(('| {0} | {1} | {2} | {3} | {4} | {5} | {6} |' -f
                    $event.timestamp, $event.source, $event.actor,
                    ($event.action -replace '\\|', '/'), ($event.target -replace '\\|', '/'),
                    $event.severity, (@($event.mitre) -join ' ')))
            }
            [System.IO.File]::WriteAllText($OutputPath, (($lines -join "`r`n") + "`r`n"), $script:TlUtf8)
        }
    }

    if (-not $Quiet) { Write-Host "    [export] timeline $Format -> $OutputPath" -ForegroundColor Green }
    return [pscustomobject]@{ Path = $OutputPath; Format = $Format; EventCount = @($events).Count }
}

function Get-OFTimelineContext {
    <#
    .SYNOPSIS
        Menyusun ringkasan timeline sebagai teks untuk konteks AI.
    .DESCRIPTION
        Dipakai oleh lapisan AI agar model melihat urutan kejadian, bukan output tool
        yang terpisah. Kejadian severity tinggi diprioritaskan bila jumlahnya dibatasi.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]$Case,
        [ValidateRange(10, 2000)][int]$MaxEvents = 200
    )

    $events = @(Get-OFTimeline -Case $Case -Deduplicate)
    if ($events.Count -eq 0) { return '' }
    if ($events.Count -gt $MaxEvents) {
        $priority = @($events | Where-Object { $_.severityRank -ge 2 } | Select-Object -First $MaxEvents)
        $filler = @($events | Where-Object { $_.severityRank -lt 2 } | Select-Object -First ([math]::Max(0, $MaxEvents - $priority.Count)))
        $events = @(($priority + $filler) | Sort-Object -Property timestamp)
    }

    $lines = New-Object System.Collections.ArrayList
    [void]$lines.Add("TIMELINE TERNORMALISASI ($($events.Count) kejadian, urut waktu UTC)")
    foreach ($event in $events) {
        $mitre = if (@($event.mitre).Count -gt 0) { ' [' + (@($event.mitre) -join ',') + ']' } else { '' }
        [void]$lines.Add(('{0} | {1} | {2} | {3} | {4} | {5}{6}' -f
            $event.timestamp, $event.source, $event.severity,
            $(if ($event.actor) { $event.actor } else { '-' }),
            $event.action, $(if ($event.target) { $event.target } else { '-' }), $mitre))
    }
    return ($lines -join "`n")
}

function Get-OFMitreSummary {
    <#
    .SYNOPSIS
        Ringkasan teknik MITRE ATT&CK pada kasus, dikelompokkan per taktik.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)]$Case)

    if (-not (Test-OFTlProperty -InputObject $Case -Name 'mitre')) { return @() }
    return @($Case.mitre | Group-Object -Property tactic | ForEach-Object {
        [pscustomobject]@{
            tactic     = $_.Name
            techniques = @($_.Group | ForEach-Object { '{0} ({1})' -f $_.id, $_.name })
            count      = $_.Count
        }
    } | Sort-Object -Property tactic)
}

# ---------------------------------------------------------------------------
# Ekspor IOC
# ---------------------------------------------------------------------------

function Export-OFCaseIoc {
    <#
    .SYNOPSIS
        Mengekspor IOC dari artefak kasus ke CSV, JSON, STIX 2.1, atau MISP.
    .DESCRIPTION
        Hanya artefak yang bertipe indikator jaringan/berkas yang diekspor; artefak
        seperti flag CTF dan indikasi prompt injection sengaja tidak diikutkan.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]$Case,
        [ValidateSet('Csv', 'Json', 'Stix', 'Misp')][string]$Format = 'Csv',
        [string]$OutputPath,
        [switch]$Quiet
    )

    $iocTypes = @{
        url            = 'url'
        domain         = 'domain-name'
        ipv4           = 'ipv4-addr'
        email          = 'email-addr'
        onion_address  = 'url'
        md5_hash       = 'file:hashes.MD5'
        sha256_hash    = 'file:hashes.SHA-256'
        bitcoin_address = 'cryptocurrency-wallet'
        ethereum_address = 'cryptocurrency-wallet'
    }

    $artifacts = if (Test-OFTlProperty -InputObject $Case -Name 'artifacts') { @($Case.artifacts) } else { @() }
    $iocs = New-Object System.Collections.ArrayList
    foreach ($artifact in $artifacts) {
        $type = if (Test-OFTlProperty -InputObject $artifact -Name 'type') { [string]$artifact.type } else { '' }
        if (-not $iocTypes.ContainsKey($type)) { continue }
        $value = if (Test-OFTlProperty -InputObject $artifact -Name 'value') { [string]$artifact.value } else { '' }
        if (-not $value) { continue }
        [void]$iocs.Add([pscustomobject]@{
            type       = $type
            stixType   = $iocTypes[$type]
            value      = $value
            evidenceId = if (Test-OFTlProperty -InputObject $artifact -Name 'evidenceId') { [string]$artifact.evidenceId } else { '' }
            toolId     = if (Test-OFTlProperty -InputObject $artifact -Name 'toolId') { [string]$artifact.toolId } else { '' }
            severity   = if (Test-OFTlProperty -InputObject $artifact -Name 'severity') { [string]$artifact.severity } else { 'info' }
            firstSeen  = if (Test-OFTlProperty -InputObject $artifact -Name 'detectedAt') { [string]$artifact.detectedAt } else { '' }
        })
    }

    if ($iocs.Count -eq 0) { throw 'Tidak ada IOC yang dapat diekspor dari artefak kasus.' }

    $exportDir = Join-Path $Case.caseDir 'exports'
    if (-not (Test-Path -LiteralPath $exportDir)) { New-Item -ItemType Directory -Path $exportDir -Force | Out-Null }
    $stamp = Get-Date -Format 'yyyyMMdd_HHmmss'
    $extension = if ($Format -eq 'Csv') { 'csv' } else { 'json' }
    if (-not $OutputPath) { $OutputPath = Join-Path $exportDir "ioc_$stamp.$extension" }

    switch ($Format) {
        'Csv' {
            $iocs | Export-Csv -LiteralPath $OutputPath -NoTypeInformation -Encoding UTF8
        }
        'Json' {
            [System.IO.File]::WriteAllText($OutputPath, (@($iocs) | ConvertTo-Json -Depth 5), $script:TlUtf8)
        }
        'Stix' {
            $objects = New-Object System.Collections.ArrayList
            foreach ($ioc in $iocs) {
                $pattern = switch ($ioc.stixType) {
                    'url'                    { "[url:value = '$($ioc.value)']" }
                    'domain-name'            { "[domain-name:value = '$($ioc.value)']" }
                    'ipv4-addr'              { "[ipv4-addr:value = '$($ioc.value)']" }
                    'email-addr'             { "[email-addr:value = '$($ioc.value)']" }
                    'file:hashes.MD5'        { "[file:hashes.MD5 = '$($ioc.value)']" }
                    'file:hashes.SHA-256'    { "[file:hashes.'SHA-256' = '$($ioc.value)']" }
                    default                  { "[x-openforensic:value = '$($ioc.value)']" }
                }
                [void]$objects.Add([ordered]@{
                    type            = 'indicator'
                    spec_version    = '2.1'
                    id              = 'indicator--' + [Guid]::NewGuid().ToString()
                    created         = (Get-Date).ToUniversalTime().ToString('o')
                    modified        = (Get-Date).ToUniversalTime().ToString('o')
                    name            = "$($ioc.type): $($ioc.value)"
                    description     = "Diekstrak OpenForensic dari $($ioc.evidenceId) via $($ioc.toolId)"
                    indicator_types = @('anomalous-activity')
                    pattern         = $pattern
                    pattern_type    = 'stix'
                    valid_from      = (Get-Date).ToUniversalTime().ToString('o')
                    labels          = @("severity:$($ioc.severity)", "case:$($Case.caseId)")
                })
            }
            $bundle = [ordered]@{
                type    = 'bundle'
                id      = 'bundle--' + [Guid]::NewGuid().ToString()
                objects = @($objects)
            }
            [System.IO.File]::WriteAllText($OutputPath, ($bundle | ConvertTo-Json -Depth 8), $script:TlUtf8)
        }
        'Misp' {
            $attributes = New-Object System.Collections.ArrayList
            foreach ($ioc in $iocs) {
                $mispType = switch ($ioc.type) {
                    'url'              { 'url' }
                    'domain'           { 'domain' }
                    'ipv4'             { 'ip-dst' }
                    'email'            { 'email-src' }
                    'onion_address'    { 'url' }
                    'md5_hash'         { 'md5' }
                    'sha256_hash'      { 'sha256' }
                    default            { 'text' }
                }
                [void]$attributes.Add([ordered]@{
                    type     = $mispType
                    value    = $ioc.value
                    category = if ($mispType -in @('md5', 'sha256')) { 'Payload delivery' } else { 'Network activity' }
                    comment  = "OpenForensic $($Case.caseId) / $($ioc.evidenceId) / $($ioc.toolId)"
                    to_ids   = ($ioc.severity -in @('high', 'critical'))
                })
            }
            $event = [ordered]@{
                Event = [ordered]@{
                    info           = "OpenForensic - $($Case.name) ($($Case.caseId))"
                    date           = (Get-Date -Format 'yyyy-MM-dd')
                    threat_level_id = '2'
                    analysis       = '1'
                    distribution   = '0'
                    Attribute      = @($attributes)
                }
            }
            [System.IO.File]::WriteAllText($OutputPath, ($event | ConvertTo-Json -Depth 8), $script:TlUtf8)
        }
    }

    if (-not $Quiet) { Write-Host "    [export] $($iocs.Count) IOC $Format -> $OutputPath" -ForegroundColor Green }
    return [pscustomobject]@{ Path = $OutputPath; Format = $Format; IocCount = $iocs.Count }
}

function Invoke-OFTimelineWorkflow {
    <#
    .SYNOPSIS
        Membangun timeline lengkap: state kasus + CSV tool + pemetaan MITRE.
    .DESCRIPTION
        Mencari otomatis CSV keluaran tool di folder artifacts kasus (Hayabusa, Chainsaw,
        MFTECmd) lalu menormalkannya ke satu timeline.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]$Case,
        [switch]$IncludeExaminerActions,
        [switch]$Quiet
    )

    Set-OFTlProperty -InputObject $Case -Name 'normalizedTimeline' -Value @()
    Import-OFTimelineFromCase -Case $Case -IncludeExaminerActions:$IncludeExaminerActions -Quiet:$Quiet | Out-Null

    $artifactDir = Join-Path $Case.caseDir 'artifacts'
    if (Test-Path -LiteralPath $artifactDir) {
        foreach ($csv in @(Get-ChildItem -LiteralPath $artifactDir -Filter '*.csv' -File -Recurse -ErrorAction SilentlyContinue)) {
            try {
                Import-OFTimelineCsv -Case $Case -Path $csv.FullName -Source auto -Quiet:$Quiet | Out-Null
            } catch {
                if (-not $Quiet) { Write-Host "    [timeline] lewati $($csv.Name): $($_.Exception.Message)" -ForegroundColor DarkYellow }
            }
        }
    }

    Update-OFCaseMitre -Case $Case -Quiet:$Quiet | Out-Null
    $events = @(Get-OFTimeline -Case $Case -Deduplicate)
    if (-not $Quiet) { Write-Host "    [timeline] total $($events.Count) kejadian ternormalisasi" -ForegroundColor Green }
    return $events
}

Export-ModuleMember -Function @(
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
    'Invoke-OFTimelineWorkflow'
)
