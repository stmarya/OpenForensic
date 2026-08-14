#Requires -Version 5.1
<#
    Pester 5 - timeline ternormalisasi, pemetaan MITRE, dan ekspor IOC.
#>

BeforeAll {
    Import-Module (Join-Path (Split-Path -Parent $PSScriptRoot) 'OpenForensic.psd1') -Force -DisableNameChecking

    function New-TimelineTestCase {
        $dir = Join-Path ([System.IO.Path]::GetTempPath()) ('of_tl_' + [Guid]::NewGuid().ToString('N').Substring(0, 8))
        New-Item -ItemType Directory -Path (Join-Path $dir 'exports') -Force | Out-Null
        return [pscustomobject]@{
            caseId             = 'CASE-TEST-TL'
            name               = 'Kasus Timeline'
            caseDir            = $dir
            artifacts          = @()
            findings           = @()
            evidence           = @()
            normalizedTimeline = @()
        }
    }
}

Describe 'New-OFTimelineEvent' {
    It 'menormalkan timestamp ke ISO-8601' {
        $event = New-OFTimelineEvent -Timestamp '2026-08-15 03:04:05' -Source 'hayabusa' -Action 'Suspicious PowerShell'
        $event.timestamp | Should -Not -BeNullOrEmpty
        [datetime]::Parse($event.timestamp).Year | Should -Be 2026
    }

    It 'menghasilkan timestamp null untuk nilai yang tidak dapat diparse' {
        (New-OFTimelineEvent -Timestamp 'bukan-tanggal' -Source 'generic').timestamp | Should -BeNullOrEmpty
    }

    It 'memetakan severity ke severityRank' {
        (New-OFTimelineEvent -Timestamp '2026-01-01' -Source 'x' -Severity 'critical').severityRank | Should -Be 4
        (New-OFTimelineEvent -Timestamp '2026-01-01' -Source 'x' -Severity 'info').severityRank | Should -Be 0
    }
}

Describe 'Get-OFMitreTechnique' {
    It 'memetakan scheduled task ke T1053.005' {
        $techniques = Get-OFMitreTechnique -Text 'schtasks /create /tn evil'
        @($techniques | Where-Object { $_.id -eq 'T1053.005' }).Count | Should -Be 1
    }

    It 'mengambil teknik yang disebut langsung oleh tool' {
        $techniques = Get-OFMitreTechnique -Text 'capa ATT&CK: Defense Evasion::Obfuscated Files T1027'
        @($techniques | Where-Object { $_.id -eq 'T1027' }).Count | Should -Be 1
    }

    It 'mengembalikan array kosong untuk teks kosong' {
        @(Get-OFMitreTechnique -Text '').Count | Should -Be 0
    }

    It 'memetakan prompt injection ke MITRE ATLAS' {
        @(Get-OFMitreTechnique -Text 'prompt_injection ditemukan' | Where-Object { $_.id -eq 'AML.T0051' }).Count | Should -Be 1
    }
}

Describe 'Get-OFTimeline' {
    It 'mengurutkan, memfilter severity, dan menghapus duplikat' {
        $case = New-TimelineTestCase
        try {
            $case.normalizedTimeline = @(
                (New-OFTimelineEvent -Timestamp '2026-08-15T10:00:00Z' -Source 'a' -Action 'kedua' -Severity 'high'),
                (New-OFTimelineEvent -Timestamp '2026-08-15T09:00:00Z' -Source 'a' -Action 'pertama' -Severity 'info'),
                (New-OFTimelineEvent -Timestamp '2026-08-15T10:00:00Z' -Source 'a' -Action 'kedua' -Severity 'high')
            )

            $all = @(Get-OFTimeline -Case $case -Deduplicate)
            $all.Count | Should -Be 2
            $all[0].action | Should -Be 'pertama'

            @(Get-OFTimeline -Case $case -MinSeverity 'high' -Deduplicate).Count | Should -Be 1
        } finally {
            Remove-Item -LiteralPath $case.caseDir -Recurse -Force -ErrorAction SilentlyContinue
        }
    }
}

Describe 'Import-OFTimelineCsv' {
    It 'mendeteksi kolom waktu secara otomatis' {
        $case = New-TimelineTestCase
        $csv = Join-Path $case.caseDir 'hayabusa.csv'
        try {
            @(
                [pscustomobject]@{ Timestamp = '2026-08-15T08:00:00Z'; Computer = 'WS01'; RuleTitle = 'Suspicious Service Creation'; Level = 'high'; Details = 'sc create evil' },
                [pscustomobject]@{ Timestamp = '2026-08-15T08:05:00Z'; Computer = 'WS01'; RuleTitle = 'Encoded PowerShell'; Level = 'medium'; Details = 'powershell -enc AAA' }
            ) | Export-Csv -LiteralPath $csv -NoTypeInformation -Encoding UTF8

            $events = @(Import-OFTimelineCsv -Case $case -Path $csv -Quiet)
            $events.Count | Should -Be 2
            $events[0].severity | Should -Be 'high'
            @($events[0].mitre).Count | Should -BeGreaterThan 0
        } finally {
            Remove-Item -LiteralPath $case.caseDir -Recurse -Force -ErrorAction SilentlyContinue
        }
    }
}

Describe 'Export-OFCaseIoc' {
    It 'mengekspor hanya artefak bertipe indikator' {
        $case = New-TimelineTestCase
        try {
            $case.artifacts = @(
                [pscustomobject]@{ type = 'url'; value = 'http://jahat.example/a'; evidenceId = 'E001'; toolId = 'strings'; severity = 'high'; count = 2; category = 'network' },
                [pscustomobject]@{ type = 'ipv4'; value = '10.20.30.40'; evidenceId = 'E001'; toolId = 'tshark'; severity = 'medium'; count = 1; category = 'network' },
                [pscustomobject]@{ type = 'ctf_flag'; value = 'flag{abc}'; evidenceId = 'E001'; toolId = 'strings'; severity = 'low'; count = 1; category = 'ctf' }
            )

            $csv = Export-OFCaseIoc -Case $case -Format Csv -Quiet
            $csv.IocCount | Should -Be 2
            Test-Path -LiteralPath $csv.Path | Should -BeTrue

            $stix = Export-OFCaseIoc -Case $case -Format Stix -Quiet
            $bundle = Get-Content -LiteralPath $stix.Path -Raw | ConvertFrom-Json
            $bundle.type | Should -Be 'bundle'
            @($bundle.objects).Count | Should -Be 2

            $misp = Export-OFCaseIoc -Case $case -Format Misp -Quiet
            $event = Get-Content -LiteralPath $misp.Path -Raw | ConvertFrom-Json
            @($event.Event.Attribute).Count | Should -Be 2
        } finally {
            Remove-Item -LiteralPath $case.caseDir -Recurse -Force -ErrorAction SilentlyContinue
        }
    }

    It 'gagal dengan pesan jelas bila tidak ada IOC' {
        $case = New-TimelineTestCase
        try {
            { Export-OFCaseIoc -Case $case -Format Csv -Quiet } | Should -Throw
        } finally {
            Remove-Item -LiteralPath $case.caseDir -Recurse -Force -ErrorAction SilentlyContinue
        }
    }
}
