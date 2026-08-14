#Requires -Version 5.1
<#
    Regression test berbasis golden fixtures.

    Tujuannya: bila detektor artefak diubah dan mulai kehilangan indikator penting,
    test ini gagal. Semua fixture adalah bukti sintetis di tests/fixtures.
#>

BeforeAll {
    $script:RepoRoot = Split-Path -Parent $PSScriptRoot
    $script:FixtureDir = Join-Path $PSScriptRoot 'fixtures'
    Import-Module (Join-Path $script:RepoRoot 'OpenForensic.psd1') -Force -DisableNameChecking

    function Get-FixturePath {
        param([Parameter(Mandatory)][string]$Name)
        $path = Join-Path $script:FixtureDir $Name
        if (-not (Test-Path -LiteralPath $path)) { throw "Fixture tidak ditemukan: $path" }
        return $path
    }
}

Describe 'Fixture tersedia dan portabel' {
    It 'memuat seluruh fixture yang diharapkan' {
        foreach ($name in @('sample_strings.txt', 'sample_prompt_injection.txt', 'hayabusa_sample.csv', 'mftecmd_sample.csv', 'allowlist_sample.txt', 'README.md')) {
            Test-Path -LiteralPath (Join-Path $script:FixtureDir $name) | Should -BeTrue -Because "fixture $name harus ada"
        }
    }

    It 'memakai akhir baris LF tanpa CR' {
        foreach ($file in (Get-ChildItem -LiteralPath $script:FixtureDir -File)) {
            $bytes = [System.IO.File]::ReadAllBytes($file.FullName)
            ($bytes -contains 13) | Should -BeFalse -Because "$($file.Name) harus LF agar hasil test sama di semua OS"
        }
    }

    It 'memakai UTF-8 tanpa BOM' {
        foreach ($file in (Get-ChildItem -LiteralPath $script:FixtureDir -File)) {
            $bytes = [System.IO.File]::ReadAllBytes($file.FullName)
            if ($bytes.Length -ge 3) {
                (($bytes[0] -eq 0xEF) -and ($bytes[1] -eq 0xBB) -and ($bytes[2] -eq 0xBF)) | Should -BeFalse -Because "$($file.Name) tidak boleh berisi BOM"
            }
        }
    }
}

Describe 'Find-OFArtifact pada sample_strings.txt' {
    BeforeAll {
        $script:StringsLines = Get-Content -LiteralPath (Get-FixturePath 'sample_strings.txt')
        $script:Artifacts = @(Find-OFArtifact -Text $script:StringsLines -EvidenceId 'E001' -ToolId 'strings')
        $script:Types = @($script:Artifacts | Select-Object -ExpandProperty type -Unique)
    }

    It 'menghasilkan artefak' {
        $script:Artifacts.Count | Should -BeGreaterThan 10
    }

    It 'mendeteksi indikator jaringan dan identitas' {
        foreach ($type in @('url', 'ipv4', 'domain', 'email')) {
            $script:Types | Should -Contain $type
        }
    }

    It 'mendeteksi persistence dan eksekusi' {
        foreach ($type in @('registry_autorun', 'scheduled_task', 'lolbin')) {
            $script:Types | Should -Contain $type
        }
    }

    It 'mendeteksi kredensial' {
        foreach ($type in @('credential_pair', 'aws_access_key')) {
            $script:Types | Should -Contain $type
        }
    }

    It 'mendeteksi indikator kripto dan ransomware' {
        foreach ($type in @('bitcoin_address', 'ethereum_address', 'ransom_note_hint')) {
            $script:Types | Should -Contain $type
        }
    }

    It 'mendeteksi hash dan flag CTF' {
        foreach ($type in @('md5_hash', 'sha256_hash', 'ctf_flag')) {
            $script:Types | Should -Contain $type
        }
    }

    It 'mengambil nilai IOC yang tepat, bukan hanya tipenya' {
        $values = @($script:Artifacts | Select-Object -ExpandProperty value)
        $values | Should -Contain '198.51.100.23'
        $values | Should -Contain 'operator@example-malicious.test'
        $values | Should -Contain '1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2'
        $values | Should -Contain 'AKIAIOSFODNN7EXAMPLE'
        ($values | Where-Object { $_ -like 'flag{*}' }).Count | Should -BeGreaterThan 0
    }

    It 'memberi severity dan kategori pada setiap artefak' {
        foreach ($artifact in $script:Artifacts) {
            $artifact.severity | Should -BeIn @('info', 'low', 'medium', 'high', 'critical')
            $artifact.category | Should -Not -BeNullOrEmpty
            $artifact.evidenceId | Should -Be 'E001'
            $artifact.count | Should -BeGreaterThan 0
        }
    }

    It 'menghormati batas MaxPerType' {
        $limited = @(Find-OFArtifact -Text $script:StringsLines -MaxPerType 1)
        foreach ($group in ($limited | Group-Object -Property type)) {
            $group.Count | Should -BeLessOrEqual 1
        }
    }

    It 'dapat difilter ke detektor tertentu saja' {
        $only = @(Find-OFArtifact -Text $script:StringsLines -DetectorName @('ipv4'))
        $only.Count | Should -BeGreaterThan 0
        @($only | Select-Object -ExpandProperty type -Unique) | Should -Be @('ipv4')
    }
}

Describe 'Find-OFArtifact pada sample_prompt_injection.txt' {
    BeforeAll {
        $script:InjectionLines = Get-Content -LiteralPath (Get-FixturePath 'sample_prompt_injection.txt')
        $script:InjectionArtifacts = @(Find-OFArtifact -Text $script:InjectionLines -EvidenceId 'E002')
    }

    It 'menandai upaya prompt injection' {
        $types = @($script:InjectionArtifacts | Select-Object -ExpandProperty type -Unique)
        $types | Should -Contain 'prompt_injection'
    }

    It 'memberi severity minimal high pada prompt injection' {
        $injection = @($script:InjectionArtifacts | Where-Object { $_.type -eq 'prompt_injection' })
        foreach ($item in $injection) {
            $item.severity | Should -BeIn @('high', 'critical')
        }
    }

    It 'tetap menangkap URL eksfiltrasi di dalam teks injeksi' {
        @($script:InjectionArtifacts | Select-Object -ExpandProperty value) |
            Where-Object { $_ -like '*198.51.100.23*' } |
            Should -Not -BeNullOrEmpty
    }
}

Describe 'Fixture CSV untuk impor timeline' {
    It 'hayabusa_sample.csv memiliki kolom dan jumlah baris yang diharapkan' {
        $rows = @(Import-Csv -LiteralPath (Get-FixturePath 'hayabusa_sample.csv'))
        $rows.Count | Should -Be 6
        $columns = @($rows[0].PSObject.Properties.Name)
        foreach ($column in @('Timestamp', 'Computer', 'Channel', 'EventID', 'Level', 'RuleTitle', 'Details')) {
            $columns | Should -Contain $column
        }
        @($rows | Where-Object { $_.Level -in @('high', 'critical') }).Count | Should -Be 4
    }

    It 'setiap timestamp hayabusa dapat diurai sebagai waktu' {
        foreach ($row in (Import-Csv -LiteralPath (Get-FixturePath 'hayabusa_sample.csv'))) {
            { [datetime]::Parse($row.Timestamp, [System.Globalization.CultureInfo]::InvariantCulture) } | Should -Not -Throw
        }
    }

    It 'mftecmd_sample.csv memiliki kolom waktu MFT' {
        $rows = @(Import-Csv -LiteralPath (Get-FixturePath 'mftecmd_sample.csv'))
        $rows.Count | Should -Be 4
        @($rows[0].PSObject.Properties.Name) | Should -Contain 'Created0x10'
        foreach ($row in $rows) {
            { [datetime]::Parse($row.'Created0x10', [System.Globalization.CultureInfo]::InvariantCulture) } | Should -Not -Throw
        }
    }
}

Describe 'Fixture allowlist hash' {
    It 'memuat tiga hash SHA256 yang sah dan mengabaikan komentar' {
        $lines = @(Get-Content -LiteralPath (Get-FixturePath 'allowlist_sample.txt') |
            Where-Object { $_ -and -not $_.StartsWith('#') })
        $lines.Count | Should -Be 3
        foreach ($line in $lines) {
            $line.Trim() | Should -Match '^[A-Fa-f0-9]{64}$'
        }
    }

    It 'memuat hash SHA256 dari string kosong sebagai kontrol' {
        $content = Get-Content -LiteralPath (Get-FixturePath 'allowlist_sample.txt') -Raw
        $content | Should -Match 'E3B0C44298FC1C149AFBF4C8996FB92427AE41E4649B934CA495991B7852B855'
    }
}
