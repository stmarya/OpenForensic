#Requires -Version 5.1
<#
    Pester 5 - modul integritas.
    Semua pengujian offline dan memakai folder kasus sintetis di TEMP.
#>

BeforeAll {
    $script:ModuleManifest = Join-Path (Split-Path -Parent $PSScriptRoot) 'OpenForensic.psd1'
    Import-Module $script:ModuleManifest -Force -DisableNameChecking
    $script:IsWindowsHost = ($env:OS -eq 'Windows_NT')

    function New-TestCase {
        $dir = Join-Path ([System.IO.Path]::GetTempPath()) ('of_test_' + [Guid]::NewGuid().ToString('N').Substring(0, 8))
        New-Item -ItemType Directory -Path $dir -Force | Out-Null
        foreach ($sub in @('logs', 'artifacts', 'ai', 'exports', 'evidence')) {
            New-Item -ItemType Directory -Path (Join-Path $dir $sub) -Force | Out-Null
        }
        $now = (Get-Date).ToString('o')
        return [pscustomobject]@{
            schemaVersion  = 1
            caseId         = 'CASE-TEST-0001'
            name           = 'Kasus Uji'
            description    = ''
            reference      = ''
            classification = 'internal'
            examiner       = 'pester'
            status         = 'open'
            toolkit        = 'OpenForensic 0.4.0'
            createdAt      = $now
            updatedAt      = $now
            caseDir        = $dir
            evidence       = @()
            findings       = @()
            artifacts      = @()
            timeline       = @()
            chainOfCustody = @()
            ai             = [pscustomobject]@{ enabled = $false; provider = ''; model = ''; summary = ''; narrative = ''; runs = @() }
        }
    }
}

Describe 'Manifest kasus' {
    It 'mendeteksi berkas yang dimodifikasi, hilang, dan ditambahkan' {
        $case = New-TestCase
        try {
            $fileA = Join-Path $case.caseDir 'logs\a.log'
            $fileB = Join-Path $case.caseDir 'logs\b.log'
            Set-Content -LiteralPath $fileA -Value 'isi awal A' -Encoding UTF8
            Set-Content -LiteralPath $fileB -Value 'isi awal B' -Encoding UTF8

            New-OFCaseManifest -Case $case | Out-Null
            (Test-OFCaseManifest -Case $case).Ok | Should -BeTrue

            Set-Content -LiteralPath $fileA -Value 'isi diubah' -Encoding UTF8
            Remove-Item -LiteralPath $fileB -Force
            Set-Content -LiteralPath (Join-Path $case.caseDir 'logs\c.log') -Value 'baru' -Encoding UTF8

            $check = Test-OFCaseManifest -Case $case
            $check.Ok | Should -BeFalse
            @($check.Modified).Count | Should -BeGreaterThan 0
            @($check.Missing).Count | Should -BeGreaterThan 0
            @($check.Added).Count | Should -BeGreaterThan 0
        } finally {
            Remove-Item -LiteralPath $case.caseDir -Recurse -Force -ErrorAction SilentlyContinue
        }
    }
}

Describe 'Segel kasus (PBKDF2 passphrase)' {
    It 'valid setelah disegel dan gagal setelah berkas diubah' {
        $case = New-TestCase
        try {
            Set-Content -LiteralPath (Join-Path $case.caseDir 'logs\a.log') -Value 'isi' -Encoding UTF8
            $passphrase = ConvertTo-SecureString 'kata-sandi-uji-123' -AsPlainText -Force

            New-OFCaseManifest -Case $case | Out-Null
            New-OFCaseSeal -Case $case -Passphrase $passphrase | Out-Null
            (Test-OFCaseSeal -Case $case -Passphrase $passphrase).Ok | Should -BeTrue

            Set-Content -LiteralPath (Join-Path $case.caseDir 'logs\a.log') -Value 'isi diubah' -Encoding UTF8
            New-OFCaseManifest -Case $case | Out-Null
            (Test-OFCaseSeal -Case $case -Passphrase $passphrase).Ok | Should -BeFalse
        } finally {
            Remove-Item -LiteralPath $case.caseDir -Recurse -Force -ErrorAction SilentlyContinue
        }
    }

    It 'menolak passphrase yang salah' {
        $case = New-TestCase
        try {
            Set-Content -LiteralPath (Join-Path $case.caseDir 'logs\a.log') -Value 'isi' -Encoding UTF8
            New-OFCaseManifest -Case $case | Out-Null
            New-OFCaseSeal -Case $case -Passphrase (ConvertTo-SecureString 'benar-123' -AsPlainText -Force) | Out-Null
            (Test-OFCaseSeal -Case $case -Passphrase (ConvertTo-SecureString 'salah-456' -AsPlainText -Force)).Ok | Should -BeFalse
        } finally {
            Remove-Item -LiteralPath $case.caseDir -Recurse -Force -ErrorAction SilentlyContinue
        }
    }
}

Describe 'Allowlist hash' {
    It 'mengembalikan false untuk hash yang tidak terdaftar' {
        $random = ([Guid]::NewGuid().ToString('N') + [Guid]::NewGuid().ToString('N')).Substring(0, 64).ToUpperInvariant()
        Test-OFHashAllowlist -Sha256 $random | Should -BeFalse
    }
}

Describe 'Deduplikasi bukti' {
    It 'mengenali berkas dengan hash yang sama sebagai duplikat' {
        $case = New-TestCase
        $temp = Join-Path ([System.IO.Path]::GetTempPath()) ('of_dup_' + [Guid]::NewGuid().ToString('N').Substring(0, 8) + '.txt')
        try {
            Set-Content -LiteralPath $temp -Value 'konten duplikat' -Encoding UTF8
            $hash = (Get-FileHash -LiteralPath $temp -Algorithm SHA256).Hash
            $case.evidence = @([pscustomobject]@{ id = 'E001'; name = 'lama.txt'; sha256 = $hash })

            $result = Test-OFEvidenceDuplicate -Case $case -Path $temp
            $result.IsDuplicate | Should -BeTrue
            $result.ExistingEvidenceId | Should -Be 'E001'
        } finally {
            Remove-Item -LiteralPath $temp -Force -ErrorAction SilentlyContinue
            Remove-Item -LiteralPath $case.caseDir -Recurse -Force -ErrorAction SilentlyContinue
        }
    }
}

Describe 'Eksekusi proses dengan timeout' {
    It 'menghentikan proses yang menggantung dan menandai TimedOut' -Skip:(-not ($env:OS -eq 'Windows_NT')) {
        $result = Invoke-OFProcessWithTimeout -FilePath $env:ComSpec -Arguments @('/c', 'ping -n 30 127.0.0.1') -TimeoutSeconds 2
        $result.TimedOut | Should -BeTrue
        $result.Success | Should -BeFalse
    }

    It 'mengembalikan output proses yang selesai normal' -Skip:(-not ($env:OS -eq 'Windows_NT')) {
        $result = Invoke-OFProcessWithTimeout -FilePath $env:ComSpec -Arguments @('/c', 'echo HALO') -TimeoutSeconds 20
        $result.TimedOut | Should -BeFalse
        $result.StandardOutput | Should -Match 'HALO'
    }
}
