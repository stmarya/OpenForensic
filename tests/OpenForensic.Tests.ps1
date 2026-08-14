#Requires -Version 5.1
<#
    Pester tests untuk modul OpenForensic.
    Semua test bersifat offline: tidak ada panggilan jaringan dan tidak ada tool eksternal
    selain cmd.exe bawaan Windows.
#>

BeforeAll {
    $script:RepoRoot = Split-Path -Parent $PSScriptRoot
    Import-Module (Join-Path $script:RepoRoot 'OpenForensic.psd1') -Force

    $script:Sandbox = Join-Path ([System.IO.Path]::GetTempPath()) ("of_tests_" + [guid]::NewGuid().ToString('N'))
    New-Item -ItemType Directory -Path $script:Sandbox -Force | Out-Null

    function New-TestBinaryFile {
        param([string]$Name, [byte[]]$Bytes)
        $path = Join-Path $script:Sandbox $Name
        [System.IO.File]::WriteAllBytes($path, $Bytes)
        return $path
    }

    $script:PngBytes = [byte[]](0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A, 0x00, 0x00, 0x00, 0x0D, 0x49, 0x48, 0x44, 0x52)
    $script:PdfBytes = [System.Text.Encoding]::ASCII.GetBytes('%PDF-1.7' + "`n" + 'trailer')
    $script:OleBytes = [byte[]](0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1, 0x00, 0x00, 0x00, 0x00)
}

AfterAll {
    if ($script:Sandbox -and (Test-Path -LiteralPath $script:Sandbox)) {
        Remove-Item -LiteralPath $script:Sandbox -Recurse -Force -ErrorAction SilentlyContinue
    }
}

Describe 'Katalog tools.json' {
    BeforeAll {
        $script:Catalog = @(Get-OFToolCatalog)
        $script:RequiredFields = @('id', 'name', 'description', 'category', 'executable', 'source',
            'builtin', 'extensions', 'kinds', 'argTemplate', 'requiresPlugin', 'plugins',
            'triage', 'triageArgs', 'dialogFilter', 'installHint')
    }

    It 'memuat minimal satu tool' {
        $script:Catalog.Count | Should -BeGreaterThan 0
    }

    It 'memiliki id yang unik' {
        $ids = $script:Catalog | ForEach-Object { $_.id }
        ($ids | Select-Object -Unique).Count | Should -Be $ids.Count
    }

    It 'memiliki seluruh field wajib pada setiap entri' {
        foreach ($tool in $script:Catalog) {
            $properties = $tool.PSObject.Properties.Name
            foreach ($field in $script:RequiredFields) {
                $properties | Should -Contain $field -Because "tool '$($tool.id)' harus punya field '$field'"
            }
        }
    }

    It 'hanya memakai source yang dikenal' {
        foreach ($tool in $script:Catalog) {
            $tool.source | Should -BeIn @('bin', 'path', 'builtin')
        }
    }

    It 'mendefinisikan builtin handler yang benar-benar ada' {
        foreach ($tool in ($script:Catalog | Where-Object { $_.source -eq 'builtin' })) {
            Get-Command -Name $tool.builtin -ErrorAction SilentlyContinue | Should -Not -BeNullOrEmpty
        }
    }

    It 'memakai placeholder {file} pada argTemplate tool berbasis file' {
        foreach ($tool in ($script:Catalog | Where-Object { $_.argTemplate.Count -gt 0 })) {
            ($tool.argTemplate -join ' ') | Should -Match '\{file\}'
        }
    }

    It 'dapat me-resolve setiap tool tanpa error' {
        foreach ($tool in $script:Catalog) {
            { Resolve-OFTool -Id $tool.id -Catalog $script:Catalog } | Should -Not -Throw
        }
    }
}

Describe 'Get-OFEvidenceHash' {
    It 'menghitung SHA256 yang benar' {
        $path = Join-Path $script:Sandbox 'abc.txt'
        [System.IO.File]::WriteAllBytes($path, [System.Text.Encoding]::ASCII.GetBytes('abc'))
        $hash = Get-OFEvidenceHash -Path $path
        $hash.SHA256 | Should -Be 'BA7816BF8F01CFEA414140DE5DAE2223B00361A396177A9CB410FF61F20015AD'
        $hash.Size | Should -Be 3
    }

    It 'mengembalikan ketiga algoritma' {
        $path = Join-Path $script:Sandbox 'abc.txt'
        $hash = Get-OFEvidenceHash -Path $path
        $hash.MD5 | Should -Not -BeNullOrEmpty
        $hash.SHA1 | Should -Not -BeNullOrEmpty
        $hash.SHA256 | Should -Not -BeNullOrEmpty
    }
}

Describe 'Get-OFFileType' {
    It 'mendeteksi PNG dari magic bytes' {
        $path = New-TestBinaryFile -Name 'gambar.png' -Bytes $script:PngBytes
        (Get-OFFileType -Path $path).Kind | Should -Be 'image'
    }

    It 'mendeteksi PDF dari magic bytes' {
        $path = New-TestBinaryFile -Name 'dokumen.pdf' -Bytes $script:PdfBytes
        (Get-OFFileType -Path $path).Kind | Should -Be 'pdf'
    }

    It 'mendeteksi OLE2 sebagai dokumen Office lama' {
        $path = New-TestBinaryFile -Name 'makro.doc' -Bytes $script:OleBytes
        (Get-OFFileType -Path $path).Kind | Should -Be 'ole'
    }

    It 'menandai ekstensi palsu sebagai TypeMismatch' {
        $path = New-TestBinaryFile -Name 'palsu.pdf' -Bytes $script:PngBytes
        $type = Get-OFFileType -Path $path
        $type.Kind | Should -Be 'image'
        $type.ExpectedFromExtension | Should -Be 'pdf'
        $type.TypeMismatch | Should -BeTrue
    }

    It 'tidak menandai mismatch untuk ekstensi yang benar' {
        $path = New-TestBinaryFile -Name 'benar.png' -Bytes $script:PngBytes
        (Get-OFFileType -Path $path).TypeMismatch | Should -BeFalse
    }

    It 'menangani file kosong tanpa error' {
        $path = Join-Path $script:Sandbox 'kosong.bin'
        [System.IO.File]::WriteAllBytes($path, [byte[]]@())
        { Get-OFFileType -Path $path } | Should -Not -Throw
    }
}

Describe 'Invoke-OFStrings' {
    It 'menemukan string ASCII yang ditanam' {
        $path = Join-Path $script:Sandbox 'ascii.bin'
        $bytes = [System.Text.Encoding]::ASCII.GetBytes("junk" + [char]0 + "flag{unit_test_ascii}" + [char]0 + "junk")
        [System.IO.File]::WriteAllBytes($path, $bytes)
        $result = Invoke-OFStrings -Path $path
        ($result -join "`n") | Should -Match 'flag\{unit_test_ascii\}'
    }

    It 'menemukan string UTF-16LE yang ditanam' {
        $path = Join-Path $script:Sandbox 'wide.bin'
        $bytes = [System.Text.Encoding]::Unicode.GetBytes('flag{unit_test_wide}')
        [System.IO.File]::WriteAllBytes($path, $bytes)
        $result = Invoke-OFStrings -Path $path
        ($result -join "`n") | Should -Match 'flag\{unit_test_wide\}'
    }

    It 'menghormati filter Pattern' {
        $path = Join-Path $script:Sandbox 'ascii.bin'
        $result = Invoke-OFStrings -Path $path -Pattern 'flag\{'
        ($result -join "`n") | Should -Not -Match 'junk'
    }
}

Describe 'Invoke-OFTool' {
    It 'menjalankan proses dan menangkap output' {
        $result = Invoke-OFTool -ToolPath $env:ComSpec -Arguments @('/c', 'echo', 'openforensic') -Quiet
        ($result.Output -join ' ') | Should -Match 'openforensic'
        $result.ExitCode | Should -Be 0
        $result.Success | Should -BeTrue
    }

    It 'menangkap exit code bukan nol' {
        $result = Invoke-OFTool -ToolPath $env:ComSpec -Arguments @('/c', 'exit', '3') -Quiet
        $result.ExitCode | Should -Be 3
        $result.Success | Should -BeFalse
    }

    It 'tidak mengevaluasi metakarakter pada argumen (anti command injection)' {
        $payload = 'a & echo INJECTED'
        $result = Invoke-OFTool -ToolPath $env:ComSpec -Arguments @('/c', 'echo', $payload) -Quiet
        ($result.Output -join ' ') | Should -Not -Match 'INJECTED\s*$'
        ($result.Output -join ' ') | Should -Match 'echo INJECTED'
    }

    It 'tidak melempar error saat executable tidak ada' {
        $result = Invoke-OFTool -ToolPath (Join-Path $script:Sandbox 'tidak_ada.exe') -Arguments @() -Quiet
        $result.Success | Should -BeFalse
        $result.Error | Should -Not -BeNullOrEmpty
    }
}

Describe 'Report' {
    BeforeAll {
        $script:TargetFile = Join-Path $script:Sandbox 'bukti.png'
        [System.IO.File]::WriteAllBytes($script:TargetFile, $script:PngBytes)
        $script:Report = New-OFReport -TargetPath $script:TargetFile
    }

    AfterAll {
        foreach ($path in @($script:Report.TextPath, $script:Report.JsonPath)) {
            if ($path -and (Test-Path -LiteralPath $path)) { Remove-Item -LiteralPath $path -Force -ErrorAction SilentlyContinue }
        }
    }

    It 'membuat file report teks berisi hash bukti' {
        Test-Path -LiteralPath $script:Report.TextPath | Should -BeTrue
        $content = Get-Content -LiteralPath $script:Report.TextPath -Raw
        $content | Should -Match 'SHA256'
        $content | Should -Match $script:Report.Hashes.SHA256
    }

    It 'mencatat entry analisis' {
        Add-OFReportEntry -Report $script:Report -Command 'dummy.exe' -Arguments @('-x') -Output @('baris output') -ExitCode 0
        $script:Report.Entries.Count | Should -Be 1
        (Get-Content -LiteralPath $script:Report.TextPath -Raw) | Should -Match 'baris output'
    }

    It 'menyimpan JSON dan memverifikasi integritas bukti' {
        [void](Save-OFReport -Report $script:Report)
        Test-Path -LiteralPath $script:Report.JsonPath | Should -BeTrue
        $payload = Get-Content -LiteralPath $script:Report.JsonPath -Raw | ConvertFrom-Json
        $payload.integrity.verified | Should -BeTrue
        $payload.target.sha256 | Should -Be $script:Report.Hashes.SHA256
        $payload.entries.Count | Should -Be 1
    }
}

Describe 'Kebijakan keamanan kode' {
    It 'tidak memakai Invoke-Expression di file PowerShell root' {
        $files = Get-ChildItem -Path $script:RepoRoot -Filter '*.ps*1' -File
        foreach ($file in $files) {
            $content = Get-Content -LiteralPath $file.FullName -Raw
            $content | Should -Not -Match 'Invoke-Expression' -Because "$($file.Name) tidak boleh memakai Invoke-Expression"
        }
    }

    It 'tidak menyimpan API key sebagai plaintext lewat Set-Content langsung' {
        $module = Get-Content -LiteralPath (Join-Path $script:RepoRoot 'OpenForensic.psm1') -Raw
        $module | Should -Match 'ConvertFrom-SecureString'
    }

    It 'mengekspor seluruh fungsi yang dideklarasikan di manifest' {
        $manifest = Import-PowerShellDataFile -Path (Join-Path $script:RepoRoot 'OpenForensic.psd1')
        foreach ($functionName in $manifest.FunctionsToExport) {
            Get-Command -Name $functionName -Module 'OpenForensic' -ErrorAction SilentlyContinue |
                Should -Not -BeNullOrEmpty -Because "$functionName harus diekspor"
        }
    }
}
