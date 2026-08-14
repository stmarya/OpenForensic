#Requires -Version 5.1
<#
    Pester tests untuk modul OpenForensic.
    Semua test bersifat offline: tidak ada panggilan jaringan.
    Proses eksternal yang dipakai hanya shell bawaan OS:
      Windows : cmd.exe (dari %ComSpec%)
      Unix    : /bin/echo dan /bin/sh
#>

BeforeAll {
    $script:RepoRoot = Split-Path -Parent $PSScriptRoot
    Import-Module (Join-Path $script:RepoRoot 'OpenForensic.psd1') -Force

    $script:Sandbox = Join-Path ([System.IO.Path]::GetTempPath()) ("of_tests_" + [guid]::NewGuid().ToString('N'))
    New-Item -ItemType Directory -Path $script:Sandbox -Force | Out-Null

    $script:OnWindows = [bool](Test-OFWindows)

    # Perintah eksternal portabel untuk menguji Invoke-OFTool.
    if ($script:OnWindows) {
        $script:ShellPath = $env:ComSpec
        if (-not $script:ShellPath) { $script:ShellPath = 'cmd.exe' }
        $script:EchoPath = $script:ShellPath
        $script:EchoPrefix = @('/c', 'echo')
        $script:ExitPath = $script:ShellPath
        $script:ExitPrefix = @('/c', 'exit')
        $script:ExitArgs = @('3')
    } else {
        $script:ShellPath = '/bin/sh'
        $script:EchoPath = if (Test-Path -LiteralPath '/bin/echo') { '/bin/echo' } else { '/usr/bin/echo' }
        $script:EchoPrefix = @()
        $script:ExitPath = $script:ShellPath
        $script:ExitPrefix = @('-c')
        $script:ExitArgs = @('exit 3')
    }

    function Invoke-TestEcho {
        param([Parameter(Mandatory)][string]$Text)
        $arguments = @($script:EchoPrefix) + @($Text)
        return Invoke-OFTool -ToolPath $script:EchoPath -Arguments $arguments -Quiet
    }

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

    It 'dapat me-resolve setiap tool tanpa error di OS apa pun' {
        foreach ($tool in $script:Catalog) {
            { Resolve-OFTool -Id $tool.id -Catalog $script:Catalog } | Should -Not -Throw
        }
    }

    It 'menghasilkan objek resolusi dengan field lintas platform' {
        $resolved = Resolve-OFTool -Id $script:Catalog[0].id -Catalog $script:Catalog
        $resolved.PSObject.Properties.Name | Should -Contain 'ResolvedFrom'
        $resolved.ResolvedFrom | Should -BeIn @('builtin', 'local', 'path', 'none')
        $resolved.PSObject.Properties.Name | Should -Contain 'Available'
    }

    It 'memakai executableByOs bila tersedia tanpa error' {
        $withOverride = @($script:Catalog | Where-Object { $_.PSObject.Properties.Name -contains 'executableByOs' })
        foreach ($tool in $withOverride) {
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
        $result = Invoke-TestEcho -Text 'openforensic'
        ($result.Output -join ' ') | Should -Match 'openforensic'
        $result.ExitCode | Should -Be 0
        $result.Success | Should -BeTrue
    }

    It 'menangkap exit code bukan nol' {
        $arguments = @($script:ExitPrefix) + @($script:ExitArgs)
        $result = Invoke-OFTool -ToolPath $script:ExitPath -Arguments $arguments -Quiet
        $result.ExitCode | Should -Be 3
        $result.Success | Should -BeFalse
    }

    It 'tidak mengevaluasi metakarakter shell pada argumen (anti command injection)' {
        # Payload berisi metakarakter shell. Karena argumen dikirim sebagai array,
        # payload harus muncul utuh sebagai SATU baris output dan tidak boleh
        # dieksekusi sebagai perintah kedua.
        $payload = 'a & echo INJECTED'
        $result = Invoke-TestEcho -Text $payload
        $lines = @($result.Output | Where-Object { $_ -match '\S' })
        $lines.Count | Should -Be 1 -Because 'payload tidak boleh dipecah menjadi dua perintah'
        $lines[0] | Should -Match 'a\s*&\s*echo INJECTED'
    }

    It 'tidak mengevaluasi substitusi perintah gaya Unix' -Skip:$script:OnWindows {
        $payload = 'x $(id) `id` ${HOME}'
        $result = Invoke-TestEcho -Text $payload
        $joined = ($result.Output -join ' ')
        $joined | Should -Match '\$\(id\)'
        $joined | Should -Match '\$\{HOME\}'
        $joined | Should -Not -Match 'uid='
    }

    It 'tidak melempar error saat executable tidak ada' {
        $missing = Join-Path $script:Sandbox 'tidak_ada_executable'
        $result = Invoke-OFTool -ToolPath $missing -Arguments @() -Quiet
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

    It 'mencatat lingkungan pemeriksaan pada header report' {
        $content = Get-Content -LiteralPath $script:Report.TextPath -Raw
        $content | Should -Match 'Lingkungan'
        $content | Should -Match 'Toolkit'
        $content | Should -Not -Match 'Analis      : \s*$'
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
        $payload.analyst | Should -Not -BeNullOrEmpty
        $payload.workstation | Should -Not -BeNullOrEmpty
    }
}

Describe 'Select-OFTargetFile' {
    It 'mengembalikan path yang diberikan tanpa dialog GUI' {
        $path = Join-Path $script:Sandbox 'abc.txt'
        (Select-OFTargetFile -Path $path) | Should -Be (Resolve-Path -LiteralPath $path).Path
    }

    It 'memperingatkan dan mengembalikan null untuk path yang tidak ada' {
        $result = Select-OFTargetFile -Path (Join-Path $script:Sandbox 'tidak_ada_file.bin') -WarningAction SilentlyContinue
        $result | Should -BeNullOrEmpty
    }

    It 'tidak memerlukan System.Windows.Forms saat Path diberikan' -Skip:$script:OnWindows {
        $path = Join-Path $script:Sandbox 'abc.txt'
        { Select-OFTargetFile -Path $path } | Should -Not -Throw
    }
}

Describe 'Penyimpanan API key lintas platform' {
    It 'melaporkan mode penyimpanan yang sesuai platform' {
        $mode = Get-OFSecureStorageMode
        $mode | Should -BeIn @('dpapi', 'pbkdf2')
        if (-not $script:OnWindows) { $mode | Should -Be 'pbkdf2' }
    }

    It 'mengembalikan path key store yang absolut' {
        $paths = Get-OFPath
        $paths.KeyStore | Should -Not -BeNullOrEmpty
        [System.IO.Path]::IsPathRooted($paths.KeyStore) | Should -BeTrue
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

    It 'modul inti tidak memakai variabel lingkungan khusus Windows' {
        $coreModules = @('OpenForensic.psm1', 'OpenForensic.Workflow.psm1')
        foreach ($name in $coreModules) {
            $path = Join-Path $script:RepoRoot $name
            if (-not (Test-Path -LiteralPath $path)) { continue }
            $content = Get-Content -LiteralPath $path -Raw
            $content | Should -Not -Match '\$env:TEMP' -Because "$name harus memakai Get-OFTempDirectory"
            $content | Should -Not -Match '\$env:ComSpec' -Because "$name tidak boleh bergantung pada cmd.exe"
        }
    }

    It 'hanya lapisan platform yang memakai flag $IsWindows' {
        $modules = Get-ChildItem -Path $script:RepoRoot -Filter '*.psm1' -File |
            Where-Object { $_.Name -ne 'OpenForensic.Platform.psm1' }
        foreach ($module in $modules) {
            $content = Get-Content -LiteralPath $module.FullName -Raw
            $content | Should -Not -Match '\$IsWindows' -Because "$($module.Name) harus memakai Test-OFWindows"
        }
    }

    It 'mengekspor seluruh fungsi yang dideklarasikan di manifest' {
        $manifest = Import-PowerShellDataFile -Path (Join-Path $script:RepoRoot 'OpenForensic.psd1')
        foreach ($functionName in $manifest.FunctionsToExport) {
            Get-Command -Name $functionName -Module 'OpenForensic' -ErrorAction SilentlyContinue |
                Should -Not -BeNullOrEmpty -Because "$functionName harus diekspor"
        }
    }
}
