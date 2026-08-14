#Requires -Version 5.1
<#
    Test lapisan kompatibilitas lintas platform.
    Test ini harus lulus di Windows (5.1 dan 7), Linux, dan macOS.
#>

BeforeAll {
    $script:ModuleManifest = Join-Path (Split-Path -Parent $PSScriptRoot) 'OpenForensic.psd1'
    Import-Module $script:ModuleManifest -Force -DisableNameChecking
}

Describe 'Get-OFPlatform' {
    It 'mengenali tepat satu sistem operasi' {
        $platform = Get-OFPlatform
        $flags = @($platform.IsWindows, $platform.IsLinux, $platform.IsMacOS) | Where-Object { $_ }
        $flags.Count | Should -Be 1
    }

    It 'melaporkan versi dan edisi PowerShell' {
        $platform = Get-OFPlatform
        $platform.PSVersion | Should -Not -BeNullOrEmpty
        $platform.PSEdition | Should -BeIn @('Desktop', 'Core')
    }

    It 'menyediakan direktori data yang absolut' {
        $platform = Get-OFPlatform
        [System.IO.Path]::IsPathRooted($platform.DataRoot) | Should -BeTrue
    }

    It 'konsisten dengan Test-OFWindows' {
        (Get-OFPlatform).IsWindows | Should -Be (Test-OFWindows)
    }
}

Describe 'Get-OFDataRoot dan Get-OFTempDirectory' {
    It 'menghormati OPENFORENSIC_HOME' {
        $previous = $env:OPENFORENSIC_HOME
        try {
            $custom = Join-Path ([System.IO.Path]::GetTempPath()) ('of-home-' + [guid]::NewGuid().ToString('N').Substring(0, 6))
            $env:OPENFORENSIC_HOME = $custom
            Get-OFDataRoot | Should -Be $custom
        } finally {
            $env:OPENFORENSIC_HOME = $previous
        }
    }

    It 'dapat membuat direktori sementara' {
        $temp = Get-OFTempDirectory -Create
        Test-Path -LiteralPath $temp | Should -BeTrue
    }
}

Describe 'Convert-OFPath' {
    It 'menormalkan pemisah path ke pemisah platform' {
        $separator = [string][System.IO.Path]::DirectorySeparatorChar
        Convert-OFPath -Path 'artifacts/logs/out.csv' | Should -Be ('artifacts' + $separator + 'logs' + $separator + 'out.csv')
    }

    It 'mengembalikan string kosong tanpa error' {
        Convert-OFPath -Path '' | Should -Be ''
    }
}

Describe 'Resolve-OFCommand' {
    It 'menemukan perintah yang pasti ada pada platform ini' {
        $name = if (Test-OFWindows) { 'cmd' } else { 'sh' }
        $resolved = Resolve-OFCommand -Name $name
        $resolved.Found | Should -BeTrue
        $resolved.Path | Should -Not -BeNullOrEmpty
    }

    It 'melaporkan Found palsu untuk perintah yang tidak ada' {
        (Resolve-OFCommand -Name 'openforensic-perintah-tidak-ada-123').Found | Should -BeFalse
    }

    It 'memprioritaskan direktori lokal' {
        $directory = Join-Path (Get-OFTempDirectory -Create) ('bin-' + [guid]::NewGuid().ToString('N').Substring(0, 6))
        New-Item -ItemType Directory -Path $directory -Force | Out-Null
        try {
            $fileName = if (Test-OFWindows) { 'oftooluji.cmd' } else { 'oftooluji' }
            $filePath = Join-Path $directory $fileName
            Set-Content -LiteralPath $filePath -Value '# uji' -Encoding ascii
            $resolved = Resolve-OFCommand -Name 'oftooluji' -SearchPath @($directory)
            $resolved.Found | Should -BeTrue
            $resolved.Source | Should -Be 'local'
        } finally {
            Remove-Item -LiteralPath $directory -Recurse -Force -ErrorAction SilentlyContinue
        }
    }
}

Describe 'Get-OFInstallHint' {
    It 'memberi saran sesuai platform untuk exiftool' {
        $hint = Get-OFInstallHint -ToolId exiftool
        $hint | Should -Not -BeNullOrEmpty
        if (Test-OFWindows) {
            $hint | Should -Match 'winget'
        } else {
            $hint | Should -Match 'apt-get|dnf|pacman|brew'
        }
    }

    It 'memakai fallback untuk tool yang tidak dipetakan' {
        Get-OFInstallHint -ToolId 'tool-tidak-dikenal' -FallbackHint 'petunjuk katalog' | Should -Be 'petunjuk katalog'
    }

    It 'selalu mengembalikan string tidak kosong' {
        Get-OFInstallHint -ToolId 'tool-tidak-dikenal' | Should -Not -BeNullOrEmpty
    }
}

Describe 'Get-OFSecureStorageMode' {
    It 'memakai pbkdf2 di luar Windows' {
        $mode = Get-OFSecureStorageMode
        $mode | Should -BeIn @('dpapi', 'pbkdf2')
        if (-not (Test-OFWindows)) { $mode | Should -Be 'pbkdf2' }
    }
}

Describe 'Test-OFPlatformCompatibility' {
    It 'melaporkan matriks kemampuan yang lengkap' {
        $matrix = @(Test-OFPlatformCompatibility)
        $matrix.Count | Should -BeGreaterThan 10
        foreach ($feature in $matrix) {
            $feature.Feature | Should -Not -BeNullOrEmpty
            $feature.Supported | Should -BeOfType [bool]
            $feature.Notes | Should -Not -BeNullOrEmpty
        }
    }

    It 'menyatakan kemampuan inti didukung di semua platform' {
        $core = @(Test-OFPlatformCompatibility) | Where-Object { $_.Feature -match 'Alur kerja kasus' }
        $core.Supported | Should -BeTrue
    }

    It 'menandai DPAPI tidak didukung di luar Windows' {
        $dpapi = @(Test-OFPlatformCompatibility) | Where-Object { $_.Feature -match 'DPAPI' } | Select-Object -First 1
        if (-not (Test-OFWindows)) { $dpapi.Supported | Should -BeFalse }
    }
}

Describe 'Format-OFPlatformSummary' {
    It 'menghasilkan Markdown yang memuat sistem operasi' {
        $summary = Format-OFPlatformSummary
        $summary | Should -Match 'Lingkungan Pemeriksaan'
        $summary | Should -Match 'Sistem operasi'
    }

    It 'dapat menyertakan tabel matriks' {
        Format-OFPlatformSummary -IncludeMatrix | Should -Match '\| Kemampuan \| Didukung \| Catatan \|'
    }
}

Describe 'Portabilitas kode sumber' {
    BeforeAll {
        $script:RepoRoot = Split-Path -Parent $PSScriptRoot
        $script:SourceFiles = @(Get-ChildItem -LiteralPath $script:RepoRoot -Filter '*.psm1' -File) +
            @(Get-ChildItem -LiteralPath $script:RepoRoot -Filter '*.ps1' -File)
    }

    It 'tidak memakai path Windows yang di-hardcode' {
        $offenders = New-Object System.Collections.ArrayList
        foreach ($file in $script:SourceFiles) {
            $content = Get-Content -LiteralPath $file.FullName -Raw
            if ($content -match '[A-Za-z]:\\(Users|Windows|Program Files)') {
                [void]$offenders.Add($file.Name)
            }
        }
        $offenders -join ', ' | Should -BeNullOrEmpty
    }

    It 'tidak memakai Invoke-Expression' {
        $offenders = New-Object System.Collections.ArrayList
        foreach ($file in $script:SourceFiles) {
            $content = Get-Content -LiteralPath $file.FullName -Raw
            if ($content -match 'Invoke-Expression|(?<![\w-])iex(?![\w-])') {
                [void]$offenders.Add($file.Name)
            }
        }
        $offenders -join ', ' | Should -BeNullOrEmpty
    }

    It 'menyertakan launcher untuk Windows dan POSIX' {
        Test-Path -LiteralPath (Join-Path $script:RepoRoot 'openforensic.bat') | Should -BeTrue
        Test-Path -LiteralPath (Join-Path $script:RepoRoot 'openforensic.sh') | Should -BeTrue
        Test-Path -LiteralPath (Join-Path $script:RepoRoot 'setup_tools.ps1') | Should -BeTrue
        Test-Path -LiteralPath (Join-Path $script:RepoRoot 'setup_tools.sh') | Should -BeTrue
        Test-Path -LiteralPath (Join-Path $script:RepoRoot 'Dockerfile') | Should -BeTrue
    }
}
