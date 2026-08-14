#Requires -Version 5.1
<#
    Pester 5 - registry model AI milik pengguna.
    Tidak ada panggilan jaringan: hanya registrasi, pembacaan, dan penghapusan profil.
#>

BeforeAll {
    Import-Module (Join-Path (Split-Path -Parent $PSScriptRoot) 'OpenForensic.psd1') -Force -DisableNameChecking
    $script:TestModelName = 'pester-' + [Guid]::NewGuid().ToString('N').Substring(0, 6)
}

AfterAll {
    Remove-OFAiModel -Name $script:TestModelName -Confirm:$false -ErrorAction SilentlyContinue | Out-Null
}

Describe 'Get-OFAiModelPreset' {
    It 'menyediakan preset untuk provider populer' {
        $presets = @(Get-OFAiModelPreset)
        $presets.Count | Should -BeGreaterThan 5
        @($presets | Where-Object { $_.Preset -eq 'ollama' }).Count | Should -Be 1
        @($presets | Where-Object { $_.Preset -eq 'openrouter' }).Count | Should -Be 1
    }

    It 'hanya memakai protokol dasar yang diimplementasikan' {
        foreach ($preset in @(Get-OFAiModelPreset)) {
            $preset.BaseProvider | Should -BeIn @('openai', 'gemini', 'ollama')
        }
    }

    It 'menandai preset lokal sebagai Local' {
        (@(Get-OFAiModelPreset -Preset 'ollama')[0]).Local | Should -BeTrue
        (@(Get-OFAiModelPreset -Preset 'openai')[0]).Local | Should -BeFalse
    }
}

Describe 'Register-OFAiModel' {
    It 'mendaftarkan model kustom lalu menampilkannya di daftar' {
        Register-OFAiModel -Name $script:TestModelName -BaseProvider openai -Model 'model-uji' `
            -Endpoint 'https://ai.contoh.local/v1' -KeyEnvVar 'CONTOH_AI_KEY' -Force | Out-Null

        $entry = @(Get-OFAiModelList | Where-Object { $_.Name -eq $script:TestModelName })[0]
        $entry | Should -Not -BeNullOrEmpty
        $entry.BaseProvider | Should -Be 'openai'
        $entry.Model | Should -Be 'model-uji'
        $entry.Endpoint | Should -Be 'https://ai.contoh.local/v1'
        $entry.KeyEnvVar | Should -Be 'CONTOH_AI_KEY'
    }

    It 'menolak pendaftaran ganda tanpa -Force' {
        { Register-OFAiModel -Name $script:TestModelName -BaseProvider openai -Model 'lain' -Endpoint 'https://a.local/v1' } |
            Should -Throw
    }

    It 'mewajibkan endpoint untuk provider openai' {
        { Register-OFAiModel -Name 'pester-tanpa-endpoint' -BaseProvider openai -Model 'x' } | Should -Throw
    }

    It 'menolak endpoint yang bukan URL' {
        { Register-OFAiModel -Name 'pester-url-salah' -BaseProvider openai -Model 'x' -Endpoint 'bukan-url' } | Should -Throw
    }

    It 'tidak pernah menyimpan API key di berkas registry' {
        $registryPath = Join-Path (Split-Path -Parent $PSScriptRoot) '.ai_models.json'
        if (Test-Path -LiteralPath $registryPath) {
            $raw = Get-Content -LiteralPath $registryPath -Raw
            $raw | Should -Not -Match '"apiKey"'
            $raw | Should -Not -Match 'sk-[A-Za-z0-9]{20,}'
        }
    }
}

Describe 'Remove-OFAiModel' {
    It 'menghapus profil yang ada dan memperingatkan untuk yang tidak ada' {
        $name = 'pester-hapus-' + [Guid]::NewGuid().ToString('N').Substring(0, 6)
        Register-OFAiModel -Name $name -Preset ollama -Model 'llama3.1' -Force | Out-Null
        Remove-OFAiModel -Name $name -Confirm:$false | Should -BeTrue
        @(Get-OFAiModelList | Where-Object { $_.Name -eq $name }).Count | Should -Be 0
        Remove-OFAiModel -Name $name -Confirm:$false -WarningAction SilentlyContinue | Should -BeFalse
    }
}
