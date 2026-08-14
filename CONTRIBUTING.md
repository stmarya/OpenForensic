# Contributing

## Setup

```powershell
git clone https://github.com/stmarya/OpenForensic.git
cd OpenForensic
Install-Module PSScriptAnalyzer, Pester -Scope CurrentUser -Force -SkipPublisherCheck
```

## Sebelum membuka PR

```powershell
Invoke-ScriptAnalyzer -Path . -Recurse -Settings .\PSScriptAnalyzerSettings.psd1
Invoke-Pester -Path .\tests
```

Keduanya harus bersih (tanpa severity Error). CI menjalankan hal yang sama di `windows-latest`.

## Aturan kode

- Setiap script diawali `#Requires -Version 5.1` dan `Set-StrictMode -Version Latest`.
- **Dilarang** `Invoke-Expression`, string interpolation untuk membangun command line, atau
  penyimpanan secret dalam plaintext.
- Eksekusi proses eksternal selalu melalui `Invoke-OFTool` dengan `-Arguments` berupa array.
- Input pengguna numerik divalidasi dengan `Read-OFChoice` (tanpa cast `[int]` langsung).
- Gunakan verb-noun standar PowerShell dengan prefiks `OF` (contoh: `Get-OFFileType`).

## Menambah tool baru

Tambahkan entri di `tools.json`; tidak perlu menyentuh `menu.ps1`. Field wajib:
`id`, `name`, `description`, `category`, `executable`, `source` (`bin`/`path`/`builtin`),
`builtin`, `extensions`, `kinds`, `argTemplate`, `requiresPlugin`, `plugins`,
`triage`, `triageArgs`, `dialogFilter`, `installHint`.

Placeholder yang tersedia di `argTemplate`/`triageArgs`: `{file}` dan `{plugin}`.
Token yang menjadi kosong setelah substitusi otomatis dibuang.

## Commit

Gunakan Conventional Commits: `feat:`, `fix:`, `docs:`, `refactor:`, `test:`, `chore:`.
