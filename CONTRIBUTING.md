# Kontribusi

Terima kasih sudah tertarik membantu OpenForensic / Kan9Ch3k.

## Setup

```powershell
git clone https://github.com/stmarya/OpenForensic.git
cd OpenForensic
.\setup_tools.ps1 -IncludeOptional
Install-Module Pester, PSScriptAnalyzer -Scope CurrentUser -Force
```

## Sebelum membuat PR

```powershell
Invoke-ScriptAnalyzer -Path . -Recurse -Settings PSGallery   # harus bersih dari Error/Warning
Invoke-Pester .\tests                                       # harus hijau
```

## Aturan kode

- Target **PowerShell 5.1** (jangan pakai `??`, ternary `? :`, atau `-AsHashtable`).
- `Set-StrictMode -Version Latest` di setiap script/module.
- **Dilarang** `Invoke-Expression`, `iex`, atau string interpolation untuk membangun command line.
  Gunakan `& $exe @argArray`.
- Selalu `-LiteralPath` untuk path file bukti (nama file bisa berisi `[ ]`, `` ` ``, `$`).
- Cek `$LASTEXITCODE` setelah setiap native command.
- Fungsi publik memakai prefix `OF` (mis. `Get-OFFileType`) dan `[CmdletBinding()]`.
- Tambahkan comment-based help pada fungsi publik baru.

## Menambah tool

Cukup tambahkan entri di [`tools.json`](tools.json) — jangan hardcode di dalam module.
Wajib menyertakan: `id`, `name`, `category`, `command`, `kinds`, `args`, `install`.
Sertakan juga baris baru di tabel README dan test di `tests/`.

## Menambah deteksi tipe file

Tambahkan signature di `Get-OFFileType` (`OpenForensic.psm1`) beserta unit test
yang membangun byte header sintetis. Jangan mengandalkan ekstensi.

## Commit

Gunakan [Conventional Commits](https://www.conventionalcommits.org/):
`feat:`, `fix:`, `docs:`, `refactor:`, `test:`, `chore:`, `security:`.

## Branch

PR ditujukan ke `dev`. Rilis di-merge dari `dev` ke `main` dan diberi tag `vX.Y.Z`.
