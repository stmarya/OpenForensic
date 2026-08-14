# Changelog

Format mengikuti [Keep a Changelog](https://keepachangelog.com/), versioning [SemVer](https://semver.org/).

## [0.2.0] - 2026-08-14

### Security

- **Menghapus `Invoke-Expression`** dari alur eksekusi tool. Semua proses eksternal kini
  dijalankan lewat `Invoke-OFTool` dengan argumen berupa array, menutup celah command
  injection melalui nama file bukti.
- **API key tidak lagi plaintext.** Disimpan terenkripsi DPAPI di `.ai_config`, atau dibaca
  dari `$env:OPENFORENSIC_AI_KEY` / `$env:GEMINI_API_KEY`. Key dikirim via header
  `x-goog-api-key`, bukan query string URL.
- **Konfirmasi wajib** sebelum mengirim isi report ke API eksternal, dengan peringatan
  kerahasiaan bukti.
- **Mitigasi prompt injection**: isi report dibungkus delimiter dan ditandai sebagai data
  tak terpercaya di prompt.
- Menghapus path pribadi (`C:\Users\...`) dari dokumentasi.

### Fixed

- Installer kini mendeteksi direktori Scripts Python melalui `sysconfig.get_path('scripts')`
  **dan** `site.USER_BASE`, sehingga `vol.exe` dkk. tidak lagi gagal ditemukan pada instalasi
  non-`--user` maupun venv.
- Kegagalan `git`/`pip`/`winget` kini terdeteksi lewat pemeriksaan `$LASTEXITCODE`.
- Perpindahan direktori pada installer memakai `Push-Location`/`Pop-Location` dalam `try/finally`.
- Input menu non-numerik tidak lagi membuat script crash (`Read-OFChoice` dengan `TryParse`).
- ID paket winget dibuat eksplisit (`OliverBetz.ExifTool`, `7zip.7zip`) agar tidak silent-fail.
- Encoding report dipaksa UTF-8 tanpa BOM secara konsisten.
- API key multi-baris tidak lagi merusak permintaan HTTP.

### Added

- Modul `OpenForensic.psm1` + manifest, katalog `tools.json`, `run.ps1`, `openforensic.bat`.
- Hashing bukti MD5/SHA1/SHA256 otomatis dengan verifikasi ulang setelah analisis.
- Deteksi tipe file via magic bytes + penandaan `TypeMismatch` untuk ekstensi palsu.
- Report JSON berdampingan dengan report teks.
- Tool built-in `strings` (ASCII + UTF-16LE) dengan filter regex.
- Cakupan tool baru: `rtfobj`, `oleobj`, `decompyle3`, `binwalk`, `7z`, `tshark`, `steghide`, `zsteg`.
- Pester tests, PSScriptAnalyzer settings, GitHub Actions CI, Dependabot.
- LICENSE (MIT), SECURITY.md, CONTRIBUTING.md, CHANGELOG.md, docs/TOOLS.md.

### Changed

- Penamaan disatukan menjadi **OpenForensic** (Kan9Ch3k tetap sebagai codename banner).
- `kan9ch3k.bat` dan `kan9ch3k_menu.ps1` digantikan `openforensic.bat` + `menu.ps1` + modul.

## [0.1.0] - 2026-08-14

- Rilis awal: Kan9Ch3k Toolkit (batch launcher, menu PowerShell, installer, catatan tool).
