# Changelog

Semua perubahan penting pada proyek ini dicatat di file ini.
Format mengikuti [Keep a Changelog](https://keepachangelog.com/id/1.1.0/)
dan proyek ini memakai [Semantic Versioning](https://semver.org/lang/id/).

## [0.3.0] - 2026-08-14

### Ditambahkan

- **Alur kerja end-to-end berbasis kasus** (`OpenForensic.Workflow.psm1`): kasus, bukti,
  eksekusi tool, artefak, temuan, timeline, chain of custody, dan report tersimpan dalam
  satu state `cases/<CaseId>/case.json`.
  - `New-OFCase`, `Get-OFCase`, `Get-OFCaseList`, `Save-OFCase`
  - `Add-OFCaseEvidence` (hash MD5/SHA1/SHA256, salinan terverifikasi, deteksi tipe)
  - `Invoke-OFEvidenceAnalysis` (pemilihan tool otomatis per tipe file + log per eksekusi)
  - `Find-OFArtifact` dengan 31 detektor artefak (IOC, kredensial, persistence, LOLBin,
    makro, PDF aktif, flag CTF, indikasi prompt injection)
  - `Add-OFCaseFinding`, `Get-OFCaseFinding`, `Add-OFCaseTimelineEntry`, `Get-OFCaseSummary`
  - `Export-OFCaseReport` (Markdown + HTML, 9 bagian)
  - `Invoke-OFWorkflow` sebagai orkestrator satu perintah
- **Lapisan AI assistance** (`OpenForensic.Ai.psm1`):
  - Multi provider: Gemini, OpenAI-compatible, dan Ollama lokal (`Set-OFAiConfig`)
  - `Invoke-OFAiToolPlan`: AI memilih tool berikutnya, hanya dari id yang ada di katalog
  - `Invoke-OFAiGuidedAnalysis`: loop rencana-persetujuan-eksekusi
  - `Invoke-OFAiCaseAnalysis`: korelasi artefak menjadi temuan + verdict + ringkasan
  - `New-OFAiCaseReport`: analisa lalu ekspor report bernarasi
  - `Start-OFAiAssistant`: sesi interaktif dengan aksi yang harus disetujui pemeriksa
  - `Protect-OFEvidenceText`: redaksi email, token, AWS key, JWT, private key
- **`case.ps1`**: CLI alur kerja end-to-end (`-Path`, `-List`, `-CaseId`, `-UseAi`, `-GuidedAi`).
- **Katalog tool v2**: 39 tool (dari 15) dengan field `phase` dan `aiHint`. Tambahan antara
  lain YARA, capa, FLOSS, ClamAV, pdfid, pdf-parser, oledump, zipdump, msoffcrypto-tool,
  base64dump, evtx_dump, Hayabusa, Chainsaw, MFTECmd, RegRipper, bulk_extractor, PhotoRec,
  Stegseek, pngcheck, SQLite3, jadx, rizin, capinfos, John the Ripper.
- Dokumentasi baru: `docs/WORKFLOW.md` dan `docs/AI.md`.
- Test suite untuk workflow, detektor artefak, dan lapisan AI.

### Diubah

- `menu.ps1` menjadi menu berbasis kasus (17 pilihan) dengan bagian AI terpisah; menu
  tetap tipis karena seluruh logika ada di modul.
- Manifest `OpenForensic.psd1` versi 0.3.0 dengan `NestedModules` dan 51 fungsi terekspor.
- `.gitignore` menutup `cases/`, `artifacts/`, `rules/`, `wordlists/`, dan `.ai_settings.json`.

## [0.2.0] - 2026-08-14

### Keamanan

- Menghapus `Invoke-Expression` pada eksekusi tool; semua proses dijalankan dengan operator
  panggilan dan argumen berbentuk array sehingga nama file bukti tidak bisa dipakai untuk
  command injection. CI menjaga agar pola ini tidak kembali.
- API key tidak lagi disimpan plaintext; dienkripsi DPAPI atau dibaca dari environment variable.
- API key dipindahkan dari query string URL ke header `x-goog-api-key`, TLS 1.2 dipaksa.
- Persetujuan eksplisit sebelum data bukti dikirim ke layanan AI eksternal.
- Data bukti dipagari penanda UNTRUSTED untuk memitigasi prompt injection terhadap LLM.

### Ditambahkan

- Modul `OpenForensic.psm1` + manifest, katalog `tools.json`, `run.ps1`, `openforensic.bat`.
- Hash bukti MD5/SHA1/SHA256 dengan verifikasi integritas setelah analisis.
- Deteksi tipe file via magic bytes (24 signature) termasuk deteksi ekstensi palsu.
- Mode Magic Triage, report ganda TXT + JSON, `Invoke-OFStrings` (ASCII + UTF-16LE).
- CI GitHub Actions: validasi katalog, PSScriptAnalyzer, guard `Invoke-Expression`, Pester.
- `LICENSE` (MIT), `SECURITY.md`, `CONTRIBUTING.md`, `docs/TOOLS.md`.

### Diperbaiki

- Crash pada input non-numerik di menu, exit code native tool yang diabaikan,
  `Set-Location` tanpa `try/finally`, deteksi direktori Scripts Python pada installer,
  identifikasi paket ExifTool pada winget, encoding output report yang tidak konsisten,
  dan path pribadi yang ter-hardcode.

## [0.1.0] - 2026-08-13

### Ditambahkan

- Rilis awal sebagai Kan9Ch3k Toolkit: menu PowerShell, integrasi Volatility 3, oletools,
  uncompyle6, ExifTool, dan analisis LLM sederhana.
