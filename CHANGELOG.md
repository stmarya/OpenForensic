# Changelog

Semua perubahan penting pada proyek ini dicatat di file ini.
Format mengikuti [Keep a Changelog](https://keepachangelog.com/id/1.1.0/)
dan proyek ini memakai [Semantic Versioning](https://semver.org/lang/id/).

## [0.5.0] - 2026-08-15

Rilis kompatibilitas lintas platform: OpenForensic kini resmi berjalan di Windows, Linux,
macOS, dan di dalam kontainer.

### Ditambahkan

- **`OpenForensic.Platform.psm1`** (13 fungsi) sebagai lapisan kompatibilitas:
  - `Get-OFPlatform`, `Test-OFWindows`, `Test-OFInteractive`, `Test-OFAdministrator`
  - `Get-OFDataRoot` (menghormati `OPENFORENSIC_HOME`, `%LOCALAPPDATA%`,
    `~/Library/Application Support`, dan `XDG_DATA_HOME`), `Get-OFTempDirectory`, `Convert-OFPath`
  - `Resolve-OFCommand` (resolusi executable lintas OS termasuk sufiks Windows)
  - `Get-OFPackageManager` dan `Get-OFInstallHint` (saran pemasangan per OS: winget, apt,
    dnf, pacman, zypper, apk, brew, pip, gem)
  - `Get-OFSecureStorageMode`, `Test-OFPlatformCompatibility`, `Format-OFPlatformSummary`
- **`setup_tools.sh`**: installer POSIX untuk Linux dan macOS (deteksi package manager,
  pemasangan PowerShell 7, paket pip forensik, unduhan rilis Hayabusa/Chainsaw/Stegseek,
  rule YARA, pencatatan SHA256 di `bin/_downloads.log`, tanpa `curl | bash`).
- **`openforensic.sh`**: launcher POSIX dengan mode `menu`, `case`, `run`, dan `doctor`.
- **`Dockerfile`, `docker-compose.yml`, `.dockerignore`**: image siap pakai berbasis
  `mcr.microsoft.com/powershell` dengan Volatility 3, oletools, capa, FLOSS, YARA, ExifTool,
  tshark, ClamAV, SQLite, steghide, john, pngcheck, testdisk, dan Pester. Bukti di-mount
  read-only, hasil kasus tetap di host, plus profil opsional `ai-local` untuk Ollama.
- **Workflow CI `cross-platform`**: matriks Windows PowerShell 5.1, PowerShell 7 di Windows,
  Ubuntu, dan macOS; ditambah job `shellcheck` untuk script POSIX dan job build image Docker.
- **Fixtures bukti sintetis** di `tests/fixtures/` (strings ber-IOC, contoh prompt injection,
  CSV Hayabusa, CSV MFTECmd, contoh allowlist hash) untuk regression test yang stabil.
- **`tests/OpenForensic.Platform.Tests.ps1`**: test deteksi platform, direktori data, normalisasi
  path, resolusi perintah, saran pemasangan, mode penyimpanan rahasia, matriks kemampuan, serta
  guard portabilitas (tanpa path Windows hardcoded, tanpa `Invoke-Expression`, launcher lengkap).
- **`docs/CROSS-PLATFORM.md`**: tiga cara pemakaian, tabel perbedaan kemampuan per OS,
  penyesuaian praktis di luar Windows, daftar variabel environment, dan aturan kompatibilitas
  untuk kontributor.

### Diubah

- Manifest `OpenForensic.psd1` versi 0.5.0: enam nested module dan 103 fungsi terekspor,
  deskripsi dan tag diperbarui menjadi lintas platform.
- README ditulis ulang dengan jalur pemasangan Windows, Linux/macOS, dan Docker.

### Catatan platform

- Segel DPAPI dan penyimpanan API key DPAPI hanya tersedia di Windows. Di Linux dan macOS
  gunakan segel mode passphrase (PBKDF2) dan variabel environment untuk API key.
- Dialog pemilih berkas grafis hanya ada di Windows; di luar Windows gunakan argumen CLI.
- Tool khusus Windows (MFTECmd, RegRipper, EZ Tools) tetap Windows-only; alternatif lintas
  platform dan jalur impor CSV dijelaskan di `docs/CROSS-PLATFORM.md`.

## [0.4.0] - 2026-08-15

### Ditambahkan

- **Lapisan integritas dan reproduktifitas bukti** (`OpenForensic.Integrity.psm1`, 17 fungsi):
  - `New-OFCaseManifest` / `Test-OFCaseManifest`: manifest SHA256 seluruh berkas kasus dengan
    deteksi berkas dimodifikasi, hilang, dan ditambahkan.
  - `New-OFCaseSeal` / `Test-OFCaseSeal`: segel HMAC-SHA256 atas manifest, kunci DPAPI
    (satu mesin) atau PBKDF2 120.000 iterasi (lintas mesin).
  - `Update-OFCaseToolVersions` / `Get-OFToolVersion`: snapshot versi tool untuk reproduktifitas.
  - `Protect-OFEvidenceFile` / `Test-OFEvidenceLock`: write-block lunak dan deteksi berkas terkunci.
  - `Get-OFHashAllowlist`, `Test-OFHashAllowlist`, `Add-OFHashToAllowlist`, `Import-OFHashAllowlist`:
    allowlist hash untuk menekan positif palsu.
  - `Test-OFEvidenceDuplicate`: deduplikasi bukti berbasis SHA256.
  - `Invoke-OFProcessWithTimeout`: eksekusi proses dengan batas waktu sehingga tool yang
    menggantung tidak membekukan pemeriksaan.
  - `Get-OFIntegrityStatus` / `Format-OFIntegritySummary` / `Invoke-OFCaseSealWorkflow`.
- **Super-timeline, MITRE ATT&CK, dan ekspor IOC** (`OpenForensic.Timeline.psm1`, 11 fungsi):
  - Skema kejadian ternormalisasi `timestamp | source | actor | action | target | detail |
    severity | evidenceId | mitre` untuk semua sumber.
  - `Import-OFTimelineCsv` dengan deteksi kolom waktu otomatis (Hayabusa, Chainsaw, MFTECmd,
    evtx_dump, CSV umum), `Import-OFTimelineFromCase`, `Invoke-OFTimelineWorkflow`.
  - `Get-OFTimeline` (filter waktu/sumber/severity + deduplikasi), `Export-OFTimeline`
    (CSV, JSON, Markdown).
  - `Update-OFCaseMitre` / `Get-OFMitreTechnique` / `Get-OFMitreSummary`: pemetaan ATT&CK
    deterministik dari detektor artefak dan dari teknik yang disebut langsung oleh tool
    (capa, Sigma/Hayabusa, Chainsaw). Prompt injection dipetakan ke MITRE ATLAS `AML.T0051`.
  - `Export-OFCaseIoc`: ekspor IOC ke CSV, JSON, STIX 2.1 bundle, dan MISP Event.
- **Registry model AI milik pengguna** (`OpenForensic.Models.psm1`, 11 fungsi):
  - `Register-OFAiModel`, `Get-OFAiModelList`, `Use-OFAiModel`, `Remove-OFAiModel`,
    `Test-OFAiModel`, `Test-OFAiModelAll`, `Initialize-OFAiModelDefaults`.
  - 11 preset: OpenAI, Azure OpenAI, OpenRouter, Groq, Together, DeepSeek, Mistral, Gemini,
    LM Studio, vLLM, Ollama. API key tidak pernah disimpan di registry, hanya nama variabel
    environment-nya.
  - `Get-OFAiCaseContext` dan `Invoke-OFAiDeepAnalysis`: analisis AI yang memakai timeline,
    pemetaan MITRE, dan status integritas sebagai konteks; keluaran memuat kronologi naratif,
    penilaian dampak, catatan integritas, dan kesenjangan bukti.
  - `Invoke-OFCompleteWorkflow`: satu perintah untuk analisis -> timeline -> MITRE -> versi
    tool -> AI -> report/timeline/IOC -> manifest + segel.
- Dokumentasi baru: `docs/INTEGRITY.md`, `docs/TIMELINE.md`, `docs/AI-MODELS.md`.
- Test suite baru untuk integritas (manifest, segel, allowlist, dedup, timeout), timeline
  (normalisasi waktu, deteksi kolom, MITRE, ekspor IOC/STIX/MISP), dan registry model AI.

### Diubah

- `case.ps1` mendapat `-Complete`, `-CompleteExisting`, `-Timeline`, `-ExportTimeline`,
  `-ExportIoc`, `-Seal`, `-SealPassphrase`, `-VerifyIntegrity`, `-DeepAi`, `-Model`,
  `-ListModels`, dan `-TestModels`. Penambahan bukti kini melewati duplikat secara otomatis.
  `-VerifyIntegrity` mengembalikan exit code 3 bila integritas bermasalah.
- `menu.ps1` diperluas menjadi 23 pilihan: alur lengkap satu langkah, timeline dan MITRE,
  ekspor IOC, integritas kasus, AI analisa mendalam, dan manajer model AI.
- Manifest `OpenForensic.psd1` versi 0.4.0: lima nested module dan 90 fungsi terekspor.
- `.gitignore` menutup `.ai_models.json` serta ekspor timeline/IOC yang tercecer di root.

### Catatan keterbatasan

- Eksekusi tool paralel belum diaktifkan: mutasi state kasus dari beberapa runspace berisiko
  merusak `case.json`. Batas waktu per tool sudah tersedia lewat `Invoke-OFProcessWithTimeout`.
- Segel DPAPI hanya dapat diverifikasi pada akun dan mesin yang sama; gunakan mode passphrase
  untuk penyerahan bukti lintas pihak.
- API native Anthropic belum didukung langsung karena tidak OpenAI-compatible; gunakan
  OpenRouter atau proxy OpenAI-compatible.

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
