# OpenForensic

**Toolkit forensik digital lintas platform dengan alur kerja end-to-end dan AI assistance.**

Berjalan di **Windows, Linux, macOS, dan Docker**. Satu alur:
**KASUS -> BUKTI -> TOOL -> ARTEFAK -> TEMUAN -> TIMELINE + MITRE -> REPORT + IOC -> SEGEL INTEGRITAS**.
Semua state kasus hidup di satu berkas `cases/<CaseId>/case.json`, sehingga menu interaktif, CLI,
AI, dan test memakai kode dan data yang sama.

Versi: **0.5.0** | Runtime: PowerShell 7 (Windows/Linux/macOS) dan Windows PowerShell 5.1 | Lisensi: MIT

> Peringatan profesional: perangkat ini membantu pemeriksaan, bukan menggantikan pemeriksa.
> Setiap temuan (terutama yang dihasilkan AI) wajib diverifikasi manual sebelum dipakai
> sebagai dasar kesimpulan atau bukti hukum.

---

## Jalan di semua perangkat

| Cara | Cocok untuk | Perintah |
| --- | --- | --- |
| Windows native | Cakupan tool terluas (EZ Tools, DPAPI) | `.\setup_tools.ps1` lalu `.\openforensic.bat` |
| Linux / macOS native | Pemeriksa Unix dengan PowerShell 7 | `./setup_tools.sh` lalu `./openforensic.sh` |
| Docker | Semua OS, tanpa memasang apa pun | `docker compose run --rm openforensic` |

Cek kemampuan platform Anda kapan saja:

```powershell
Get-OFPlatform | Format-List
Test-OFPlatformCompatibility | Format-Table Feature, Supported, Notes -AutoSize
```

atau `./openforensic.sh doctor`. Detail perbedaan antar OS: [`docs/CROSS-PLATFORM.md`](docs/CROSS-PLATFORM.md).

---

## Kemampuan utama

| Area | Isi |
| --- | --- |
| Katalog tool | 39 tool DFIR/CTF di `tools.json` (memori, dokumen, PE, jaringan, log Windows, disk, stego, mobile, crack) dengan petunjuk pemasangan per OS |
| Alur kasus | Kasus, bukti berhash, chain of custody, eksekusi tool otomatis per tipe file, 31 detektor artefak, temuan berperingkat, report Markdown + HTML |
| Timeline | Timeline ternormalisasi lintas sumber, impor CSV Hayabusa/Chainsaw/MFTECmd/evtx_dump, ekspor CSV/JSON/Markdown |
| Threat intel | Pemetaan MITRE ATT&CK deterministik (plus MITRE ATLAS untuk prompt injection), ekspor IOC ke CSV/JSON/STIX 2.1/MISP |
| Integritas | Manifest SHA256 seluruh kasus, segel HMAC (DPAPI atau PBKDF2), snapshot versi tool, write-block lunak, allowlist hash, deduplikasi bukti, timeout per proses |
| AI | Multi provider, perencanaan tool, analisa korelasi, analisa mendalam berbasis timeline, report bernarasi, asisten interaktif, registry model AI milik pengguna |
| Lintas platform | Deteksi OS, direktori data sesuai standar tiap OS, resolusi executable, matriks kemampuan, installer POSIX, image Docker, CI 4 kombinasi OS/PowerShell |

---

## Instalasi

### Windows

```powershell
git clone https://github.com/stmarya/OpenForensic.git
cd OpenForensic
.\setup_tools.ps1
.\openforensic.bat
```

### Linux / macOS

```bash
git clone https://github.com/stmarya/OpenForensic.git
cd OpenForensic
chmod +x openforensic.sh setup_tools.sh
./setup_tools.sh
./openforensic.sh
```

### Docker (semua OS)

```bash
docker compose build
mkdir -p evidence cases
docker compose run --rm openforensic
```

Opsi installer Windows: `-SkipVolatility -SkipPython -SkipWinget -SkipDownload -IncludeOptional -IncludeHeavy -Only <id> -Force`.
Opsi installer POSIX: `--skip-python --skip-packages --skip-download --skip-pwsh --only <id> --list --yes`.
Setiap unduhan dicatat lengkap dengan SHA256 di `bin/_downloads.log`. Panduan lengkap: [`docs/INSTALL.md`](docs/INSTALL.md).

---

## Pemakaian

### Menu interaktif

23 pilihan: alur kerja kasus, timeline/IOC/integritas, AI assistance, dan utilitas.
Menu 8 menjalankan alur lengkap satu langkah; menu 17 adalah manajer model AI.

### CLI berbasis kasus

```powershell
# Kasus baru: semua tool yang cocok, AI, report, timeline, IOC, dan segel dalam satu perintah
.\case.ps1 -Path .\bukti\memory.raw, .\bukti\invoice.docm -CaseName "Insiden Phishing" `
          -Examiner "Nama Pemeriksa" -Classification confidential -Complete -UseAi -DeepAi -Seal

.\case.ps1 -List
.\case.ps1 -CaseId CASE-... -AddEvidence .\bukti\Security.evtx -Analyze
.\case.ps1 -CaseId CASE-... -Timeline -ExportTimeline Csv -ExportIoc Stix
.\case.ps1 -CaseId CASE-... -DeepAi -Report
.\case.ps1 -CaseId CASE-... -VerifyIntegrity     # exit code 3 bila integritas bermasalah
```

Di Linux/macOS: `./openforensic.sh case -List` (argumen identik).
Exit code: `0` sukses, `1` kesalahan tak terduga, `2` argumen/manifest bermasalah, `3` verifikasi integritas gagal.

### Modul PowerShell langsung

```powershell
Import-Module ./OpenForensic.psd1 -Force

$case = New-OFCase -Name "Insiden Ransomware" -Examiner "Pemeriksa" -Classification restricted
Add-OFCaseEvidence -Case $case -Path ./bukti/note.txt -Copy | Out-Null
Invoke-OFEvidenceAnalysis -Case $case -AllTools | Out-Null
Invoke-OFTimelineWorkflow -Case $case | Out-Null
Invoke-OFCompleteWorkflow -Case $case -UseAi
```

---

## AI assistance

Lima titik sentuh AI, semuanya memakai data kasus yang sama:

1. `Invoke-OFAiToolPlan` - AI mengusulkan tool berikutnya, hanya dari id yang benar-benar ada di katalog.
2. `Invoke-OFAiGuidedAnalysis` - loop rencana -> persetujuan pemeriksa -> eksekusi.
3. `Invoke-OFAiCaseAnalysis` - korelasi artefak menjadi temuan, verdict, dan ringkasan eksekutif.
4. `Invoke-OFAiDeepAnalysis` - analisa mendalam memakai timeline, pemetaan MITRE, dan status integritas.
5. `Start-OFAiAssistant` - sesi interaktif (`/plan`, `/run`, `/analyze`, `/report`, `/findings`, `/evidence`).

Pengaman AI: persetujuan eksplisit sebelum data bukti keluar dari mesin, redaksi otomatis data
sensitif, pemagaran data bukti dengan penanda UNTRUSTED untuk memitigasi prompt injection, dan
pembatasan aksi hanya pada tool yang tersedia. Untuk kasus `restricted`, gunakan model lokal
(Ollama / LM Studio / vLLM) agar bukti tidak pernah meninggalkan mesin.

### Menambahkan model AI sendiri

```powershell
Get-OFAiModelPreset                       # 11 preset siap pakai

Register-OFAiModel -Name kerja -Preset openrouter -Model 'anthropic/claude-3.5-sonnet'
$env:OPENROUTER_API_KEY = '<api key Anda>'

Register-OFAiModel -Name internal -BaseProvider openai `
    -Endpoint 'https://ai.perusahaan.local/v1' -Model 'qwen2.5-72b-instruct' `
    -KeyEnvVar PERUSAHAAN_AI_KEY

Register-OFAiModel -Name lokal -Preset ollama -Model llama3.1

Use-OFAiModel  -Name kerja
Test-OFAiModel -Name kerja
Get-OFAiModelList
```

Preset: `openai`, `azure`, `openrouter`, `groq`, `together`, `deepseek`, `mistral`, `gemini`,
`lmstudio`, `vllm`, `ollama`. Profil disimpan di `.ai_models.json` (tidak di-commit) dan **API key
tidak pernah ditulis ke berkas** - hanya nama variabel environment-nya.
Detail: [`docs/AI-MODELS.md`](docs/AI-MODELS.md).

---

## Integritas dan reproduktifitas

```powershell
Invoke-OFCaseSealWorkflow -Case $case                      # Windows: DPAPI
Invoke-OFCaseSealWorkflow -Case $case -Passphrase $secure  # lintas OS: PBKDF2
Get-OFIntegrityStatus -Case $case | Format-OFIntegritySummary
```

Detail: [`docs/INTEGRITY.md`](docs/INTEGRITY.md).

---

## Timeline, MITRE, dan IOC

```powershell
Invoke-OFTimelineWorkflow -Case $case -IncludeExaminerActions
Get-OFTimeline -Case $case -MinSeverity medium -Deduplicate | Format-Table
Get-OFMitreSummary -Case $case
Export-OFTimeline -Case $case -Format Markdown
Export-OFCaseIoc -Case $case -Format Stix
```

Detail: [`docs/TIMELINE.md`](docs/TIMELINE.md).

---

## Dokumentasi

- [`docs/CROSS-PLATFORM.md`](docs/CROSS-PLATFORM.md) - menjalankan di Windows, Linux, macOS, dan Docker
- [`docs/INSTALL.md`](docs/INSTALL.md) - installer, dependensi, pemasangan manual
- [`docs/TOOLS.md`](docs/TOOLS.md) - katalog 39 tool dan cara menambah tool baru
- [`docs/WORKFLOW.md`](docs/WORKFLOW.md) - alur kerja kasus end-to-end
- [`docs/AI.md`](docs/AI.md) - lapisan AI dan pengamanannya
- [`docs/AI-MODELS.md`](docs/AI-MODELS.md) - registry model AI milik pengguna
- [`docs/INTEGRITY.md`](docs/INTEGRITY.md) - manifest, segel, allowlist, reproduktifitas
- [`docs/TIMELINE.md`](docs/TIMELINE.md) - timeline, MITRE ATT&CK, ekspor IOC
- [`SECURITY.md`](SECURITY.md) | [`CONTRIBUTING.md`](CONTRIBUTING.md) | [`CHANGELOG.md`](CHANGELOG.md)

---

## Struktur proyek

```
OpenForensic.psd1              manifest modul (0.5.0, 103 fungsi terekspor)
OpenForensic.psm1              inti: katalog tool, eksekusi aman, hash, tipe file, report
OpenForensic.Platform.psm1     kompatibilitas lintas OS: deteksi platform, path, executable
OpenForensic.Workflow.psm1     kasus, bukti, artefak, temuan, report
OpenForensic.Ai.psm1           provider AI, perencanaan, analisa, asisten
OpenForensic.Integrity.psm1    manifest, segel, versi tool, allowlist, dedup, timeout
OpenForensic.Timeline.psm1     timeline ternormalisasi, MITRE ATT&CK, ekspor IOC
OpenForensic.Models.psm1       registry model AI pengguna, analisa mendalam, alur lengkap
menu.ps1 / case.ps1 / run.ps1  antarmuka menu dan CLI
openforensic.bat               launcher Windows
openforensic.sh                launcher Linux dan macOS (menu, case, run, doctor)
setup_tools.ps1                installer Windows
setup_tools.sh                 installer Linux dan macOS
Dockerfile / docker-compose.yml image lintas platform + Ollama lokal opsional
tools.json                     katalog 39 tool (schemaVersion 2)
tests/                         Pester test seluruh modul + fixtures bukti sintetis
```

---

## Keamanan

- Tidak ada `Invoke-Expression`; seluruh proses dijalankan dengan argumen berbentuk array sehingga
  nama berkas bukti tidak dapat dipakai untuk command injection. CI menjaga pola ini.
- API key dienkripsi DPAPI (Windows) atau dibaca dari variabel environment, tidak pernah plaintext di repo.
- Data kasus (`cases/`, `artifacts/`, `reports/`) dan konfigurasi lokal tidak pernah di-commit.
- TLS 1.2 dipaksa untuk semua panggilan jaringan; bukti di kontainer di-mount read-only.

Laporkan kerentanan melalui [`SECURITY.md`](SECURITY.md).

---

## Lisensi

MIT - lihat [`LICENSE`](LICENSE).
