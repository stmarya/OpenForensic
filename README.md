# OpenForensic

**Toolkit forensik digital berbasis PowerShell dengan alur kerja end-to-end dan AI assistance.**

Satu alur: **KASUS -> BUKTI -> TOOL -> ARTEFAK -> TEMUAN -> TIMELINE + MITRE -> REPORT + IOC -> SEGEL INTEGRITAS**.
Semua state kasus hidup di satu berkas `cases/<CaseId>/case.json`, sehingga menu interaktif, CLI,
AI, dan test memakai kode dan data yang sama.

Versi: **0.4.0** | Platform: Windows (PowerShell 5.1) dan PowerShell 7 (Core) | Lisensi: MIT

> Peringatan profesional: perangkat ini membantu pemeriksaan, bukan menggantikan pemeriksa.
> Setiap temuan (terutama yang dihasilkan AI) wajib diverifikasi manual sebelum dipakai
> sebagai dasar kesimpulan atau bukti hukum.

---

## Kemampuan utama

| Area | Isi |
| --- | --- |
| Katalog tool | 39 tool DFIR/CTF terdaftar di `tools.json` (memori, dokumen, PE, jaringan, log Windows, disk, stego, mobile, crack) |
| Alur kasus | Kasus, bukti berhash, chain of custody, eksekusi tool otomatis per tipe file, 31 detektor artefak, temuan berperingkat, report Markdown + HTML |
| Timeline | Timeline ternormalisasi lintas sumber, impor CSV Hayabusa/Chainsaw/MFTECmd/evtx_dump, ekspor CSV/JSON/Markdown |
| Threat intel | Pemetaan MITRE ATT&CK deterministik (plus MITRE ATLAS untuk prompt injection), ekspor IOC ke CSV/JSON/STIX 2.1/MISP |
| Integritas | Manifest SHA256 seluruh kasus, segel HMAC (DPAPI atau PBKDF2), snapshot versi tool, write-block lunak, allowlist hash, deduplikasi bukti, timeout per proses |
| AI | Multi provider, perencanaan tool, analisa korelasi, analisa mendalam berbasis timeline, report bernarasi, asisten interaktif, **registry model AI milik pengguna** |

---

## Instalasi cepat

```powershell
git clone https://github.com/stmarya/OpenForensic.git
cd OpenForensic

# Pasang tool pihak ketiga (lihat docs/INSTALL.md untuk opsi lengkap)
.\setup_tools.ps1

# Menu interaktif
.\openforensic.bat
```

Opsi installer: `-SkipVolatility -SkipPython -SkipWinget -SkipDownload -IncludeOptional -IncludeHeavy -Only <id> -Force`.
Setiap unduhan dicatat lengkap dengan SHA256 di `bin/_downloads.log`.

---

## Pemakaian

### Menu interaktif

```powershell
.\openforensic.bat
```

23 pilihan, terbagi menjadi alur kerja kasus, timeline/IOC/integritas, AI assistance, dan utilitas.
Menu 8 menjalankan alur lengkap satu langkah; menu 17 adalah manajer model AI.

### CLI berbasis kasus

```powershell
# Kasus baru, semua tool yang cocok, AI, report, timeline, IOC, dan segel dalam satu perintah
.\case.ps1 -Path .\bukti\memory.raw, .\bukti\invoice.docm -CaseName "Insiden Phishing" `
          -Examiner "Nama Pemeriksa" -Classification confidential -Complete -UseAi -DeepAi -Seal

# Daftar kasus
.\case.ps1 -List

# Lanjutkan kasus yang ada
.\case.ps1 -CaseId CASE-20260815-093000-insiden-phishing -AddEvidence .\bukti\Security.evtx -Analyze
.\case.ps1 -CaseId CASE-... -Timeline -ExportTimeline Csv -ExportIoc Stix
.\case.ps1 -CaseId CASE-... -DeepAi -Report
.\case.ps1 -CaseId CASE-... -VerifyIntegrity     # exit code 3 bila integritas bermasalah
```

Exit code: `0` sukses, `1` kesalahan tak terduga, `2` argumen/manifest bermasalah, `3` verifikasi integritas gagal.

### Modul PowerShell langsung

```powershell
Import-Module .\OpenForensic.psd1 -Force

$case = New-OFCase -Name "Insiden Ransomware" -Examiner "Pemeriksa" -Classification restricted
Add-OFCaseEvidence -Case $case -Path .\bukti\note.txt -Copy | Out-Null
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
4. `Invoke-OFAiDeepAnalysis` - analisa mendalam memakai timeline, pemetaan MITRE, dan status integritas;
   menghasilkan kronologi naratif, penilaian dampak, catatan integritas, dan kesenjangan bukti.
5. `Start-OFAiAssistant` - sesi interaktif (`/plan`, `/run`, `/analyze`, `/report`, `/findings`, `/evidence`).

Pengaman AI: persetujuan eksplisit sebelum data bukti keluar dari mesin, redaksi otomatis data sensitif
(email, token, AWS key, JWT, private key), pemagaran data bukti dengan penanda UNTRUSTED untuk memitigasi
prompt injection, dan pembatasan aksi hanya pada tool yang tersedia. Untuk kasus `restricted`, gunakan
model lokal (Ollama / LM Studio / vLLM) agar bukti tidak pernah meninggalkan mesin.

### Menambahkan model AI sendiri

```powershell
# Lihat preset yang tersedia
Get-OFAiModelPreset

# Daftarkan dari preset
Register-OFAiModel -Name kerja -Preset openrouter -Model 'anthropic/claude-3.5-sonnet'
$env:OPENROUTER_API_KEY = '<api key Anda>'

# Atau endpoint milik sendiri / on-premise
Register-OFAiModel -Name internal -BaseProvider openai `
    -Endpoint 'https://ai.perusahaan.local/v1' -Model 'qwen2.5-72b-instruct' `
    -KeyEnvVar PERUSAHAAN_AI_KEY

# Model lokal penuh untuk bukti sensitif
Register-OFAiModel -Name lokal -Preset ollama -Model llama3.1

Use-OFAiModel -Name kerja      # aktifkan
Test-OFAiModel -Name kerja     # uji koneksi + latensi (tanpa mengirim data bukti)
Get-OFAiModelList              # lihat semua profil dan kesiapan API key
```

Preset bawaan: `openai`, `azure`, `openrouter`, `groq`, `together`, `deepseek`, `mistral`, `gemini`,
`lmstudio`, `vllm`, `ollama`. Profil disimpan di `.ai_models.json` (tidak di-commit) dan **API key tidak
pernah ditulis ke berkas** - hanya nama variabel environment-nya. Detail: [`docs/AI-MODELS.md`](docs/AI-MODELS.md).

---

## Integritas dan reproduktifitas

```powershell
Invoke-OFCaseSealWorkflow -Case $case                      # versi tool -> manifest -> segel -> verifikasi
Get-OFIntegrityStatus -Case $case | Format-OFIntegritySummary
```

- `case.manifest.sha256` mencatat hash dan ukuran seluruh berkas kasus.
- `case.seal.json` menyegel manifest dengan HMAC-SHA256; kunci lewat DPAPI (mesin ini) atau PBKDF2
  120.000 iterasi (passphrase, bisa diverifikasi pihak lain).
- Snapshot versi tool membuat hasil pemeriksaan dapat direproduksi.
- Allowlist hash menekan positif palsu, deduplikasi bukti mencegah bukti sama diperiksa dua kali.

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

- [`docs/INSTALL.md`](docs/INSTALL.md) - installer, dependensi, dan pemasangan manual
- [`docs/TOOLS.md`](docs/TOOLS.md) - katalog 39 tool dan cara menambah tool baru
- [`docs/WORKFLOW.md`](docs/WORKFLOW.md) - alur kerja kasus end-to-end
- [`docs/AI.md`](docs/AI.md) - lapisan AI dan pengamanannya
- [`docs/AI-MODELS.md`](docs/AI-MODELS.md) - registry model AI milik pengguna
- [`docs/INTEGRITY.md`](docs/INTEGRITY.md) - manifest, segel, allowlist, dan reproduktifitas
- [`docs/TIMELINE.md`](docs/TIMELINE.md) - timeline, MITRE ATT&CK, dan ekspor IOC
- [`SECURITY.md`](SECURITY.md) - kebijakan keamanan dan pelaporan kerentanan
- [`CONTRIBUTING.md`](CONTRIBUTING.md) - panduan kontribusi
- [`CHANGELOG.md`](CHANGELOG.md) - riwayat perubahan

---

## Struktur proyek

```
OpenForensic.psd1              manifest modul (0.4.0, 90 fungsi terekspor)
OpenForensic.psm1              inti: katalog tool, eksekusi aman, hash, tipe file, report
OpenForensic.Workflow.psm1     kasus, bukti, artefak, temuan, report
OpenForensic.Ai.psm1           provider AI, perencanaan, analisa, asisten
OpenForensic.Integrity.psm1    manifest, segel, versi tool, allowlist, dedup, timeout
OpenForensic.Timeline.psm1     timeline ternormalisasi, MITRE ATT&CK, ekspor IOC
OpenForensic.Models.psm1       registry model AI pengguna, analisa mendalam, alur lengkap
menu.ps1 / case.ps1 / run.ps1  antarmuka menu dan CLI
setup_tools.ps1                installer tool pihak ketiga
tools.json                     katalog 39 tool (schemaVersion 2)
tests/                         Pester test untuk seluruh modul
```

---

## Keamanan

- Tidak ada `Invoke-Expression`; seluruh proses dijalankan dengan argumen berbentuk array sehingga
  nama berkas bukti tidak dapat dipakai untuk command injection. CI menjaga pola ini.
- API key dienkripsi DPAPI atau dibaca dari environment variable, tidak pernah plaintext di repo.
- Data kasus (`cases/`, `artifacts/`, `reports/`) dan konfigurasi lokal tidak pernah di-commit.
- TLS 1.2 dipaksa untuk semua panggilan jaringan.

Laporkan kerentanan melalui [`SECURITY.md`](SECURITY.md).

---

## Lisensi

MIT - lihat [`LICENSE`](LICENSE).
