# OpenForensic

Toolkit forensik digital & CTF untuk Windows dengan **alur kerja end-to-end berbasis kasus**:
satu perintah membawa Anda dari file bukti sampai laporan siap lampir.

```
BUKTI -> TOOL -> ARTEFAK -> TEMUAN -> REPORT
   (hash & chain of custody, pemilihan tool otomatis, 31 detektor artefak,
    korelasi + narasi dibantu AI, ekspor Markdown + HTML)
```

> **Disclaimer:** gunakan hanya pada sistem, file, dan data yang Anda miliki atau yang Anda
> punya izin tertulis untuk dianalisis. Penulis tidak bertanggung jawab atas penyalahgunaan.

## Fitur utama

- **Satu alur kerja terintegrasi** - kasus, bukti, eksekusi tool, artefak, temuan, timeline,
  chain of custody, dan report tersimpan dalam satu state `cases/<CaseId>/case.json`.
  Pemeriksaan bisa dihentikan dan dilanjutkan kapan saja. Lihat [`docs/WORKFLOW.md`](docs/WORKFLOW.md).
- **39 tool dalam katalog `tools.json`** - menambah tool baru tidak perlu mengubah kode.
- **Pemilihan tool otomatis** - berdasarkan magic bytes, bukan ekstensi, sehingga file yang
  ekstensinya dipalsukan tetap diperiksa dengan tool yang benar (dan langsung jadi temuan).
- **31 detektor artefak** - IOC jaringan, kredensial, LOLBin, persistence, makro, PDF aktif,
  blob base64, alamat kripto, flag CTF, sampai indikasi prompt injection.
- **AI Assistance di 5 titik** - perencana tool, analisis terpandu, analis kasus, penulis
  report, dan assistant interaktif. Multi provider termasuk **Ollama lokal**.
  Lihat [`docs/AI.md`](docs/AI.md).
- **Eksekusi aman** - argumen dilewatkan sebagai array, tanpa `Invoke-Expression` (dijaga CI),
  sehingga nama file bukti tidak bisa dipakai untuk command injection.
- **Integritas bukti** - MD5/SHA1/SHA256 dihitung sebelum dan sesudah analisis; perubahan hash
  otomatis menjadi temuan severity `critical`.
- **Report profesional** - 9 bagian, Markdown + HTML, memuat metode, log tool, temuan
  berurut severity, timeline, chain of custody, dan pernyataan keterbatasan.

## Prasyarat

| Komponen | Keterangan |
| --- | --- |
| Windows 10/11 | PowerShell 5.1 atau PowerShell 7+ |
| Python 3.8+ | harus ada di `PATH` (`python --version`) |
| Git | untuk meng-clone Volatility 3 |
| winget | opsional, untuk ExifTool / 7-Zip / Wireshark |
| Ollama | opsional, untuk AI lokal tanpa mengirim data keluar |

## Instalasi

```powershell
git clone https://github.com/stmarya/OpenForensic.git
cd OpenForensic
powershell -ExecutionPolicy Bypass -File .\setup_tools.ps1
```

Opsi installer: `-SkipVolatility`, `-SkipWinget`, `-IncludeOptional`.
Semua binary hasil unduhan masuk ke `bin/` dan tidak pernah di-commit.
Tool yang belum terpasang otomatis dilewati (dengan petunjuk instalasi), bukan menggagalkan alur.

## Penggunaan

### 1. Alur end-to-end dalam satu perintah

```powershell
# Bukti -> tool -> artefak -> temuan -> report, otomatis
.\case.ps1 -Path .\bukti\dump.raw -CaseName "Insiden Workstation A"

# Banyak bukti, salinan terverifikasi, plus analisa AI
.\case.ps1 -Path .\bukti\*.docx -CaseName "Phishing Batch" -CopyEvidence -UseAi

# AI memilih tool berikutnya, setiap rencana Anda setujui dulu
.\case.ps1 -Path .\bukti\suspect.exe -CaseName "Malware Triage" -GuidedAi

# Lanjutkan kasus yang sudah ada
.\case.ps1 -List
.\case.ps1 -CaseId CASE-20260814-231500-Insiden_A -AddEvidence .\bukti\baru.evtx -Analyze
.\case.ps1 -CaseId CASE-20260814-231500-Insiden_A -AiAnalyze -Report
```

### 2. Menu interaktif

```powershell
.\openforensic.bat
```

Menu 1-7 alur kerja kasus, 8-12 lapisan AI, 13-17 utilitas (analisa cepat tanpa kasus,
status tool, daftar report, update tool, hapus API key).

### 3. Mode CLI per tool

```powershell
.\openforensic.bat --list
.\openforensic.bat vol -f memory.dmp windows.pslist
.\run.ps1 -ToolId strings -TargetPath .\image.png
```

### 4. Sebagai modul PowerShell

```powershell
Import-Module .\OpenForensic.psd1 -Force

$case = New-OFCase -Name 'Insiden Workstation A' -Reference 'TIKET-1234' -Classification confidential
$e1   = Add-OFCaseEvidence -Case $case -Path .\bukti\invoice.docm -Copy

Invoke-OFEvidenceAnalysis -Case $case -EvidenceId $e1.id      # tool otomatis sesuai tipe file
Invoke-OFAiCaseAnalysis   -Case $case                         # korelasi + verdict + ringkasan
Export-OFCaseReport       -Case $case -Format Both -IncludeArtifacts
```

## Katalog tool (39)

| Kategori | Tool |
| --- | --- |
| Memori | Volatility 3, bulk_extractor |
| Event log & timeline | evtx_dump, Hayabusa, Chainsaw, MFTECmd |
| Registry | RegRipper |
| Dokumen | oleid, olevba, mraptor, rtfobj, oleobj, oledump, zipdump, msoffcrypto-tool, pdfid, pdf-parser |
| Reverse engineering | capa, FLOSS, rizin, uncompyle6, decompyle3, jadx |
| Deteksi | YARA, ClamAV |
| Metadata | ExifTool |
| Stego | steghide, stegseek, zsteg, pngcheck |
| Carving & arsip | binwalk, 7-Zip, PhotoRec |
| Network | TShark, capinfos |
| Aplikasi | SQLite3 |
| Password | John the Ripper |
| Decode | base64dump |
| Built-in | strings (ASCII + UTF-16LE) |

Setiap entri memiliki `phase` (triage/extract/analyze/timeline/crack) dan `aiHint` yang dipakai
AI saat memilih tool. Catatan pemakaian: [`docs/TOOLS.md`](docs/TOOLS.md).

Cek yang sudah terpasang di mesin Anda:

```powershell
Get-OFToolStatus | Format-Table Id, Name, Category, Available
```

## Privasi & keamanan fitur AI

1. AI **tidak pernah** mengeksekusi command bebas - hanya boleh memilih `toolId` yang ada di
   `tools.json`; argumen dibangun oleh modul.
2. Tidak ada data yang keluar tanpa **persetujuan eksplisit**; kasus berklasifikasi
   `confidential`/`restricted` diberi peringatan dan saran memakai provider lokal.
3. Data bukti dipagari penanda `UNTRUSTED` dan model diinstruksikan menolak instruksi di
   dalamnya, lalu melaporkannya sebagai temuan **Indikasi prompt injection**.
4. Temuan dari AI ditandai `[AI]` dengan `origin = ai` dan wajib diverifikasi pada log tool.

```powershell
Set-OFAiConfig -Provider ollama -Model llama3.1   # 100% lokal, data tidak keluar mesin
Set-OFAiConfig -Provider gemini -Model gemini-1.5-flash
Set-OFAiConfig -Redact $true                      # redaksi email/token/key sebelum dikirim
```

API key dibaca berurutan: `$env:OPENFORENSIC_AI_KEY` -> `$env:GEMINI_API_KEY` /
`$env:OPENAI_API_KEY` -> file `.ai_config` (terenkripsi DPAPI). Hapus dengan `Clear-OFApiKey`.

## Struktur repo

```
OpenForensic.psd1              manifest modul (51 fungsi terekspor)
OpenForensic.psm1              modul inti: hash, magic bytes, eksekusi aman, report, strings
OpenForensic.Workflow.psm1     kasus, bukti, detektor artefak, temuan, timeline, report kasus
OpenForensic.Ai.psm1           lapisan AI: provider, perencana tool, analis, penulis report
tools.json                     katalog 39 tool (tipe file, argumen, fase, panduan AI)
case.ps1                       CLI alur kerja end-to-end
menu.ps1                       menu interaktif berbasis kasus
run.ps1 / openforensic.bat     entry point CLI per tool
setup_tools.ps1                installer dependensi
cases/                         data kasus (gitignored: memuat data bukti)
docs/WORKFLOW.md               panduan alur kerja end-to-end
docs/AI.md                     panduan & batasan fitur AI
docs/TOOLS.md                  catatan pemakaian tiap tool
tests/                         Pester tests (inti + workflow + AI)
```

## Pengembangan

```powershell
Invoke-ScriptAnalyzer -Path . -Recurse -Settings .\PSScriptAnalyzerSettings.psd1
Invoke-Pester -Path .\tests
```

Lihat [CONTRIBUTING.md](CONTRIBUTING.md), [SECURITY.md](SECURITY.md), dan
[CHANGELOG.md](CHANGELOG.md). Lisensi: [MIT](LICENSE).
