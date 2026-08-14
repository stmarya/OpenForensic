# OpenForensic — Kan9Ch3k Toolkit

> Interactive digital forensics & CTF triage toolkit untuk Windows.
> Satu entry point untuk menjalankan Volatility 3, oletools, decompiler Python,
> ExifTool, dan tools lainnya — dengan hashing bukti otomatis, deteksi tipe file
> berbasis *magic bytes*, report bertimestamp, dan analisa opsional dengan AI.

![status](https://img.shields.io/badge/status-alpha-orange)
![platform](https://img.shields.io/badge/platform-Windows-blue)
![license](https://img.shields.io/badge/license-MIT-green)

---

## Daftar isi

- [Fitur](#fitur)
- [Prasyarat](#prasyarat)
- [Instalasi](#instalasi)
- [Cara pakai](#cara-pakai)
  - [Mode interaktif](#mode-interaktif-menu)
  - [Mode CLI](#mode-cli)
- [Tools yang didukung](#tools-yang-didukung)
- [Report & chain of custody](#report--chain-of-custody)
- [Fitur AI Analyst (opsional)](#fitur-ai-analyst-opsional)
- [Struktur project](#struktur-project)
- [Keamanan & privasi](#keamanan--privasi)
- [Disclaimer legal](#disclaimer-legal)
- [Pengembangan](#pengembangan)
- [Lisensi](#lisensi)

---

## Fitur

| Fitur | Keterangan |
|---|---|
| **Magic Triage** | Mendeteksi tipe file dari *magic bytes* (bukan ekstensi) lalu otomatis menjalankan rangkaian tool yang relevan. Tahan terhadap file CTF yang ekstensinya sengaja disalahkan. |
| **Evidence hashing** | MD5 / SHA-1 / SHA-256 dihitung dan ditulis ke header setiap report sebelum analisis dimulai. |
| **Chain of custody** | Setiap aksi dicatat sebagai JSON-lines di `reports/chain-of-custody.log` (waktu UTC, user, host, hash, command). |
| **Report ganda** | Output disimpan sebagai `.txt` (human readable) dan `.json` (machine readable) untuk diproses lanjut. |
| **Manifest-driven** | Tool didefinisikan deklaratif di [`tools.json`](tools.json) — menambah tool baru tidak perlu mengubah kode. |
| **Eksekusi aman** | Tidak ada `Invoke-Expression`. Semua tool dijalankan lewat call operator dengan array argumen, sehingga nama file bukti tidak bisa menyebabkan command injection. |
| **Built-in strings** | Ekstraktor ASCII + UTF-16LE bawaan, tanpa perlu Sysinternals. |
| **AI Analyst** | Ringkasan temuan dari log analisis via Gemini API **atau** Ollama lokal, dengan konfirmasi eksplisit dan proteksi prompt injection. |

---

## Prasyarat

| Kebutuhan | Versi | Catatan |
|---|---|---|
| Windows | 10 / 11 / Server 2019+ | — |
| PowerShell | 5.1+ (7.x direkomendasikan) | `$PSVersionTable.PSVersion` |
| Python | 3.9 – 3.12 | harus ada di `PATH` |
| Git | opsional | untuk update dari source |
| winget | opsional | untuk instalasi ExifTool otomatis |

---

## Instalasi

```powershell
git clone https://github.com/stmarya/OpenForensic.git
cd OpenForensic

# Instalasi standar (membuat .venv lokal, tidak mengotori Python global)
.\setup_tools.ps1
```

Opsi tambahan:

```powershell
.\setup_tools.ps1 -IncludeOptional   # + pdfid, uncompyle6/decompyle3, binwalk
.\setup_tools.ps1 -SkipExifTool      # lewati winget
.\setup_tools.ps1 -Recreate          # bangun ulang .venv dari nol
```

Setelah selesai, verifikasi:

```powershell
.\kan9ch3k.bat -ListTools
```

> **Catatan:** installer sengaja memakai virtual environment `.venv` di dalam folder
> project. Ini membuat lokasi executable deterministik di semua mesin dan
> menghilangkan bug versi lama yang hanya mencari `site.USER_BASE\Scripts`.
> Tool tetap dicari berurutan di `bin\` → `.venv\Scripts\` → `PATH`, jadi Anda
> boleh menaruh binary manual (mis. `pycdc.exe`) ke dalam `bin\`.

---

## Cara pakai

### Mode interaktif (menu)

```powershell
.\kan9ch3k.bat
```

```
==========================================================
   __ __            ___  ________   ____ __
  / //_/___ _____  / _ \/ ___/ _ \ /_  // /__
 / ,< / __ `/ __ \/ // / /__/ , _/  / // //_/
/_/|_|\__,_/_/ /_/\___/\___/_/|_|  /_//_/\_\
==========================================================
        Interactive Digital Forensics Toolkit
==========================================================

 [1] Magic Triage        (auto-analisis berdasarkan magic bytes)
 [2] Jalankan tool       (pilih tool secara manual)
 [3] Identifikasi & hash (tipe file + MD5/SHA1/SHA256)
 [4] Strings             (ekstraktor ASCII/UTF-16 built-in)
 [5] AI Analyst          (ringkas report dengan LLM)
 [6] Status tools        (cek tool mana yang tersedia)
 [7] Buka folder reports
[99] Update tools
 [0] Keluar
```

### Mode CLI

```powershell
# Triage otomatis
.\kan9ch3k.bat -Triage -File .\evidence\suspicious.docx

# Tool spesifik + plugin
.\kan9ch3k.bat -Tool vol -File .\evidence\memory.dmp -Plugin windows.pslist

# Bentuk positional (kompatibel gaya lama)
.\kan9ch3k.bat olevba .\evidence\macro.xls

# Argumen tambahan diteruskan apa adanya ke tool
.\kan9ch3k.bat -Tool exiftool -File .\evidence\photo.jpg -ExtraArgs '-a','-u','-g1'

# Utilitas
.\kan9ch3k.bat -ListTools
.\kan9ch3k.bat -Hash -File .\evidence\photo.jpg
```

Atau langsung lewat PowerShell / import module:

```powershell
.\openforensic.ps1 -Triage -File .\evidence\capture.pcap

Import-Module .\OpenForensic\OpenForensic.psd1
Get-OFFileType -Path .\evidence\mystery.bin
Get-OFEvidenceHash -Path .\evidence\mystery.bin
Invoke-OFTriage -Path .\evidence\mystery.bin
```

---

## Tools yang didukung

Didefinisikan di [`tools.json`](tools.json). Kolom *auto* menandakan tool ikut dijalankan saat Magic Triage.

| Tool | Kategori | Tipe file | Auto | Instalasi |
|---|---|---|:--:|---|
| Volatility 3 (`vol`) | memory | `memdump`, `crashdump` | ✅ | inti (pip) |
| `oleid` | document | `ole`, `ooxml`, `rtf` | ✅ | inti (pip) |
| `olevba` | document | `ole`, `ooxml`, `rtf` | ✅ | inti (pip) |
| `mraptor` | document | `ole`, `ooxml`, `rtf` | ✅ | inti (pip) |
| `rtfobj` | document | `rtf` | ✅ | inti (pip) |
| `pycdc` (Decompyle++) | reversing | `pyc` | ✅ | manual → `bin\pycdc.exe` |
| `uncompyle6` | reversing | `pyc` | — | opsional (legacy, gagal di Python ≥3.9) |
| ExifTool | metadata | image, pdf, video, `*` | ✅ | winget |
| `Get-OFStrings` | generic | `*` | ✅ | built-in |
| `pdfid` | document | `pdf` | ✅ | opsional (pip) |
| `tshark` | network | `pcap`, `pcapng` | ✅ | Wireshark |
| `binwalk` | carving | `*` | — | opsional (pip) |
| `zsteg` | stego | `png`, `bmp` | — | Ruby: `gem install zsteg` |
| `steghide` | stego | `jpeg`, `bmp`, `wav` | — | manual |
| `7z` | archive | `zip`, `rar`, `7z`, `gzip` | ✅ | 7-Zip |

Tipe file yang dikenali dari magic bytes: `memdump`, `crashdump`, `pe`, `elf`, `macho`, `pyc`, `ole`, `ooxml`, `rtf`, `pdf`, `png`, `jpeg`, `gif`, `bmp`, `zip`, `rar`, `7z`, `gzip`, `pcap`, `pcapng`, `sqlite`, `evtx`, `wav`, `text`, `unknown`.

Menambah tool baru = tambahkan satu entri di `tools.json`:

```json
{
  "id": "foremost",
  "name": "Foremost",
  "description": "File carving",
  "category": "carving",
  "command": "foremost.exe",
  "lookup": "auto",
  "kinds": ["*"],
  "args": ["-i", "{file}"],
  "autoTriage": false,
  "optional": true,
  "install": "Unduh manual ke folder bin\\"
}
```

---

## Report & chain of custody

Setiap analisis menghasilkan dua file di `reports/`:

```
reports/
  20260814_231500_suspicious.docx.report.txt
  20260814_231500_suspicious.docx.report.json
  chain-of-custody.log
```

Header report `.txt`:

```
================= OpenForensic / Kan9Ch3k Report =================
Report ID   : 20260814_231500
Generated   : 2026-08-14T16:15:00.0000000Z (UTC)
Operator    : DESKTOP-ABC\analyst
Toolkit     : 0.1.0
------------------------------- EVIDENCE -------------------------------
File        : C:\cases\suspicious.docx
Size        : 51200 bytes
Detected    : ooxml (Office Open XML: word/) [magic-bytes]
Extension   : .docx
MD5         : 9e107d9d372bb6826bd81d3542a419d6
SHA1        : 2fd4e1c67a2d28fced849ee1bb76e7391b93eb12
SHA256      : e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
========================================================================
```

`chain-of-custody.log` berisi satu objek JSON per baris — cocok untuk diimpor ke SIEM atau diverifikasi ulang. File ini **append-only** dan tidak pernah ditimpa oleh toolkit.

---

## Fitur AI Analyst (opsional)

Menu `[5]` mengirim isi report ke LLM untuk diringkas. Fitur ini **nonaktif secara default** sampai Anda menyediakan kredensial, dan selalu menampilkan konfirmasi sebelum data keluar dari mesin.

### Provider

```powershell
# Gemini (cloud) — default
$env:OF_GEMINI_API_KEY = 'AIza...'      # atau simpan terenkripsi lewat menu
$env:OF_GEMINI_MODEL   = 'gemini-2.0-flash'

# Ollama (lokal, data tidak keluar dari mesin) — direkomendasikan untuk kasus nyata
$env:OF_AI_PROVIDER = 'ollama'
$env:OF_OLLAMA_URL   = 'http://localhost:11434'
$env:OF_OLLAMA_MODEL = 'llama3.1'
```

### Pengamanan yang diterapkan

1. **Konfirmasi eksplisit** — prompt `[y/N]` yang menyebutkan nama provider, jumlah byte yang dikirim, dan peringatan chain of custody sebelum request dilakukan.
2. **API key tidak plaintext** — dibaca dari environment variable, atau dari `.ai_config.secure` yang dienkripsi DPAPI (`ConvertFrom-SecureString`, hanya bisa dibuka oleh user + mesin yang sama). File `.ai_config` plaintext dari versi lama akan otomatis dimigrasikan lalu dihapus.
3. **Key tidak di URL** — dikirim lewat header `x-goog-api-key`, bukan query string, agar tidak bocor ke log proxy/history.
4. **Proteksi prompt injection** — isi report dibungkus delimiter ber-nonce acak, dan system prompt secara eksplisit menginstruksikan model untuk memperlakukannya **murni sebagai data**. Ini penting karena log berasal dari dokumen/malware yang bisa saja menyisipkan instruksi untuk memanipulasi kesimpulan analis.
5. **Batas ukuran** — payload dipotong pada 80 KB dan ditandai `[TRUNCATED]`.

> ⚠️ **Jangan gunakan provider cloud pada bukti kasus nyata / data rahasia.**
> Mengirim isi report ke pihak ketiga dapat melanggar chain of custody,
> perjanjian kerahasiaan, dan regulasi perlindungan data. Gunakan Ollama lokal.

---

## Struktur project

```
OpenForensic/
├── kan9ch3k.bat                  # entry point (menu / CLI passthrough)
├── kan9ch3k_menu.ps1             # launcher mode interaktif
├── openforensic.ps1              # launcher mode CLI
├── setup_tools.ps1               # installer idempoten
├── tools.json                    # manifest tool (deklaratif)
├── requirements.txt              # dependensi Python inti
├── requirements-optional.txt     # dependensi Python opsional
├── OpenForensic/
│   ├── OpenForensic.psd1         # module manifest
│   └── OpenForensic.psm1         # seluruh logic
├── tests/
│   └── OpenForensic.Tests.ps1    # Pester
├── docs/
│   └── CTF-TOOLS.md              # catatan pemakaian tool per-tool
├── .github/
│   ├── workflows/ci.yml          # PSScriptAnalyzer + Pester
│   └── dependabot.yml
├── bin/                          # (gitignored) binary manual / override
├── .venv/                        # (gitignored) virtualenv Python
└── reports/                      # (gitignored) hasil analisis
```

---

## Keamanan & privasi

- Toolkit **tidak pernah** mengirim data ke jaringan kecuali Anda memilih menu AI Analyst dan menyetujui konfirmasinya.
- `bin/`, `reports/`, `.venv/`, `.ai_config*` seluruhnya di-`.gitignore` — bukti dan kredensial tidak akan ikut ter-commit.
- Semua tool dijalankan dengan array argumen; nama file tidak pernah di-*re-parse* sebagai perintah shell.
- Buka file bukti dengan mode read-only sharing saat identifikasi tipe file.
- Laporan kerentanan: lihat [SECURITY.md](SECURITY.md).

---

## Disclaimer legal

Toolkit ini dibuat untuk **kompetisi CTF, riset keamanan, edukasi, dan investigasi
forensik yang sah**. Gunakan hanya pada sistem dan data yang Anda miliki atau yang
Anda punya izin tertulis untuk dianalisis. Penulis tidak bertanggung jawab atas
penyalahgunaan. Untuk keperluan litigasi, verifikasi ulang setiap temuan dengan
tool yang tervalidasi — output toolkit ini bersifat membantu triase, bukan bukti final.

---

## Pengembangan

```powershell
Install-Module Pester, PSScriptAnalyzer -Scope CurrentUser -Force
Invoke-ScriptAnalyzer -Path . -Recurse -Settings PSGallery
Invoke-Pester .\tests
```

Lihat [CONTRIBUTING.md](CONTRIBUTING.md). Roadmap: file carving (foremost/binwalk
terintegrasi), dukungan Linux/macOS via PowerShell 7, output HTML report,
timeline analysis, dan integrasi YARA.

---

## Lisensi

[MIT](LICENSE) © 2026 stmarya
