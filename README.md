# OpenForensic (codename: Kan9Ch3k)

Toolkit launcher untuk digital forensics & CTF di Windows. Menyediakan menu interaktif,
*magic triage* otomatis berdasarkan magic bytes, hashing bukti, report ganda (TXT + JSON),
dan analisis opsional dengan LLM.

> **Disclaimer:** gunakan hanya pada sistem, file, dan data yang Anda miliki atau yang Anda
> punya izin tertulis untuk dianalisis. Penulis tidak bertanggung jawab atas penyalahgunaan.

## Fitur

- **Katalog tool berbasis `tools.json`** - menambah tool baru tidak perlu mengubah kode.
- **Eksekusi aman** - argumen dilewatkan sebagai array (tanpa `Invoke-Expression`), sehingga nama file bukti yang mengandung karakter khusus tidak bisa mengeksekusi perintah.
- **Integritas bukti** - MD5/SHA1/SHA256 dihitung otomatis sebelum & sesudah analisis dan dicatat di report.
- **Deteksi tipe file via magic bytes** - ekstensi palsu (kasus umum di CTF) tetap terdeteksi dan ditandai `TypeMismatch`.
- **Magic Triage** - menjalankan seluruh tool yang relevan untuk tipe file target secara berurutan.
- **Report ganda** - `reports/<timestamp>_<file>_report.txt` (manusia) dan `.json` (mesin).
- **AI Analyst (opsional)** - meringkas report; wajib konfirmasi, API key disimpan terenkripsi (DPAPI), dan log diperlakukan sebagai data tak terpercaya untuk menahan prompt injection.

## Prasyarat

| Komponen | Keterangan |
| --- | --- |
| Windows 10/11 | PowerShell 5.1 atau PowerShell 7+ |
| Python 3.8+ | harus ada di `PATH` (`python --version`) |
| Git | untuk meng-clone Volatility 3 |
| winget | opsional, untuk ExifTool / 7-Zip / Wireshark |

## Instalasi

```powershell
git clone https://github.com/stmarya/OpenForensic.git
cd OpenForensic
powershell -ExecutionPolicy Bypass -File .\setup_tools.ps1
```

Opsi installer:

```powershell
.\setup_tools.ps1 -SkipVolatility        # lewati clone/build Volatility 3
.\setup_tools.ps1 -SkipWinget            # lewati ExifTool/7-Zip
.\setup_tools.ps1 -IncludeOptional       # tambah Wireshark (tshark)
```

Semua binary hasil unduhan masuk ke `bin/` dan tidak pernah di-commit.

## Penggunaan

### Mode interaktif

```powershell
.\openforensic.bat
```

Menu memuat daftar tool dari `tools.json` dan menandai ketersediaannya (`[ok]` / `[--]`).
Aksi khusus: `T` = Magic Triage, `A` = AI Analyst, `L` = daftar report, `U` = update tools, `0` = keluar.

### Mode CLI

```powershell
.\openforensic.bat --list
.\openforensic.bat vol -f memory.dmp windows.pslist
.\openforensic.bat olevba "sample macro.xls"
```

Atau langsung lewat PowerShell:

```powershell
.\run.ps1 -ToolId vol -TargetPath .\memory.dmp -Plugin windows.malfind
.\run.ps1 -ToolId strings -TargetPath .\image.png
```

### Sebagai modul

```powershell
Import-Module .\OpenForensic.psd1
$report = New-OFReport -TargetPath .\memory.dmp
Invoke-OFTriage -TargetPath .\memory.dmp -Report $report
Save-OFReport -Report $report
```

## Tool yang didukung

| Kategori | Tool |
| --- | --- |
| Memori | Volatility 3 (`vol`) |
| Dokumen | `oleid`, `olevba`, `mraptor`, `rtfobj`, `oleobj` |
| Reverse Engineering | `uncompyle6`, `decompyle3`, `pefile`-based checks |
| Metadata & stego | `exiftool`, `steghide`, `zsteg` (opsional) |
| Carving & arsip | `binwalk`, `7z` |
| Network | `tshark` (opsional) |
| Built-in | `strings` (ASCII + UTF-16LE, filter regex flag) |

Catatan pemakaian per tool: lihat [`docs/TOOLS.md`](docs/TOOLS.md).

## Privasi fitur AI

Menu `A` mengirim **isi report** (maks 100.000 karakter) ke Google Gemini API.
Jangan gunakan pada bukti yang bersifat rahasia, atau pada perkara yang terikat chain of custody.
API key dibaca dengan urutan: `$env:OPENFORENSIC_AI_KEY` -> `$env:GEMINI_API_KEY` -> file `.ai_config`
(terenkripsi DPAPI, hanya bisa dibuka oleh akun Windows yang membuatnya). Hapus dengan `Clear-OFApiKey`.

## Struktur repo

```
OpenForensic.psd1 / .psm1   modul inti (hash, magic bytes, eksekusi, report, AI)
tools.json                  katalog tool + mapping tipe file + argumen
menu.ps1                    UI interaktif
run.ps1                     entry point CLI
openforensic.bat            launcher dual-mode
setup_tools.ps1             installer dependensi
tests/                      Pester tests
docs/TOOLS.md               catatan pemakaian tool
```

## Pengembangan

```powershell
Invoke-ScriptAnalyzer -Path . -Recurse -Settings .\PSScriptAnalyzerSettings.psd1
Invoke-Pester -Path .\tests
```

Lihat [CONTRIBUTING.md](CONTRIBUTING.md). Lisensi: [MIT](LICENSE).
