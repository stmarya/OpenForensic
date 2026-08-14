# Menjalankan OpenForensic di semua sistem operasi

OpenForensic ditulis dalam PowerShell, **tetapi PowerShell bukan lagi teknologi khusus Windows**.
Sejak PowerShell 6, runtime-nya (`pwsh`) berjalan native di Linux, macOS, ARM, dan di dalam
kontainer. Sejak versi 0.5.0 seluruh kode OpenForensic diuji di Windows PowerShell 5.1,
PowerShell 7 di Windows, Linux (Ubuntu), dan macOS pada setiap commit.

Ada tiga cara memakai OpenForensic, pilih yang paling cocok:

| Cara | Cocok untuk | Perintah |
| --- | --- | --- |
| Native Windows | Pemeriksa Windows, akses penuh tool EZ Tools dan DPAPI | `.\openforensic.bat` |
| Native Linux / macOS | Pemeriksa Linux/macOS yang sudah punya `pwsh` | `./openforensic.sh` |
| Docker | Semua OS termasuk yang tidak ingin memasang apa pun | `docker compose run --rm openforensic` |

---

## 1. Linux dan macOS (native)

```bash
git clone https://github.com/stmarya/OpenForensic.git
cd OpenForensic
chmod +x openforensic.sh setup_tools.sh

./setup_tools.sh          # memasang pwsh (bila perlu) + tool DFIR + rule YARA
./openforensic.sh doctor  # cek kompatibilitas platform
./openforensic.sh         # menu interaktif
```

Opsi installer POSIX: `--skip-python`, `--skip-packages`, `--skip-download`, `--skip-pwsh`,
`--only <tool1,tool2>`, `--list`, `--yes`. Setiap unduhan dicatat lengkap dengan SHA256 di
`bin/_downloads.log`, sama seperti installer Windows. Tidak ada `curl | bash`.

CLI dan modul tetap sama:

```bash
./openforensic.sh case -Path ./evidence/memory.raw -CaseName "Insiden A" -Complete -Seal
pwsh -c "Import-Module ./OpenForensic.psd1; Get-OFToolStatus | Format-Table"
```

## 2. Docker (semua OS, termasuk tanpa PowerShell)

```bash
docker compose build
mkdir -p evidence cases
cp /path/ke/bukti.docm evidence/

docker compose run --rm openforensic                 # menu interaktif
docker compose run --rm openforensic-cli -List       # CLI case.ps1
docker compose --profile ai-local up -d ollama       # model AI lokal
```

- `./evidence` di-mount **read-only** ke `/evidence`, jadi bukti tidak mungkin termodifikasi.
- `./cases` di-mount ke `/work/cases`, sehingga hasil kasus tetap ada di host setelah kontainer berhenti.
- Image sudah memuat Volatility 3, oletools, capa, FLOSS, YARA, ExifTool, tshark, ClamAV,
  SQLite, steghide, john, pngcheck, testdisk, dan Pester.

## 3. Windows

Tidak ada perubahan: `.\setup_tools.ps1` lalu `.\openforensic.bat`. Windows tetap platform
dengan cakupan tool paling luas (MFTECmd, RegRipper, dan segel DPAPI).

---

## Apa yang berbeda antar platform

Jalankan `./openforensic.sh doctor` atau di PowerShell:

```powershell
Get-OFPlatform | Format-List
Test-OFPlatformCompatibility | Format-Table Feature, Supported, Notes -AutoSize
Format-OFPlatformSummary -IncludeMatrix   # untuk disisipkan ke report
```

| Kemampuan | Windows | Linux | macOS | Catatan |
| --- | --- | --- | --- | --- |
| Alur kerja kasus, artefak, temuan, report | ya | ya | ya | Inti pemeriksaan identik |
| Hash bukti, manifest SHA256 | ya | ya | ya | API .NET lintas platform |
| Timeline, MITRE ATT&CK, ekspor IOC | ya | ya | ya | |
| AI + registry model pengguna | ya | ya | ya | Model lokal via Ollama/LM Studio/vLLM |
| Segel kasus mode passphrase (PBKDF2) | ya | ya | ya | **Mode yang disarankan lintas OS** |
| Segel kasus mode DPAPI | ya | tidak | tidak | Terikat akun+mesin Windows |
| API key terenkripsi DPAPI | ya | tidak | tidak | Di luar Windows gunakan variabel environment |
| Dialog pemilih berkas | ya | tidak | tidak | Di luar Windows: input teks atau argumen CLI |
| Volatility 3, YARA, capa, FLOSS, oletools, binwalk | ya | ya | ya | pip / package manager |
| Hayabusa, Chainsaw, Stegseek, rizin, jadx | ya | ya | ya (sebagian) | Rilis biner per OS |
| MFTECmd, RegRipper, EZ Tools | ya | terbatas | terbatas | Alternatif: analyzeMFT, RegRipper via Perl |

### Penyesuaian praktis di luar Windows

1. **Segel kasus**: gunakan passphrase, bukan DPAPI.
   ```powershell
   Invoke-OFCaseSealWorkflow -Case $case -Passphrase (Read-Host 'Passphrase' -AsSecureString)
   ```
   Segel passphrase juga bisa diverifikasi oleh pihak lain di OS berbeda.
2. **API key**: simpan di variabel environment, bukan DPAPI.
   ```bash
   export OPENROUTER_API_KEY='...'
   export OPENFORENSIC_AI_KEY="$OPENROUTER_API_KEY"
   ```
3. **Path bukti**: berikan lewat argumen CLI (`-Path`) karena dialog grafis tidak tersedia.
4. **Artefak Windows di mesin Linux**: proses berkas yang sudah diekspor (EVTX, hive registry,
   `$MFT`) memakai tool lintas platform, atau impor CSV hasil tool Windows dengan
   `Import-OFTimelineCsv`.

---

## Variabel environment yang relevan

| Variabel | Fungsi |
| --- | --- |
| `OPENFORENSIC_HOME` | Menimpa direktori data (default: `%LOCALAPPDATA%\OpenForensic`, `~/Library/Application Support/OpenForensic`, `$XDG_DATA_HOME/openforensic`) |
| `OPENFORENSIC_NONINTERACTIVE` | Menonaktifkan semua prompt (pipeline, cron, CI) |
| `OPENFORENSIC_IN_CONTAINER` | Menandai eksekusi di dalam kontainer |
| `OPENFORENSIC_AI_KEY` | API key aktif untuk lapisan AI |
| `GITHUB_TOKEN` | Menaikkan batas rate API GitHub saat installer mengunduh rilis |

---

## Aturan kompatibilitas untuk kontributor

Agar proyek tetap berjalan di semua OS:

1. Jangan menulis path dengan `\` literal; pakai `Join-Path` atau `Convert-OFPath`.
2. Jangan memakai `$env:TEMP`, `%LOCALAPPDATA%`, atau `$env:ComSpec` langsung;
   pakai `Get-OFTempDirectory`, `Get-OFDataRoot`, dan `Resolve-OFCommand`.
3. Jangan memakai `$IsWindows` di kode yang harus jalan di PowerShell 5.1; pakai `Test-OFWindows`.
4. Jangan memakai `Get-WmiObject`, `New-Object -ComObject`, `Add-Type -AssemblyName System.Windows.Forms`,
   atau `*-Service`/registry cmdlet tanpa pengaman platform.
5. Nama berkas Unix bersifat case sensitive: samakan huruf besar/kecil pada nama modul dan berkas test.
6. Tulis berkas dengan UTF-8 tanpa BOM dan akhir baris LF.
7. Semua test harus lulus pada empat kombinasi di workflow `cross-platform`
   (Windows 5.1, Windows 7, Ubuntu 7, macOS 7). Ada juga `shellcheck` untuk script POSIX
   dan build image Docker.
