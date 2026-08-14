# Panduan Instalasi

`setup_tools.ps1` memasang seluruh toolchain OpenForensic (39 tool) dan memverifikasi hasilnya
lewat katalog `tools.json`. Installer bersifat *best effort*: kegagalan satu tool tidak
menghentikan tool lain, dan ringkasan error/peringatan ditampilkan di akhir.

## Perintah dasar

```powershell
# Instalasi standar (paket Python, Volatility 3, winget, unduhan rilis)
powershell -ExecutionPolicy Bypass -File .\setup_tools.ps1

# Tambah Wireshark + PhotoRec, dan tool berat (bulk_extractor, capa/floss via pip)
.\setup_tools.ps1 -IncludeOptional -IncludeHeavy

# Pasang ulang beberapa tool saja
.\setup_tools.ps1 -Only hayabusa,chainsaw,yara -Force
```

## Parameter

| Parameter | Efek |
| --- | --- |
| `-SkipVolatility` | Lewati clone + build Volatility 3 |
| `-SkipPython` | Lewati semua `pip install` |
| `-SkipWinget` | Lewati ExifTool / 7-Zip / ClamAV / SQLite |
| `-SkipDownload` | Lewati unduhan rilis GitHub dan DidierStevensSuite (mode offline / air-gapped) |
| `-IncludeOptional` | Tambah Wireshark (tshark, capinfos) dan TestDisk/PhotoRec |
| `-IncludeHeavy` | Tambah bulk_extractor serta `flare-capa` / `flare-floss` |
| `-Only <id[]>` | Batasi unduhan pada id tool tertentu saja |
| `-Force` | Pasang ulang meski folder tool sudah ada |

## Apa yang dipasang dari mana

| Sumber | Tool |
| --- | --- |
| pip | oletools (oleid/olevba/mraptor/rtfobj/oleobj), msoffcrypto-tool, uncompyle6, decompyle3, binwalk, pefile, yara-python, python-registry |
| git + pip | Volatility 3 |
| winget | ExifTool, 7-Zip, ClamAV, SQLite tools, Wireshark (opsional) |
| GitHub Releases | evtx_dump, Hayabusa, Chainsaw, YARA, capa, FLOSS, rizin, Stegseek, jadx, bulk_extractor (berat) |
| Vendor | MFTECmd (Eric Zimmerman), TestDisk/PhotoRec (opsional) |
| Raw GitHub | DidierStevensSuite: pdfid, pdf-parser, oledump, zipdump, base64dump |
| Manual | RegRipper, John the Ripper, pngcheck, steghide, zsteg, rule YARA |

Unduhan rilis GitHub selalu memakai **rilis terbaru** (endpoint `releases/latest`), bukan URL
yang dipaku, sehingga installer tidak basi ketika versi tool berganti. Set `$env:GITHUB_TOKEN`
bila Anda terkena rate limit API GitHub.

## Jejak audit unduhan

Setiap berkas yang diunduh dicatat di `bin/_downloads.log`:

```
2026-08-15 00:31:12  SHA256=A1B2...  bytes=13456789  url=https://github.com/...
```

Simpan berkas ini bila hasil pemeriksaan akan dipakai sebagai alat bukti: catatan tersebut
membuktikan versi tool mana yang dipakai saat pemeriksaan berlangsung.

## Shim di folder bin/

Beberapa tool butuh folder pendukung di sebelahnya (Hayabusa dan Chainsaw butuh `rules/`,
jadx butuh `lib/`). Installer mengekstraknya ke `bin/<id>/` lalu membuat shim `bin/<id>.cmd`
yang berpindah direktori kerja sebelum memanggil executable. Konsekuensinya: **selalu berikan
path bukti secara absolut** - alur kerja `case.ps1` sudah melakukannya otomatis.

Skrip Python DidierStevensSuite juga mendapat shim (`bin/oledump.cmd`, `bin/pdfid.cmd`, dst.)
sehingga katalog dapat memanggilnya seperti executable biasa.

## Instalasi di lingkungan air-gapped

1. Di mesin yang terhubung internet, jalankan installer secara normal.
2. Salin folder `bin/` (beserta `bin/_downloads.log`) dan `rules/` ke mesin target.
3. Di mesin target jalankan `.\setup_tools.ps1 -SkipDownload -SkipWinget -SkipVolatility`
   untuk verifikasi katalog, atau langsung `Get-OFToolStatus`.

## Verifikasi

```powershell
Import-Module .\OpenForensic.psd1 -Force
Get-OFToolStatus | Format-Table Id, Name, Category, Available, Path
```

Tool yang belum terpasang otomatis dilewati saat analisis, dengan petunjuk instalasi dicatat
di report - bukan menggagalkan pemeriksaan.
