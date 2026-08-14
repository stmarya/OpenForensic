# Catatan Pemakaian Tool

Semua contoh diasumsikan dijalankan dari root repo. Binary hasil `setup_tools.ps1`
berada di `.\bin`. Anda bisa memakai launcher (`.\openforensic.bat <id> <args>`)
atau memanggil executable langsung.

## 1. Volatility 3 (`vol.exe`)

Framework analisis memori (RAM dump): proses, koneksi jaringan, file, injeksi kode.

```powershell
.\bin\vol.exe -h
.\bin\vol.exe -f memory.dmp windows.info
.\bin\vol.exe -f memory.dmp windows.pslist
.\bin\vol.exe -f memory.dmp windows.netscan
.\bin\vol.exe -f memory.dmp windows.malfind
.\openforensic.bat vol -f memory.dmp windows.cmdline
```

Plugin yang sering dipakai di CTF: `windows.pstree`, `windows.filescan`,
`windows.dumpfiles`, `windows.hashdump`, `windows.registry.printkey`, `banners`.

## 2. Dekompilasi Python

`uncompyle6` menangani bytecode lama; untuk Python 3.7+ gunakan `decompyle3`.
Jika keduanya gagal (Python 3.9+), pakai [pycdc / Decompyle++](https://github.com/zrax/pycdc)
yang harus dibuild manual dengan CMake.

```powershell
.\bin\uncompyle6.exe soal.pyc > hasil.py
.\bin\decompyle3.exe soal.pyc > hasil.py
```

## 3. Oletools (analisis dokumen Office)

| Tool | Fungsi |
| --- | --- |
| `oleid.exe` | Deteksi cepat indikator berbahaya |
| `olevba.exe` | Ekstrak & analisis makro VBA |
| `mraptor.exe` | Klasifikasi makro jahat/tidak |
| `rtfobj.exe` | Ekstrak objek tertanam dari RTF |
| `oleobj.exe` | Ekstrak objek OLE tertanam |

```powershell
.\bin\oleid.exe suspicious.docx
.\bin\olevba.exe suspicious.xls
.\bin\rtfobj.exe exploit.rtf
```

## 4. ExifTool

Metadata gambar/dokumen, sering menyimpan flag atau komentar tersembunyi.

```powershell
exiftool -a -u -g1 evidence.jpg
```

## 5. Stego & carving

```powershell
binwalk evidence.png            # cari file tertanam
7z l evidence.png               # cek apakah ada arsip di dalamnya
steghide extract -sf secret.jpg # butuh passphrase
zsteg -a evidence.png           # LSB stego (butuh Ruby)
```

Built-in `strings` OpenForensic memindai ASCII **dan** UTF-16LE sekaligus:

```powershell
.\run.ps1 -ToolId strings -TargetPath .\evidence.png
Import-Module .\OpenForensic.psd1
Invoke-OFStrings -Path .\evidence.png -Pattern 'flag\{'
```

## 6. Network (PCAP)

```powershell
tshark -r capture.pcap -q -z io,phs      # hierarki protokol
tshark -r capture.pcap -Y "http.request" # filter HTTP
```

## 7. PyCryptodome

Library kriptografi Python, dipakai dari script Anda sendiri (tidak ada executable).

```python
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

key = b'KunciRahasia1234'
cipher = AES.new(key, AES.MODE_ECB)
```

## Integritas bukti

Selalu catat hash sebelum menyentuh file. OpenForensic melakukannya otomatis di header
report, tetapi manual pun mudah:

```powershell
Get-FileHash -Algorithm SHA256 .\evidence.dmp
```
