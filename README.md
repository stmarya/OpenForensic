# CTF Digital Forensics & Analysis Tools

Dokumentasi ini berisi daftar *tools* yang telah terpasang di dalam direktori `C:\Users\altar\Documents\CTF\bin` beserta panduan singkat cara menggunakannya.

## 1. Volatility 3 (`vol.exe`)
**Fungsi:** Framework untuk melakukan analisis memori (RAM dump) dan mengekstrak informasi tersembunyi (proses, koneksi jaringan, file) dari sistem operasi.

**Cara Penggunaan Dasar:**
- **Melihat menu bantuan:**
  ```powershell
  .\bin\vol.exe -h
  ```
- **Menganalisis file memory dump (contoh file: `memory.dmp`) menggunakan plugin Windows `pslist`:**
  ```powershell
  .\bin\vol.exe -f memory.dmp windows.pslist
  ```

## 2. Uncompyle6 (`uncompyle6.exe`)
**Fungsi:** Tool dekompilasi untuk mengembalikan file Python hasil kompilasi (`.pyc`) menjadi source code Python asli (`.py`). Sangat berguna untuk tantangan *Reverse Engineering* berbasis Python.

**Cara Penggunaan Dasar:**
- **Melihat menu bantuan:**
  ```powershell
  .\bin\uncompyle6.exe --help
  ```
- **Mendekompilasi file `.pyc` dan menyimpannya ke file `.py`:**
  ```powershell
  .\bin\uncompyle6.exe file_soal.pyc > hasil_decompile.py
  ```

## 3. Oletools (Kumpulan Tools)
**Fungsi:** Rangkaian alat bantu untuk menganalisis dokumen Microsoft Office (.doc, .xls, .ppt) yang mencurigakan, seperti dokumen yang disisipi macro berbahaya (VBA).

**Tools Utama yang Tersedia:**
- `olevba.exe`: Mengekstrak dan menganalisis kode Macro VBA dari dokumen.
- `oleid.exe`: Menganalisis file dokumen secara cepat untuk mendeteksi indikator mencurigakan.
- `mraptor.exe`: Mendeteksi Macro VBA yang bersifat jahat (malicious).

**Cara Penggunaan Dasar:**
- **Mendeteksi indikator bahaya pada sebuah file Word:**
  ```powershell
  .\bin\oleid.exe file_mencurigakan.docx
  ```
- **Mengekstrak Macro VBA dari file Excel:**
  ```powershell
  .\bin\olevba.exe file_mencurigakan.xls
  ```

## 4. PyCryptodome
**Fungsi:** *Library* kriptografi komprehensif untuk Python. Tidak memiliki *executable* mandiri di folder `bin`, melainkan langsung di-*import* ketika Anda membuat *script* Python.

**Cara Penggunaan Dasar:**
Buat *script* Python (misal `solve.py`) dan import modul kriptografi yang dibutuhkan:
```python
# Contoh implementasi AES Cipher
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

key = b'KunciRahasia1234'
cipher = AES.new(key, AES.MODE_ECB)
# Lanjutkan proses dekripsi atau enkripsi...
```

---
*Catatan: Pastikan Anda menjalankan perintah-perintah di atas melalui Terminal/PowerShell dengan lokasi awal (CWD) berada di `C:\Users\altar\Documents\CTF\`.*
