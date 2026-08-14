# Integritas dan Reproduktifitas Bukti

Modul `OpenForensic.Integrity.psm1` menjawab pertanyaan yang selalu muncul di pengadilan
atau dalam audit insiden: **apakah bukti ini masih sama seperti saat diambil, dan apakah
hasil pemeriksaan bisa diulang?**

## 1. Manifest kasus

Manifest adalah daftar hash SHA256 seluruh berkas di folder kasus (report, log, artefak,
ekspor) dalam format yang dapat dibaca manusia.

```powershell
$case = Get-OFCase -CaseId CASE-20260815-001500-Insiden
New-OFCaseManifest -Case $case          # tulis cases/<id>/case.manifest.sha256
Test-OFCaseManifest -Case $case         # bandingkan kondisi sekarang vs manifest
```

Format baris: `<SHA256>  <path relatif>  <ukuran byte>`.
Hasil `Test-OFCaseManifest` memisahkan tiga kondisi: `Modified`, `Missing`, dan `Added`.

## 2. Segel kriptografis kasus

Segel (`case.seal.json`) adalah HMAC-SHA256 atas hash manifest. Dua mode kunci:

| Mode | Kapan dipakai | Catatan |
| --- | --- | --- |
| DPAPI (default) | Satu pemeriksa, satu mesin Windows | Kunci dilindungi profil pengguna; tidak perlu mengingat apa pun |
| PBKDF2 passphrase | Bukti akan diverifikasi di mesin lain | 120.000 iterasi; passphrase wajib diingat, tidak dapat dipulihkan |

```powershell
New-OFCaseSeal -Case $case                                  # DPAPI
New-OFCaseSeal -Case $case -Passphrase (Read-Host -AsSecureString)   # PBKDF2
Test-OFCaseSeal -Case $case
```

Segel DPAPI **tidak** dapat diverifikasi di komputer atau akun lain. Untuk penyerahan
bukti lintas pihak, selalu gunakan mode passphrase.

## 3. Snapshot versi tool

Reproduktifitas membutuhkan pencatatan versi tool yang dipakai.

```powershell
Update-OFCaseToolVersions -Case $case            # tool yang benar-benar dijalankan
Update-OFCaseToolVersions -Case $case -AllTools  # seluruh katalog
Get-OFToolVersion -ToolId hayabusa
```

Versi diambil dengan mencoba beberapa argumen probe (`--version`, `-V`, `version`) melalui
`Invoke-OFProcessWithTimeout` sehingga tool yang menggantung tidak membekukan proses.

## 4. Write-block lunak dan pemeriksaan lock

```powershell
Protect-OFEvidenceFile -Path .\bukti\dump.raw   # set ReadOnly + catat hash
Test-OFEvidenceLock -Path .\bukti\dump.raw      # cek berkas sedang dipakai proses lain
```

Ini **bukan** pengganti write blocker perangkat keras. Fungsinya mencegah modifikasi
tidak sengaja oleh tool atau editor, bukan menghalangi akses tingkat kernel.

## 5. Allowlist hash (pengurang positif palsu)

```powershell
Import-OFHashAllowlist -Path .\nsrl-subset.txt
Add-OFHashToAllowlist -Sha256 BA78... -Note 'Installer resmi vendor'
Test-OFHashAllowlist -Sha256 BA78...
```

Berkas yang hash-nya ada di `allowlist/hashes.txt` ditandai `Allowlisted` pada
`Get-OFIntegrityStatus` sehingga tidak mengaburkan temuan sebenarnya.

## 6. Deduplikasi bukti

```powershell
Test-OFEvidenceDuplicate -Case $case -Path .\bukti\lampiran.docx
```

`case.ps1 -AddEvidence` memanggil ini otomatis dan melewati berkas yang hash-nya sudah
terdaftar, sehingga satu bukti tidak dianalisis dua kali.

## 7. Status gabungan dan alur satu perintah

```powershell
Get-OFIntegrityStatus -Case $case | Format-List
Format-OFIntegritySummary -Status (Get-OFIntegrityStatus -Case $case)  # blok Markdown untuk report
Invoke-OFCaseSealWorkflow -Case $case   # versi tool -> manifest -> segel -> verifikasi
```

Dari CLI:

```powershell
.\case.ps1 -CaseId <id> -Seal
.\case.ps1 -CaseId <id> -VerifyIntegrity     # exit code 3 bila integritas bermasalah
```

Blok `Format-OFIntegritySummary` juga otomatis menjadi bagian konteks yang dikirim ke AI,
sehingga AI wajib menyebut bila kesimpulannya berdiri di atas bukti yang integritasnya
dipertanyakan.

## Keterbatasan yang harus dipahami

- Manifest membuktikan berkas tidak berubah **sejak manifest dibuat**, bukan sejak bukti
  diambil dari sistem asal.
- Segel DPAPI terikat akun dan mesin.
- Allowlist hanya sebaik sumber hash yang Anda impor.
- Write-block lunak dapat dilewati oleh proses dengan hak administratif.
