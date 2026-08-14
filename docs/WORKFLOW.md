# Alur Kerja End-to-End OpenForensic

Seluruh pemeriksaan berpusat pada satu objek: **KASUS**. Semua bukti, eksekusi tool,
artefak, temuan, timeline, chain of custody, dan hasil AI tersimpan dalam satu file
`cases/<CaseId>/case.json` sehingga pemeriksaan bisa dihentikan dan dilanjutkan kapan
saja, dan report selalu dapat dibangun ulang dari data yang sama.

```
  (1) KASUS          New-OFCase / menu 1 / case.ps1
        |
  (2) BUKTI          Add-OFCaseEvidence   -> hash MD5/SHA1/SHA256, tipe via magic bytes,
        |                                    salinan terverifikasi, chain of custody
  (3) TOOL           Invoke-OFEvidenceAnalysis -> pilih tool dari tools.json sesuai tipe file
        |                                          (atau AI yang memilih), log per eksekusi
  (4) ARTEFAK        Find-OFArtifact      -> 31 detektor: URL, IOC, kredensial, LOLBin,
        |                                    persistence, makro, flag CTF, prompt injection
  (5) TEMUAN         Add-OFCaseFinding    -> artefak severity high/critical naik jadi finding;
        |                                    AI menambah finding hasil korelasi
  (6) REPORT         Export-OFCaseReport  -> Markdown + HTML, 9 bagian, siap dilampirkan
```

## 1. Struktur folder kasus

```
cases/CASE-20260814-231500-Insiden_A/
  case.json          # seluruh state kasus (sumber tunggal kebenaran)
  evidence/          # salinan bukti (bila -CopyEvidence)
  logs/              # log mentah tiap eksekusi tool (E001_strings_231502.log)
  artifacts/         # output tool yang menulis file (bulk_extractor, jadx, MFTECmd)
  ai/                # respons AI mentah dalam JSON
  exports/           # report_YYYYMMDD_HHMMSS.md dan .html
```

Folder `cases/` masuk `.gitignore` karena memuat data bukti.

## 2. Cara tercepat: satu perintah

```powershell
# Satu bukti, alur penuh, report otomatis
.\case.ps1 -Path .\bukti\dump.raw -CaseName "Insiden Workstation A"

# Banyak bukti + salinan terverifikasi + analisa AI
.\case.ps1 -Path .\bukti\*.docx -CaseName "Phishing Batch" -CopyEvidence -UseAi

# AI yang memilih tool berikutnya, tiap rencana disetujui pemeriksa
.\case.ps1 -Path .\bukti\suspect.exe -CaseName "Malware Triage" -GuidedAi

# Lanjutkan kasus lama
.\case.ps1 -List
.\case.ps1 -CaseId CASE-20260814-231500-Insiden_A -AddEvidence .\bukti\baru.evtx -Analyze
.\case.ps1 -CaseId CASE-20260814-231500-Insiden_A -AiAnalyze -Report
```

## 3. Lewat menu interaktif

```powershell
.\openforensic.bat      # atau: .\menu.ps1
```

- Menu 1: kasus baru + alur end-to-end
- Menu 2-7: tambah bukti, analisa, tool tunggal, lihat temuan, ekspor report
- Menu 8-12: lapisan AI (analisa, guided analysis, assistant, report, konfigurasi)
- Menu 13-17: utilitas (analisa cepat tanpa kasus, status tool, update, hapus API key)

## 4. Lewat PowerShell (paling fleksibel)

```powershell
Import-Module .\OpenForensic.psd1 -Force

$case = New-OFCase -Name 'Insiden Workstation A' -Reference 'TIKET-1234' -Classification confidential
$e1   = Add-OFCaseEvidence -Case $case -Path .\bukti\dump.raw -Copy
$e2   = Add-OFCaseEvidence -Case $case -Path .\bukti\invoice.docm -Copy

Invoke-OFEvidenceAnalysis -Case $case -EvidenceId $e1.id                       # otomatis sesuai tipe
Invoke-OFEvidenceAnalysis -Case $case -EvidenceId $e1.id -ToolIds vol -Plugin windows.malfind
Invoke-OFEvidenceAnalysis -Case $case -EvidenceId $e2.id -AllTools              # semua tool yang cocok

Add-OFCaseFinding -Case $case -Title 'Makro mengunduh payload dari 185.x.x.x' `
    -Severity critical -Category execution -EvidenceId $e2.id `
    -Indicator 'URLDownloadToFile' -Origin analyst -Confidence high

Add-OFCaseTimelineEntry -Case $case -Timestamp '2026-08-14T09:12:00Z' `
    -Event 'Dokumen dibuka oleh korban' -Source 'wawancara' -EvidenceId $e2.id

Invoke-OFAiCaseAnalysis -Case $case          # AI korelasi + ringkasan eksekutif
Export-OFCaseReport -Case $case -Format Both -IncludeArtifacts
```

## 5. Pemilihan tool otomatis

`Get-OFApplicableTool` mencocokkan bukti dengan katalog `tools.json` berdasarkan:

1. `kind` hasil deteksi **magic bytes** (bukan ekstensi, sehingga file yang diganti
   ekstensinya tetap terdeteksi benar),
2. `kind` tambahan dari ekstensi khusus (`.evtx`, `.db`, `.apk`, `.hive`, `.dd`, ...),
3. daftar `extensions` pada definisi tool.

Mode default hanya menjalankan tool bertanda `triage: true` (cepat, aman, output ringkas).
`-AllTools` menjalankan semua tool yang cocok dan terpasang. Tool yang belum terpasang
dilewati dengan menampilkan `installHint`, bukan menggagalkan alur.

## 6. Detektor artefak

`Find-OFArtifact` menjalankan 31 detektor regex atas seluruh output tool. Kategori:

| Kategori | Contoh detektor |
|---|---|
| network | url, domain, ipv4, onion_address |
| identity | email |
| filesystem | windows_path, unc_path |
| persistence | registry_autorun, service_create, scheduled_task |
| execution | powershell_encoded, powershell_download, lolbin |
| macro | vba_autoexec, vba_suspicious |
| document | pdf_active_content |
| embedded | embedded_pe |
| encoding | base64_blob |
| credential | private_key, aws_access_key, jwt, credential_pair, ntlm_hash_line |
| crypto | bitcoin_address, ethereum_address |
| malware | ransom_note_hint, offensive_tool |
| ctf | ctf_flag |
| hash | md5_hash, sha256_hash |
| antiforensic | prompt_injection |

Artefak dengan severity `high` atau `critical` otomatis dipromosikan menjadi temuan,
dikelompokkan per tipe agar report tidak dibanjiri duplikasi.

## 7. Integritas bukti dan chain of custody

- Hash dihitung saat bukti didaftarkan dan **dihitung ulang setelah analisis**. Bila
  berubah, otomatis muncul temuan severity `critical`.
- Bila `-CopyEvidence` dipakai, SHA256 salinan diverifikasi identik; bila tidak, proses
  dibatalkan dengan error.
- Setiap aksi (kasus dibuat, bukti ditambah, bukti dianalisis, report diekspor) dicatat
  di `chainOfCustody` beserta waktu, user, dan hostname.
- Ekstensi yang tidak cocok dengan magic bytes langsung menjadi temuan `medium`.

## 8. Isi report

1. Ringkasan eksekutif (verdict otomatis + ringkasan AI bila ada)
2. Daftar bukti dengan hash lengkap dan status integritas
3. Metode dan tool yang digunakan (exit code, durasi, path log)
4. Temuan berurut severity, dengan indikator dan MITRE ATT&CK
5. Artefak terekstraksi (opsional)
6. Timeline
7. Chain of custody
8. Analisis naratif dibantu AI (bila diaktifkan)
9. Keterbatasan dan pernyataan

Verdict otomatis: `BERBAHAYA` bila ada temuan critical, `MENCURIGAKAN (PRIORITAS TINGGI)`
bila ada high, `PERLU PEMERIKSAAN LANJUTAN` bila ada medium, sisanya `BERSIH`.
