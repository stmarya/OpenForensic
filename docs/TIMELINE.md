# Super-Timeline, MITRE ATT&CK, dan Ekspor IOC

Modul `OpenForensic.Timeline.psm1` mengubah output tool yang terpisah-pisah menjadi satu
urutan kejadian yang bisa dibaca sebagai cerita.

## Skema kejadian ternormalisasi

Semua sumber dipetakan ke bentuk yang sama:

| Kolom | Arti |
| --- | --- |
| `timestamp` | ISO-8601 UTC hasil normalisasi |
| `source` / `sourceType` | asal data (hayabusa, chainsaw, mftecmd, filesystem, openforensic) dan jenisnya (tool, evidence, finding, custody, examiner) |
| `actor` | pengguna, host, atau IP yang bertindak |
| `action` | apa yang terjadi (nama rule, event id, aksi pemeriksa) |
| `target` | berkas, proses, atau tujuan |
| `detail` | konteks tambahan (dipotong 500 karakter) |
| `severity` / `severityRank` | info, low, medium, high, critical |
| `evidenceId` | keterkaitan ke bukti kasus |
| `mitre` | daftar id teknik ATT&CK |

## Membangun timeline

```powershell
$case = Get-OFCase -CaseId CASE-20260815-001500-Insiden

# 1. Dari state kasus (bukti, chain of custody, temuan, opsional aksi pemeriksa)
Import-OFTimelineFromCase -Case $case -IncludeExaminerActions

# 2. Dari CSV keluaran tool (kolom waktu dideteksi otomatis)
Import-OFTimelineCsv -Case $case -Path .\hayabusa.csv
Import-OFTimelineCsv -Case $case -Path .\mft.csv -Source mftecmd -EvidenceId E002

# 3. Sekaligus: state kasus + semua CSV di folder artifacts + pemetaan MITRE
Invoke-OFTimelineWorkflow -Case $case -IncludeExaminerActions
```

Dari CLI: `.\case.ps1 -CaseId <id> -Timeline -ExportTimeline Csv`

## Membaca dan mengekspor

```powershell
Get-OFTimeline -Case $case -MinSeverity medium -Deduplicate | Format-Table
Get-OFTimeline -Case $case -From (Get-Date).AddDays(-7) -Source hayabusa
Export-OFTimeline -Case $case -Format Markdown     # juga Csv dan Json
```

## Pemetaan MITRE ATT&CK

Pemetaan bersifat **deterministik**, bukan tebakan model:

1. Nama detektor artefak dan judul/kategori temuan dicocokkan ke tabel teknik.
2. Teknik yang disebut langsung oleh tool (capa, Hayabusa/Sigma, Chainsaw) diambil apa
   adanya dengan pola `T####[.###]`.

```powershell
Update-OFCaseMitre -Case $case          # tempelkan ke tiap temuan + rangkum di kasus
Get-OFMitreSummary -Case $case          # dikelompokkan per taktik
Get-OFMitreTechnique -Text 'schtasks /create ... powershell -enc'
```

Indikasi prompt injection dipetakan ke MITRE ATLAS `AML.T0051`, bukan ke ATT&CK
perusahaan, karena sasarannya adalah lapisan AI.

## Ekspor IOC

```powershell
Export-OFCaseIoc -Case $case -Format Csv    # untuk spreadsheet
Export-OFCaseIoc -Case $case -Format Stix   # bundle STIX 2.1 indicator
Export-OFCaseIoc -Case $case -Format Misp   # objek Event MISP siap impor
Export-OFCaseIoc -Case $case -Format Json
```

Hanya artefak bertipe indikator yang diekspor (url, domain, ipv4, email, onion, md5,
sha256, alamat kripto). Artefak seperti flag CTF, path lokal, dan indikasi prompt
injection sengaja tidak diekspor karena bukan IOC yang dapat dibagikan.

Pada ekspor MISP, `to_ids` hanya diaktifkan untuk indikator severity high/critical agar
tidak mencemari deteksi dengan data berisik.

## Integrasi dengan AI

`Get-OFTimelineContext -Case $case -MaxEvents 200` menghasilkan blok teks kompak yang
menjadi bagian konteks `Invoke-OFAiDeepAnalysis`. Bila jumlah kejadian melebihi batas,
kejadian severity medium ke atas diprioritaskan lalu diurutkan ulang secara kronologis,
sehingga AI tetap melihat alur waktu dan bukan sekadar cuplikan acak.

## Keterbatasan

- Zona waktu: nilai tanpa offset diasumsikan UTC. Pastikan tool dijalankan dengan
  keluaran UTC bila memungkinkan.
- Deteksi kolom waktu bersifat heuristik; gunakan `-Source` bila format tidak standar.
- Timeline bukan pengganti Plaso/log2timeline untuk artefak disk penuh; cakupannya adalah
  keluaran tool yang ada di katalog OpenForensic.
