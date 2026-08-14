# AI Assistance pada OpenForensic

AI di OpenForensic bukan sekadar "rangkum report". AI dipakai pada empat titik dalam alur
kerja, dan semuanya dibatasi oleh pagar keamanan yang eksplisit.

| Kemampuan | Fungsi | Kegunaan |
|---|---|---|
| Perencana tool | `Invoke-OFAiToolPlan` | AI memilih tool BERIKUTNYA dari `tools.json` beserta plugin dan alasannya |
| Analisis terpandu | `Invoke-OFAiGuidedAnalysis` | Loop: AI merencanakan -> pemeriksa menyetujui -> tool dijalankan -> hasil di-feed balik |
| Analis kasus | `Invoke-OFAiCaseAnalysis` | Korelasi artefak menjadi temuan, buang positif palsu, verdict + ringkasan eksekutif |
| Penulis report | `New-OFAiCaseReport` | Analisa lalu ekspor report Markdown + HTML dengan narasi AI |
| Assistant interaktif | `Start-OFAiAssistant` | Tanya jawab kasus + aksi `/plan`, `/run`, `/analyze`, `/report` |

## 1. Empat pagar keamanan yang tidak bisa ditembus

1. **AI tidak pernah mengeksekusi command bebas.** AI hanya boleh mengembalikan `toolId`
   yang ada di `tools.json`. Id yang tidak dikenal ditolak dengan warning, plugin yang
   tidak terdaftar diganti default. Argumen dibangun oleh modul dari `argTemplate`,
   bukan oleh AI. Tidak ada `Invoke-Expression` di seluruh repo (dijaga oleh CI).
2. **Persetujuan eksplisit sebelum data keluar.** `Confirm-OFAiConsent` menampilkan
   provider, model, jenis data, dan klasifikasi kasus. Kasus berklasifikasi
   `confidential`/`restricted` diberi peringatan merah dan saran memakai provider lokal.
3. **Pagar prompt injection.** Semua data bukti dibungkus
   `<<<BEGIN_UNTRUSTED_EVIDENCE>>>` / `<<<END_UNTRUSTED_EVIDENCE>>>`, dan system prompt
   memerintahkan model menolak instruksi di dalamnya serta melaporkannya sebagai temuan
   `Indikasi prompt injection` (severity high).
4. **Output AI selalu ditandai indikatif.** Temuan dari AI diberi prefix `[AI]`, field
   `origin = ai`, dan report memuat pernyataan bahwa setiap klaim wajib diverifikasi
   terhadap log tool.

## 2. Memilih provider

```powershell
# Cloud gratis (butuh API key dari https://aistudio.google.com/app/apikey)
Set-OFAiConfig -Provider gemini -Model gemini-1.5-flash

# OpenAI / Azure / OpenRouter / LM Studio (apa pun yang OpenAI-compatible)
Set-OFAiConfig -Provider openai -Model gpt-4o-mini -Endpoint https://api.openai.com/v1

# LOKAL - data bukti tidak pernah meninggalkan mesin (disarankan untuk perkara nyata)
Set-OFAiConfig -Provider ollama -Model llama3.1 -Endpoint http://localhost:11434

# Redaksi otomatis email, token, AWS key, JWT, private key sebelum dikirim
Set-OFAiConfig -Redact $true
```

Konfigurasi tersimpan di `.ai_settings.json` (tidak memuat rahasia, tetapi tetap di
`.gitignore`). API key **tidak** disimpan di sana: key dienkripsi DPAPI di `.ai_config`
atau dibaca dari environment variable `OPENFORENSIC_AI_KEY`, `GEMINI_API_KEY`,
`OPENAI_API_KEY`.

Untuk provider `ollama`, tidak ada API key dan tidak ada layar konsen karena tidak ada
data yang keluar dari mesin.

## 3. Contoh pemakaian

```powershell
Import-Module .\OpenForensic.psd1 -Force
$case = Get-OFCase -CaseId CASE-20260814-231500-Insiden_A

# AI mengusulkan tool berikutnya untuk satu bukti
Invoke-OFAiToolPlan -Case $case -EvidenceId E001 |
    Format-Table Priority, ToolId, Plugin, Reason -AutoSize

# Loop terpandu: 2 ronde, tiap rencana minta persetujuan
Invoke-OFAiGuidedAnalysis -Case $case -EvidenceId E001 -MaxRounds 2

# Korelasi seluruh artefak & temuan menjadi verdict + ringkasan eksekutif
Invoke-OFAiCaseAnalysis -Case $case

# Analisa + ekspor report sekaligus
New-OFAiCaseReport -Case $case -Format Both

# Sesi interaktif
Start-OFAiAssistant -Case $case
```

Di dalam assistant:

```
AI> /evidence                       daftar bukti
AI> /plan E001                      AI usulkan tool berikutnya
AI> /run E001 olevba                jalankan satu tool (minta konfirmasi)
AI> /analyze                        AI analisa seluruh kasus
AI> /findings                       lihat temuan
AI> /report                         ekspor report
AI> apakah dokumen ini bagian dari kampanye phishing yang sama?
AI> /exit
```

## 4. Skema jawaban AI untuk analisis kasus

AI diminta membalas JSON ketat, lalu divalidasi modul sebelum masuk ke kasus:

```json
{
  "verdict": "BERSIH|MENCURIGAKAN|BERBAHAYA",
  "confidence": "low|medium|high",
  "executiveSummary": "...",
  "narrative": "markdown beberapa paragraf",
  "findings": [{ "title": "...", "severity": "high", "category": "execution",
                  "evidenceId": "E001", "indicator": "...", "description": "...",
                  "confidence": "medium", "mitre": "T1059.001" }],
  "falsePositives": [{ "indicator": "...", "reason": "..." }],
  "nextSteps": ["..."],
  "promptInjectionDetected": false
}
```

Validasi yang dilakukan modul: severity dan confidence harus nilai yang sah (jika tidak,
diganti default), `evidenceId` harus benar-benar ada di kasus (jika tidak, dikosongkan),
dan respons mentah disimpan di `cases/<CaseId>/ai/analysis_*.json` untuk audit.

## 5. Batasan yang harus disadari

- LLM dapat berhalusinasi. Tidak ada temuan AI yang boleh dipakai sebagai bukti tanpa
  diverifikasi pada log tool di folder `logs/`.
- Untuk perkara dengan chain of custody yang ketat, gunakan provider lokal (Ollama) atau
  matikan lapisan AI sepenuhnya. Alur kerja tetap berfungsi penuh tanpa AI.
- Data yang dikirim dibatasi 60.000 karakter (dapat dipotong). Untuk bukti besar, AI
  bekerja atas ringkasan artefak dan temuan, bukan seluruh dump.
