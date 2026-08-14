# Menambahkan Model AI Sendiri

OpenForensic tidak mengikat Anda pada satu penyedia AI. Modul `OpenForensic.Models.psm1`
menyediakan registry profil model: Anda mendaftarkan endpoint dan nama model sendiri,
lalu berpindah model dengan satu perintah.

Profil disimpan di `.ai_models.json` (masuk `.gitignore`). **API key tidak pernah disimpan
di berkas ini** - yang dicatat hanya nama variabel environment tempat key berada.

## Tiga protokol dasar

Setiap model dipetakan ke salah satu protokol yang benar-benar diimplementasikan:

| BaseProvider | Untuk siapa |
| --- | --- |
| `openai` | Semua layanan OpenAI-compatible: OpenAI, Azure OpenAI, OpenRouter, Groq, Together, DeepSeek, Mistral, LM Studio, vLLM, llama.cpp |
| `gemini` | Google Generative Language API |
| `ollama` | Ollama lokal |

Catatan jujur: API native Anthropic (Claude) **tidak** OpenAI-compatible. Gunakan Claude
melalui OpenRouter atau proxy OpenAI-compatible; itu jalur yang didukung saat ini.

## Preset siap pakai

```powershell
Get-OFAiModelPreset | Format-Table Preset, BaseProvider, Endpoint, Model, KeyEnvVar, Local
Initialize-OFAiModelDefaults        # daftarkan gemini, openai, ollama sekaligus
```

Preset tersedia: `openai`, `azure`, `openrouter`, `groq`, `together`, `deepseek`,
`mistral`, `gemini`, `lmstudio`, `vllm`, `ollama`.

## Mendaftarkan model

```powershell
# Dari preset, ganti model saja
Register-OFAiModel -Preset groq -Name cepat -Model llama-3.3-70b-versatile

# Manual sepenuhnya (endpoint internal perusahaan)
Register-OFAiModel -Name internal -BaseProvider openai `
    -Model qwen2.5-72b-instruct `
    -Endpoint https://ai.perusahaan.local/v1 `
    -KeyEnvVar PERUSAHAAN_AI_KEY `
    -Temperature 0.1 -MaxTokens 8192 `
    -Notes 'Server GPU internal, boleh untuk kasus confidential'

# Model lokal (tidak butuh API key)
Register-OFAiModel -Preset ollama -Name lokal -Model qwen2.5:14b
Register-OFAiModel -Preset lmstudio -Name lmstudio -Model llama-3.1-8b-instruct
```

Set API key sebagai variabel environment, bukan di berkas:

```powershell
$env:PERUSAHAAN_AI_KEY = '<key>'                     # sesi ini saja
[Environment]::SetEnvironmentVariable('PERUSAHAAN_AI_KEY', '<key>', 'User')  # permanen
```

## Memakai, menguji, menghapus

```powershell
Get-OFAiModelList | Format-Table Name, Active, BaseProvider, Model, Local, KeyReady
Use-OFAiModel -Name lokal            # aktifkan
Test-OFAiModel -Name internal        # ping + latensi, tanpa mengirim data bukti
Test-OFAiModelAll                    # uji semua profil sekaligus
Remove-OFAiModel -Name cepat
```

Dari CLI:

```powershell
.\case.ps1 -ListModels
.\case.ps1 -TestModels
.\case.ps1 -Path .\bukti\* -CaseName "Insiden" -Complete -DeepAi -Model lokal -Seal
```

`Use-OFAiModel` menyalin nilai variabel environment profil ke `OPENFORENSIC_AI_KEY` untuk
sesi berjalan, sehingga lapisan AI yang sudah ada dapat membacanya tanpa perubahan
konfigurasi manual.

## Rekomendasi pemilihan model per klasifikasi kasus

| Klasifikasi kasus | Rekomendasi |
| --- | --- |
| `public`, `internal` | Model cloud apa pun; utamakan yang mendukung JSON mode |
| `confidential` | Endpoint internal perusahaan atau model lokal |
| `restricted` | **Hanya** model lokal (`ollama`, `lmstudio`, `vllm`) |

Untuk kasus `confidential` dan `restricted`, lapisan persetujuan akan menampilkan
peringatan merah bila provider yang aktif bukan lokal. Model lokal dilewati dari dialog
persetujuan karena data tidak meninggalkan mesin.

## Analisis AI mendalam

Setelah model aktif, gunakan analisis yang memakai seluruh konteks kasus:

```powershell
Get-OFAiCaseContext -Case $case | Select-Object -ExpandProperty TrustedContext
Invoke-OFAiDeepAnalysis -Case $case
```

Berbeda dari `Invoke-OFAiCaseAnalysis` (fokus artefak dan temuan), `Invoke-OFAiDeepAnalysis`
mengirim juga:

- timeline ternormalisasi (kronologi kejadian),
- teknik MITRE ATT&CK yang sudah terpetakan secara deterministik,
- status integritas bukti dan segel kasus.

Keluarannya berisi kronologi naratif, penilaian dampak, catatan integritas, kesenjangan
bukti, temuan `[AI]` yang masuk ke kasus, dan langkah investigasi berikutnya.

## Batas keamanan yang tetap berlaku

1. AI hanya boleh memilih **id tool** dari `tools.json`; argumen dibangun oleh modul.
2. Data bukti selalu dipagari `<<<BEGIN_UNTRUSTED_EVIDENCE>>>` dan model diinstruksikan
   menolak instruksi di dalamnya.
3. Tidak ada data yang dikirim tanpa persetujuan eksplisit, kecuali provider lokal.
4. Endpoint HTTP non-lokal memicu peringatan saat pendaftaran; gunakan HTTPS.
5. Seluruh keluaran AI ditandai indikatif dan wajib diverifikasi pada log tool.
