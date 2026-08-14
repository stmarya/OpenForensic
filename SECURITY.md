# Security Policy

## Melaporkan kerentanan

Jangan buka issue publik untuk kerentanan. Gunakan fitur **GitHub Security Advisories**
(Security -> Report a vulnerability) pada repo ini. Sertakan langkah reproduksi,
versi PowerShell/Windows, dan dampaknya.

## Model ancaman singkat

OpenForensic menjalankan tool pihak ketiga terhadap **file yang berpotensi jahat**.
Asumsi keamanan yang dipakai:

1. **Nama & isi file target tidak dipercaya.** Semua argumen dilewatkan sebagai array
   ke operator `&`; `Invoke-Expression` dilarang di seluruh basis kode (ditegakkan oleh PSScriptAnalyzer).
2. **Isi report tidak dipercaya.** Report berisi output tool yang berasal dari file jahat.
   Saat dikirim ke LLM, isinya dibungkus delimiter eksplisit dan model diinstruksikan untuk
   tidak mengeksekusi instruksi di dalamnya (mitigasi prompt injection).
3. **Secret tidak boleh masuk repo.** `.ai_config`, `bin/`, `reports/`, dan `volatility3/`
   ada di `.gitignore`. API key disimpan terenkripsi DPAPI, bukan plaintext.
4. **Data bukti tidak dikirim tanpa persetujuan.** Pengiriman ke API eksternal selalu
   meminta konfirmasi interaktif (kecuali dipanggil eksplisit dengan `-Force`).

## Rekomendasi operasional

- Jalankan analisis malware di VM terisolasi atau sandbox, bukan di host kerja.
- Jangan jalankan sebagai Administrator kecuali benar-benar diperlukan.
- Untuk perkara nyata, matikan fitur AI dan simpan `reports/` beserta hash pada media WORM.
