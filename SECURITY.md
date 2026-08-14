# Kebijakan Keamanan

## Melaporkan kerentanan

Jangan membuka issue publik untuk kerentanan keamanan. Gunakan
[GitHub Private Vulnerability Reporting](https://github.com/stmarya/OpenForensic/security/advisories/new)
atau hubungi maintainer secara privat.

Sertakan: versi toolkit, versi PowerShell & Python, langkah reproduksi, dan dampak.
Target respons awal: 7 hari.

## Model ancaman

Toolkit ini memproses **file yang tidak dipercaya secara desain** (malware, dokumen
ber-macro, memory dump, artefak CTF). Asumsi keamanan:

| Ancaman | Mitigasi |
|---|---|
| Command injection via nama file bukti | Tidak ada `Invoke-Expression`. Semua eksekusi memakai call operator + array argumen; nama file tidak pernah di-*re-parse* shell. Semua path memakai `-LiteralPath`. |
| Prompt injection dari isi bukti | Isi report dibungkus delimiter ber-nonce acak; system prompt melarang model mengikuti instruksi di dalam data. |
| Kebocoran kredensial | API key hanya dari environment variable atau file DPAPI-encrypted; dikirim lewat HTTP header, bukan URL. `.ai_config*` di-gitignore. Migrasi otomatis dari plaintext lalu file lama dihapus. |
| Kebocoran data bukti | Tidak ada trafik jaringan tanpa konfirmasi eksplisit. Provider LLM lokal (Ollama) didukung. `reports/`, `evidence/`, `cases/` di-gitignore. |
| Modifikasi bukti | File bukti dibuka read-only; hash dihitung sebelum analisis dan dicatat ke chain-of-custody log yang bersifat append-only. |

## Di luar cakupan

- Kerentanan pada tool pihak ketiga (Volatility 3, oletools, ExifTool, dsb.) —
  laporkan ke upstream masing-masing.
- Eksekusi kode yang berasal dari file bukti melalui parser tool pihak ketiga.
  **Selalu jalankan analisis malware di dalam VM/sandbox yang terisolasi.**
- Penyalahgunaan toolkit pada sistem tanpa izin.

## Praktik yang direkomendasikan

1. Jalankan di VM terisolasi tanpa akses ke jaringan produksi.
2. Gunakan `OF_AI_PROVIDER=ollama` untuk data sensitif.
3. Simpan salinan bukti asli read-only di luar folder kerja; verifikasi hash sebelum & sesudah.
4. Jangan pernah menjalankan toolkit sebagai Administrator kecuali benar-benar diperlukan.
