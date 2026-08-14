# Fixtures pengujian

Berkas di folder ini adalah **bukti sintetis** yang dibuat khusus untuk regression test.
Tidak ada data kasus nyata, tidak ada malware nyata, dan tidak ada data pribadi.

| Berkas | Dipakai untuk |
| --- | --- |
| `sample_strings.txt` | Detektor artefak: URL, IP, domain, email, bitcoin, onion, hash, kredensial |
| `sample_prompt_injection.txt` | Detektor prompt injection dan pemetaan MITRE ATLAS `AML.T0051` |
| `hayabusa_sample.csv` | `Import-OFTimelineCsv` sumber `hayabusa` dan pemetaan MITRE ATT&CK |
| `mftecmd_sample.csv` | `Import-OFTimelineCsv` sumber `mftecmd` (kolom `Created0x10`) |
| `allowlist_sample.txt` | `Import-OFHashAllowlist` |

Semua berkas memakai akhir baris LF dan encoding UTF-8 tanpa BOM agar hasil test
identik di Windows, Linux, dan macOS.
