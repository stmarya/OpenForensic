#!/usr/bin/env bash
#
# OpenForensic - launcher untuk Linux dan macOS (padanan openforensic.bat di Windows).
#
# Pemakaian:
#   ./openforensic.sh                 # menu interaktif
#   ./openforensic.sh case -List      # teruskan argumen ke case.ps1
#   ./openforensic.sh run <berkas>    # teruskan argumen ke run.ps1
#   ./openforensic.sh doctor          # cek kompatibilitas platform
#
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

if ! command -v pwsh >/dev/null 2>&1; then
  printf '[-] PowerShell 7 (pwsh) tidak ditemukan.\n' >&2
  printf '    Pasang dengan ./setup_tools.sh, ikuti docs/CROSS-PLATFORM.md,\n' >&2
  printf '    atau jalankan lewat Docker: docker compose run --rm openforensic\n' >&2
  exit 2
fi

MODE="${1:-menu}"
if [ $# -gt 0 ]; then shift; fi

case "$MODE" in
  menu)
    exec pwsh -NoLogo -NoProfile -ExecutionPolicy Bypass -File "$ROOT_DIR/menu.ps1" "$@"
    ;;
  case)
    exec pwsh -NoLogo -NoProfile -ExecutionPolicy Bypass -File "$ROOT_DIR/case.ps1" "$@"
    ;;
  run)
    exec pwsh -NoLogo -NoProfile -ExecutionPolicy Bypass -File "$ROOT_DIR/run.ps1" "$@"
    ;;
  doctor)
    exec pwsh -NoLogo -NoProfile -ExecutionPolicy Bypass -Command \
      "Import-Module '$ROOT_DIR/OpenForensic.psd1' -Force -DisableNameChecking; Get-OFPlatform | Format-List; Test-OFPlatformCompatibility | Format-Table Feature, Supported, Notes -AutoSize"
    ;;
  -h|--help|help)
    sed -n '2,12p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'
    ;;
  *)
    printf '[-] Mode tidak dikenal: %s (gunakan menu, case, run, doctor)\n' "$MODE" >&2
    exit 2
    ;;
esac
