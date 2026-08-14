#!/usr/bin/env bash
#
# OpenForensic - installer tool pihak ketiga untuk Linux dan macOS.
#
# Pendamping setup_tools.ps1 (Windows). Script ini:
#   - mendeteksi package manager (apt, dnf, pacman, zypper, apk, brew)
#   - mendeteksi arsitektur (x86_64, arm64/aarch64) dan memilih aset rilis yang cocok
#   - memasang PowerShell 7 bila belum ada (OpenForensic butuh pwsh di non-Windows)
#   - memasang tool DFIR dari repositori distribusi dan pip
#   - mengunduh rilis biner lintas platform (Hayabusa, Chainsaw, Stegseek) ke ./bin
#   - mencatat SHA256 setiap unduhan ke bin/_downloads.log
#   - menutup dengan rekap BERHASIL/GAGAL/DILEWATI dan exit code yang bermakna
#
# Tidak ada eksekusi script pihak ketiga secara langsung (tidak ada curl | bash).
#
# Pemakaian:
#   ./setup_tools.sh                  # pemasangan standar
#   ./setup_tools.sh --skip-python    # lewati paket pip
#   ./setup_tools.sh --skip-download  # lewati unduhan rilis GitHub
#   ./setup_tools.sh --only yara,capa # hanya komponen tertentu
#   ./setup_tools.sh --list           # hanya tampilkan status
#   ./setup_tools.sh --ignore-errors  # selalu exit 0 walau ada kegagalan
#
# Exit code: 0 = tidak ada kegagalan, 1 = ada komponen yang gagal, 2 = argumen salah.
#
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BIN_DIR="$ROOT_DIR/bin"
RULES_DIR="$ROOT_DIR/rules"
LOG_FILE="$BIN_DIR/_downloads.log"

SKIP_PYTHON=0
SKIP_PACKAGES=0
SKIP_DOWNLOAD=0
SKIP_PWSH=0
ASSUME_YES=0
IGNORE_ERRORS=0
ONLY_LIST=""
LIST_ONLY=0

PKG=""
SUDO=""
OS_NAME="$(uname -s)"
ARCH_RAW="$(uname -m)"
ARCH_KIND="unknown"

# Rekap hasil
RESULT_OK=()
RESULT_FAIL=()
RESULT_SKIP=()

info() { printf '[i] %s\n' "$1"; }
ok()   { printf '[+] %s\n' "$1"; }
warn() { printf '[!] %s\n' "$1" >&2; }
fail() { printf '[-] %s\n' "$1" >&2; }

record_ok()   { RESULT_OK+=("$1"); ok "$1"; }
record_fail() { RESULT_FAIL+=("$1: $2"); fail "$1: $2"; }
record_skip() { RESULT_SKIP+=("$1: $2"); info "$1 dilewati ($2)"; }

have() { command -v "$1" >/dev/null 2>&1; }

wanted() {
  if [ -z "$ONLY_LIST" ]; then return 0; fi
  case ",$ONLY_LIST," in
    *",$1,"*) return 0 ;;
    *) return 1 ;;
  esac
}

usage() {
  sed -n '2,32p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'
  exit 0
}

while [ $# -gt 0 ]; do
  case "$1" in
    --skip-python) SKIP_PYTHON=1 ;;
    --skip-packages) SKIP_PACKAGES=1 ;;
    --skip-download) SKIP_DOWNLOAD=1 ;;
    --skip-pwsh) SKIP_PWSH=1 ;;
    --yes|-y) ASSUME_YES=1 ;;
    --ignore-errors) IGNORE_ERRORS=1 ;;
    --only) shift; ONLY_LIST="${1:-}" ;;
    --list) LIST_ONLY=1 ;;
    -h|--help) usage ;;
    *) fail "Opsi tidak dikenal: $1"; exit 2 ;;
  esac
  shift
done

detect_arch() {
  case "$ARCH_RAW" in
    x86_64|amd64) ARCH_KIND="x64" ;;
    aarch64|arm64) ARCH_KIND="arm64" ;;
    armv7l|armv7) ARCH_KIND="arm" ;;
    *) ARCH_KIND="unknown" ;;
  esac
}

detect_pkg() {
  if have brew; then PKG="brew"
  elif have apt-get; then PKG="apt"
  elif have dnf; then PKG="dnf"
  elif have pacman; then PKG="pacman"
  elif have zypper; then PKG="zypper"
  elif have apk; then PKG="apk"
  else PKG=""; fi

  if [ "$(id -u)" != "0" ] && [ "$PKG" != "brew" ] && have sudo; then
    SUDO="sudo"
  fi
}

pkg_install() {
  # pkg_install <nama-apt> <nama-dnf> <nama-pacman> <nama-brew>
  # Mengembalikan status asli package manager (tidak ditelan).
  local apt_name="$1" dnf_name="$2" pacman_name="$3" brew_name="$4" name=""
  case "$PKG" in
    apt)    name="$apt_name";    [ -n "$name" ] || return 3; $SUDO apt-get install -y "$name" ;;
    dnf)    name="$dnf_name";    [ -n "$name" ] || return 3; $SUDO dnf install -y "$name" ;;
    pacman) name="$pacman_name"; [ -n "$name" ] || return 3; $SUDO pacman -S --noconfirm --needed "$name" ;;
    zypper) name="$dnf_name";    [ -n "$name" ] || return 3; $SUDO zypper --non-interactive install "$name" ;;
    apk)    name="$apt_name";    [ -n "$name" ] || return 3; $SUDO apk add --no-cache "$name" ;;
    brew)   name="$brew_name";   [ -n "$name" ] || return 3; brew install "$name" ;;
    *) return 4 ;;
  esac
}

try_install() {
  # try_install <id-tool> <perintah-cek> <apt> <dnf> <pacman> <brew>
  local id="$1" probe="$2" apt_name="$3" dnf_name="$4" pacman_name="$5" brew_name="$6"
  if ! wanted "$id"; then return 0; fi
  if have "$probe"; then
    record_ok "$id sudah tersedia"
    return 0
  fi
  local status=0
  pkg_install "$apt_name" "$dnf_name" "$pacman_name" "$brew_name" >/dev/null 2>&1 || status=$?
  if [ "$status" -eq 0 ] && have "$probe"; then
    record_ok "$id terpasang"
  elif [ "$status" -eq 0 ]; then
    record_fail "$id" 'paket terpasang tetapi perintah belum ada di PATH'
  elif [ "$status" -eq 3 ]; then
    record_skip "$id" "tidak tersedia di package manager $PKG"
  elif [ "$status" -eq 4 ]; then
    record_skip "$id" 'tidak ada package manager yang dikenali'
  else
    record_fail "$id" "pemasangan gagal (status $status)"
  fi
}

log_download() {
  local url="$1" file="$2" hash="" size=""
  if have sha256sum; then hash="$(sha256sum "$file" | awk '{print $1}')"
  elif have shasum; then hash="$(shasum -a 256 "$file" | awk '{print $1}')"
  else hash="tidak-terhitung"; fi
  size="$(wc -c < "$file" | tr -d ' ')"
  mkdir -p "$BIN_DIR"
  printf '%s  SHA256=%s  bytes=%s  url=%s\n' "$(date '+%Y-%m-%d %H:%M:%S')" "$hash" "$size" "$url" >> "$LOG_FILE"
  info "Unduhan tercatat: SHA256=$hash"
}

github_release_assets() {
  # github_release_assets <owner/repo> -> daftar URL aset
  local repo="$1" auth=()
  if [ -n "${GITHUB_TOKEN:-}" ]; then auth=(-H "Authorization: Bearer $GITHUB_TOKEN"); fi
  curl -fsSL "${auth[@]}" "https://api.github.com/repos/$repo/releases/latest" \
    | grep 'browser_download_url' \
    | cut -d '"' -f 4
}

arch_patterns() {
  # Pola nama aset sesuai OS + arsitektur, dari paling spesifik ke paling umum.
  if [ "$OS_NAME" = "Darwin" ]; then
    case "$ARCH_KIND" in
      arm64) printf '%s\n' 'darwin.*arm64' 'mac.*arm64' 'aarch64.*apple' 'arm64.*darwin' 'mac' 'darwin' ;;
      x64)   printf '%s\n' 'darwin.*x86_64' 'mac.*x64' 'x86_64.*apple' 'mac' 'darwin' ;;
      *)     printf '%s\n' 'mac' 'darwin' ;;
    esac
  else
    case "$ARCH_KIND" in
      arm64) printf '%s\n' 'linux.*aarch64' 'linux.*arm64' 'aarch64.*linux' 'arm64.*linux' 'aarch64' 'arm64' ;;
      x64)   printf '%s\n' 'linux.*x86_64' 'linux.*amd64' 'x86_64.*linux' 'linux.*x64' 'linux' ;;
      *)     printf '%s\n' 'linux' ;;
    esac
  fi
}

select_asset_url() {
  # select_asset_url <owner/repo> [pola-tambahan]
  local repo="$1" extra="${2:-}" assets="" pattern="" url=""
  assets="$(github_release_assets "$repo" || true)"
  if [ -z "$assets" ]; then return 1; fi

  if [ -n "$extra" ]; then
    url="$(printf '%s\n' "$assets" | grep -Ei "$extra" | grep -Eiv 'sha256|\.asc$|\.sig$' | head -n 1 || true)"
    if [ -n "$url" ]; then printf '%s\n' "$url"; return 0; fi
  fi

  while IFS= read -r pattern; do
    [ -n "$pattern" ] || continue
    url="$(printf '%s\n' "$assets" | grep -Ei "$pattern" | grep -Eiv 'sha256|\.asc$|\.sig$' | head -n 1 || true)"
    if [ -n "$url" ]; then printf '%s\n' "$url"; return 0; fi
  done <<EOF
$(arch_patterns)
EOF
  return 1
}

install_release_archive() {
  # install_release_archive <id> <owner/repo> <subdir-bin> <nama-binari> [pola-tambahan]
  local id="$1" repo="$2" subdir="$3" binary="$4" extra="${5:-}"
  local url="" staging="" archive="" found=""

  if ! wanted "$id"; then return 0; fi
  if ! have curl; then record_skip "$id" 'curl tidak tersedia'; return 0; fi

  url="$(select_asset_url "$repo" "$extra" || true)"
  if [ -z "$url" ]; then
    record_skip "$id" "tidak ada aset rilis untuk $OS_NAME/$ARCH_RAW"
    return 0
  fi

  staging="$(mktemp -d)"
  archive="$staging/$(basename "$url")"
  info "Mengunduh $id dari $repo ..."
  if ! curl -fsSL -o "$archive" "$url"; then
    rm -rf "$staging"
    record_fail "$id" 'unduhan gagal'
    return 0
  fi
  log_download "$url" "$archive"
  mkdir -p "$BIN_DIR/$subdir"

  local extracted=0
  case "$archive" in
    *.zip)
      if have unzip; then unzip -oq "$archive" -d "$BIN_DIR/$subdir" && extracted=1; fi
      if [ "$extracted" -eq 0 ]; then record_fail "$id" 'unzip tidak tersedia atau ekstraksi gagal'; fi ;;
    *.tar.gz|*.tgz)
      if tar -xzf "$archive" -C "$BIN_DIR/$subdir"; then extracted=1; else record_fail "$id" 'ekstraksi tar.gz gagal'; fi ;;
    *.tar.xz)
      if tar -xJf "$archive" -C "$BIN_DIR/$subdir"; then extracted=1; else record_fail "$id" 'ekstraksi tar.xz gagal'; fi ;;
    *.deb)
      if [ "$PKG" = "apt" ] && $SUDO apt-get install -y "$archive"; then
        extracted=1
      else
        record_skip "$id" 'paket .deb hanya bisa dipasang di distribusi berbasis apt'
      fi ;;
    *)
      # Biner tunggal tanpa arsip.
      if cp "$archive" "$BIN_DIR/$subdir/$binary"; then extracted=1; else record_fail "$id" 'penyalinan biner gagal'; fi ;;
  esac
  rm -rf "$staging"
  if [ "$extracted" -eq 0 ]; then return 0; fi

  found="$(find "$BIN_DIR/$subdir" -maxdepth 3 -type f -name "$binary*" ! -name '*.md' ! -name '*.txt' | head -n 1 || true)"
  if [ -z "$found" ] && have "$binary"; then
    record_ok "$id tersedia dari sistem"
    return 0
  fi
  if [ -z "$found" ]; then
    record_fail "$id" 'binari tidak ditemukan di dalam arsip'
    return 0
  fi
  chmod +x "$found"
  ln -sf "$found" "$BIN_DIR/$binary"
  record_ok "$id siap di bin/$binary"
}

install_pwsh() {
  if have pwsh; then record_ok "PowerShell 7 sudah terpasang ($(pwsh --version))"; return 0; fi
  info 'Memasang PowerShell 7 ...'
  local status=0
  case "$PKG" in
    brew) { brew install --cask powershell || brew install powershell; } >/dev/null 2>&1 || status=$? ;;
    apt)
      if have snap; then $SUDO snap install powershell --classic >/dev/null 2>&1 || status=$?
      else
        record_skip 'pwsh' 'ikuti panduan resmi Microsoft atau pakai Docker (docs/CROSS-PLATFORM.md)'
        return 0
      fi ;;
    dnf) $SUDO dnf install -y powershell >/dev/null 2>&1 || status=$? ;;
    pacman) record_skip 'pwsh' 'pasang paket AUR powershell-bin atau pakai Docker'; return 0 ;;
    apk) record_skip 'pwsh' 'gunakan image mcr.microsoft.com/powershell untuk Alpine'; return 0 ;;
    *) record_skip 'pwsh' 'package manager tidak dikenali'; return 0 ;;
  esac
  if [ "$status" -eq 0 ] && have pwsh; then
    record_ok 'PowerShell 7 terpasang'
  else
    record_fail 'pwsh' 'pemasangan gagal - OpenForensic tidak dapat berjalan tanpa pwsh'
  fi
}

install_python_tools() {
  local python_bin=""
  if have python3; then python_bin="python3"
  elif have python; then python_bin="python"
  else
    record_skip 'paket pip' 'Python 3 tidak ditemukan'
    return 0
  fi
  info "Memasang paket forensik via pip ($python_bin) ..."
  local packages=(volatility3 oletools msoffcrypto-tool flare-capa flare-floss uncompyle6 decompyle3 binwalk)
  local package status
  for package in "${packages[@]}"; do
    if ! wanted "$package"; then continue; fi
    status=0
    "$python_bin" -m pip install --user --upgrade "$package" >/dev/null 2>&1 || status=$?
    if [ "$status" -eq 0 ]; then
      record_ok "pip: $package"
    else
      record_fail "pip: $package" 'gagal - coba virtualenv atau --break-system-packages'
    fi
  done
  info 'Pastikan direktori skrip pip ada di PATH, mis. $HOME/.local/bin.'
}

install_system_tools() {
  info "Memasang tool sistem dengan package manager: ${PKG:-tidak ada}"
  if [ "$PKG" = "apt" ]; then
    $SUDO apt-get update -qq >/dev/null 2>&1 || warn 'apt-get update gagal; melanjutkan dengan indeks paket yang ada.'
  fi

  try_install exiftool exiftool  libimage-exiftool-perl perl-Image-ExifTool perl-image-exiftool exiftool
  try_install 7z       7z        p7zip-full             p7zip               p7zip               p7zip
  try_install tshark   tshark    tshark                 wireshark-cli       wireshark-cli       wireshark
  try_install clamscan clamscan  clamav                 clamav              clamav              clamav
  try_install sqlite3  sqlite3   sqlite3                sqlite              sqlite              sqlite
  try_install yara     yara      yara                   yara                yara                yara
  try_install john     john      john                   john                john                john-jumbo
  try_install steghide steghide  steghide               steghide            steghide            steghide
  try_install pngcheck pngcheck  pngcheck               pngcheck            pngcheck            pngcheck
  try_install photorec photorec  testdisk               testdisk            testdisk            testdisk
  try_install rizin    rizin     rizin                  rizin               rizin               rizin
  try_install strings  strings   binutils               binutils            binutils            binutils
  try_install jadx     jadx      jadx                   ""                  jadx                jadx
  try_install curl     curl      curl                   curl                curl                curl
  try_install git      git       git                    git                 git                 git
}

install_binary_releases() {
  info "Target unduhan: $OS_NAME / $ARCH_RAW (kategori: $ARCH_KIND)"
  if [ "$ARCH_KIND" = "unknown" ]; then
    warn "Arsitektur $ARCH_RAW belum dipetakan; pemilihan aset memakai pola umum."
  fi

  install_release_archive hayabusa 'Yamato-Security/hayabusa' 'hayabusa' 'hayabusa'
  install_release_archive chainsaw 'WithSecureLabs/chainsaw' 'chainsaw' 'chainsaw'

  if [ "$OS_NAME" = "Darwin" ]; then
    record_skip 'stegseek' 'rilis resmi hanya untuk Linux'
  elif [ "$ARCH_KIND" != "x64" ]; then
    record_skip 'stegseek' "rilis resmi hanya x86_64, arsitektur saat ini $ARCH_RAW"
  else
    install_release_archive stegseek 'RickdeJager/stegseek' 'stegseek' 'stegseek' 'ubuntu|linux|\.deb$'
  fi
}

install_rules() {
  if ! wanted rules; then return 0; fi
  mkdir -p "$RULES_DIR"
  if ! have git; then record_skip 'rule YARA' 'git tidak tersedia'; return 0; fi
  if [ -d "$RULES_DIR/signature-base" ]; then
    record_ok 'rules/signature-base sudah ada'
    return 0
  fi
  info 'Mengambil rule YARA signature-base ...'
  if git clone --depth 1 https://github.com/Neo23x0/signature-base "$RULES_DIR/signature-base" >/dev/null 2>&1; then
    record_ok 'rules/signature-base siap'
  else
    record_fail 'rule YARA' 'clone signature-base gagal'
  fi
}

verify_install() {
  info 'Verifikasi ketersediaan tool:'
  local tools=(pwsh python3 exiftool 7z tshark clamscan sqlite3 yara john steghide pngcheck strings vol capa floss olevba)
  local tool
  for tool in "${tools[@]}"; do
    if have "$tool"; then printf '  [ok] %s\n' "$tool"; else printf '  [--] %s\n' "$tool"; fi
  done
  for tool in hayabusa chainsaw stegseek; do
    if [ -e "$BIN_DIR/$tool" ]; then printf '  [ok] %s (bin/)\n' "$tool"; else printf '  [--] %s\n' "$tool"; fi
  done
}

print_recap() {
  local item
  printf '\n'
  printf '==================== REKAP PEMASANGAN ====================\n'
  printf 'Sistem        : %s %s (%s)\n' "$OS_NAME" "$ARCH_RAW" "$ARCH_KIND"
  printf 'Package mgr   : %s\n' "${PKG:-tidak ada}"
  printf 'Berhasil      : %s\n' "${#RESULT_OK[@]}"
  printf 'Dilewati      : %s\n' "${#RESULT_SKIP[@]}"
  printf 'Gagal         : %s\n' "${#RESULT_FAIL[@]}"
  if [ "${#RESULT_SKIP[@]}" -gt 0 ]; then
    printf '\nDilewati:\n'
    for item in "${RESULT_SKIP[@]}"; do printf '  - %s\n' "$item"; done
  fi
  if [ "${#RESULT_FAIL[@]}" -gt 0 ]; then
    printf '\nGagal:\n'
    for item in "${RESULT_FAIL[@]}"; do printf '  - %s\n' "$item"; done
  fi
  printf '==========================================================\n'
}

main() {
  detect_arch
  detect_pkg

  if [ "$LIST_ONLY" = "1" ]; then
    info "Sistem: $OS_NAME $ARCH_RAW ($ARCH_KIND); package manager: ${PKG:-tidak ada}"
    verify_install
    exit 0
  fi

  info "OpenForensic installer (POSIX) - $OS_NAME $ARCH_RAW"
  info "Package manager: ${PKG:-tidak ada}"
  if [ "$ASSUME_YES" != "1" ]; then
    printf 'Lanjutkan pemasangan? [Y/n] '
    read -r answer || answer="y"
    case "$answer" in [nN]*) info 'Dibatalkan.'; exit 0 ;; esac
  fi

  mkdir -p "$BIN_DIR"
  if [ "$SKIP_PWSH" != "1" ]; then install_pwsh; else record_skip 'pwsh' '--skip-pwsh'; fi
  if [ "$SKIP_PACKAGES" != "1" ]; then install_system_tools; else record_skip 'tool sistem' '--skip-packages'; fi
  if [ "$SKIP_PYTHON" != "1" ]; then install_python_tools; else record_skip 'paket pip' '--skip-python'; fi
  if [ "$SKIP_DOWNLOAD" != "1" ]; then
    install_binary_releases
    install_rules
  else
    record_skip 'unduhan rilis' '--skip-download'
  fi

  verify_install
  print_recap

  if [ "${#RESULT_FAIL[@]}" -gt 0 ] && [ "$IGNORE_ERRORS" != "1" ]; then
    fail "Ada ${#RESULT_FAIL[@]} komponen yang gagal. Perbaiki lalu jalankan ulang, atau pakai --ignore-errors."
    exit 1
  fi

  ok 'Selesai. Jalankan ./openforensic.sh untuk membuka menu, atau ./openforensic.sh doctor untuk diagnostik.'
}

main "$@"
