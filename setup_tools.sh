#!/usr/bin/env bash
#
# OpenForensic - installer tool pihak ketiga untuk Linux dan macOS.
#
# Pendamping setup_tools.ps1 (Windows). Script ini:
#   - mendeteksi package manager (apt, dnf, pacman, zypper, apk, brew)
#   - memasang PowerShell 7 bila belum ada (OpenForensic butuh pwsh di non-Windows)
#   - memasang tool DFIR dari repositori distribusi dan pip
#   - mengunduh rilis biner lintas platform (Hayabusa, Chainsaw) ke ./bin
#   - mencatat SHA256 setiap unduhan ke bin/_downloads.log
#
# Tidak ada eksekusi script pihak ketiga secara langsung (tidak ada curl | bash).
#
# Pemakaian:
#   ./setup_tools.sh                 # pemasangan standar
#   ./setup_tools.sh --skip-python   # lewati paket pip
#   ./setup_tools.sh --skip-download # lewati unduhan rilis GitHub
#   ./setup_tools.sh --only yara,capa
#   ./setup_tools.sh --list
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
ONLY_LIST=""
LIST_ONLY=0

PKG=""
SUDO=""

color() { printf '%s\n' "$2"; }
info()  { printf '[i] %s\n' "$1"; }
ok()    { printf '[+] %s\n' "$1"; }
warn()  { printf '[!] %s\n' "$1" >&2; }
fail()  { printf '[-] %s\n' "$1" >&2; }

have() { command -v "$1" >/dev/null 2>&1; }

wanted() {
  if [ -z "$ONLY_LIST" ]; then return 0; fi
  case ",$ONLY_LIST," in
    *",$1,"*) return 0 ;;
    *) return 1 ;;
  esac
}

usage() {
  sed -n '2,30p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'
  exit 0
}

while [ $# -gt 0 ]; do
  case "$1" in
    --skip-python) SKIP_PYTHON=1 ;;
    --skip-packages) SKIP_PACKAGES=1 ;;
    --skip-download) SKIP_DOWNLOAD=1 ;;
    --skip-pwsh) SKIP_PWSH=1 ;;
    --yes|-y) ASSUME_YES=1 ;;
    --only) shift; ONLY_LIST="${1:-}" ;;
    --list) LIST_ONLY=1 ;;
    -h|--help) usage ;;
    *) fail "Opsi tidak dikenal: $1"; exit 2 ;;
  esac
  shift
done

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
  local apt_name="$1" dnf_name="$2" pacman_name="$3" brew_name="$4" name=""
  case "$PKG" in
    apt) name="$apt_name"; [ -n "$name" ] && $SUDO apt-get install -y "$name" ;;
    dnf) name="$dnf_name"; [ -n "$name" ] && $SUDO dnf install -y "$name" ;;
    pacman) name="$pacman_name"; [ -n "$name" ] && $SUDO pacman -S --noconfirm --needed "$name" ;;
    zypper) name="$dnf_name"; [ -n "$name" ] && $SUDO zypper --non-interactive install "$name" ;;
    apk) name="$apt_name"; [ -n "$name" ] && $SUDO apk add --no-cache "$name" ;;
    brew) name="$brew_name"; [ -n "$name" ] && brew install "$name" ;;
    *) warn "Tidak ada package manager yang dikenali; pasang manual: $apt_name"; return 1 ;;
  esac
}

log_download() {
  local url="$1" file="$2" hash="" size=""
  if have sha256sum; then hash="$(sha256sum "$file" | awk '{print $1}')"
  elif have shasum; then hash="$(shasum -a 256 "$file" | awk '{print $1}')"
  else hash="tidak-terhitung"; fi
  size="$(wc -c < "$file" | tr -d ' ')"
  mkdir -p "$BIN_DIR"
  printf '%s  SHA256=%s  bytes=%s  url=%s\n' "$(date '+%Y-%m-%d %H:%M:%S')" "$hash" "$size" "$url" >> "$LOG_FILE"
  ok "Unduhan tercatat: SHA256=$hash"
}

github_latest_asset() {
  # github_latest_asset <owner/repo> <pola-nama-asset>
  local repo="$1" pattern="$2" auth=()
  if [ -n "${GITHUB_TOKEN:-}" ]; then auth=(-H "Authorization: Bearer $GITHUB_TOKEN"); fi
  curl -fsSL "${auth[@]}" "https://api.github.com/repos/$repo/releases/latest" \
    | grep 'browser_download_url' \
    | grep -i "$pattern" \
    | head -n 1 \
    | cut -d '"' -f 4
}

install_release_zip() {
  # install_release_zip <owner/repo> <pola> <subdir-bin> <nama-binari>
  local repo="$1" pattern="$2" subdir="$3" binary="$4"
  local url staging archive
  url="$(github_latest_asset "$repo" "$pattern" || true)"
  if [ -z "$url" ]; then
    warn "Aset rilis untuk $repo (pola: $pattern) tidak ditemukan; lewati."
    return 0
  fi
  staging="$(mktemp -d)"
  archive="$staging/$(basename "$url")"
  info "Mengunduh $repo ..."
  curl -fsSL -o "$archive" "$url"
  log_download "$url" "$archive"
  mkdir -p "$BIN_DIR/$subdir"
  case "$archive" in
    *.zip) have unzip || { warn 'unzip tidak tersedia; lewati.'; rm -rf "$staging"; return 0; }; unzip -oq "$archive" -d "$BIN_DIR/$subdir" ;;
    *.tar.gz|*.tgz) tar -xzf "$archive" -C "$BIN_DIR/$subdir" ;;
    *) warn "Format arsip tidak dikenali: $archive" ;;
  esac
  rm -rf "$staging"

  local found
  found="$(find "$BIN_DIR/$subdir" -maxdepth 3 -type f -name "$binary*" | head -n 1 || true)"
  if [ -n "$found" ]; then
    chmod +x "$found"
    ln -sf "$found" "$BIN_DIR/$binary"
    ok "$binary siap di bin/$binary"
  else
    warn "Binari $binary tidak ditemukan di dalam arsip."
  fi
}

install_pwsh() {
  if have pwsh; then ok "PowerShell 7 sudah terpasang: $(pwsh --version)"; return 0; fi
  info 'Memasang PowerShell 7 ...'
  case "$PKG" in
    brew) brew install --cask powershell || brew install powershell ;;
    apt)
      if have snap; then $SUDO snap install powershell --classic
      else warn 'Pasang PowerShell mengikuti panduan resmi Microsoft untuk distribusi Anda, atau gunakan Docker (lihat docs/CROSS-PLATFORM.md).'; fi ;;
    dnf) $SUDO dnf install -y powershell || warn 'Tambahkan repositori packages.microsoft.com terlebih dahulu.' ;;
    pacman) warn 'Pasang paket AUR powershell-bin, atau gunakan Docker.' ;;
    apk) warn 'Gunakan image Docker mcr.microsoft.com/powershell untuk Alpine.' ;;
    *) warn 'Package manager tidak dikenali; pasang PowerShell 7 secara manual.' ;;
  esac
}

install_python_tools() {
  local python_bin=""
  if have python3; then python_bin="python3"; elif have python; then python_bin="python"; else
    warn 'Python 3 tidak ditemukan; paket pip dilewati.'
    return 0
  fi
  info "Memasang paket forensik via pip ($python_bin) ..."
  local packages=(volatility3 oletools msoffcrypto-tool flare-capa flare-floss uncompyle6 decompyle3 binwalk)
  for package in "${packages[@]}"; do
    if ! wanted "$package"; then continue; fi
    if "$python_bin" -m pip install --user --upgrade "$package" >/dev/null 2>&1; then
      ok "pip: $package"
    else
      warn "pip gagal memasang $package (coba dalam virtualenv atau tambahkan --break-system-packages)."
    fi
  done
  info 'Pastikan direktori skrip pip ada di PATH, mis. $HOME/.local/bin.'
}

install_system_tools() {
  info "Memasang tool sistem dengan package manager: ${PKG:-tidak ada}"
  [ "$PKG" = "apt" ] && $SUDO apt-get update -qq || true

  wanted exiftool  && pkg_install libimage-exiftool-perl perl-Image-ExifTool perl-image-exiftool exiftool || true
  wanted 7z        && pkg_install p7zip-full p7zip p7zip p7zip || true
  wanted tshark    && pkg_install tshark wireshark-cli wireshark-cli wireshark || true
  wanted clamscan  && pkg_install clamav clamav clamav clamav || true
  wanted sqlite3   && pkg_install sqlite3 sqlite sqlite sqlite || true
  wanted yara      && pkg_install yara yara yara yara || true
  wanted john      && pkg_install john john john john-jumbo || true
  wanted steghide  && pkg_install steghide steghide steghide steghide || true
  wanted pngcheck  && pkg_install pngcheck pngcheck pngcheck pngcheck || true
  wanted photorec  && pkg_install testdisk testdisk testdisk testdisk || true
  wanted rizin     && pkg_install rizin rizin rizin rizin || true
  wanted strings   && pkg_install binutils binutils binutils binutils || true
  wanted jadx      && pkg_install jadx "" jadx jadx || true
  wanted curl      && pkg_install curl curl curl curl || true
}

install_binary_releases() {
  local os_pattern="linux" arch
  arch="$(uname -m)"
  if [ "$(uname -s)" = "Darwin" ]; then os_pattern="mac"; fi

  if wanted hayabusa; then
    install_release_zip 'Yamato-Security/hayabusa' "$os_pattern" 'hayabusa' 'hayabusa'
  fi
  if wanted chainsaw; then
    install_release_zip 'WithSecureLabs/chainsaw' "$os_pattern" 'chainsaw' 'chainsaw'
  fi
  if wanted stegseek && [ "$os_pattern" = "linux" ]; then
    install_release_zip 'RickdeJager/stegseek' 'ubuntu' 'stegseek' 'stegseek'
  fi
  info "Arsitektur terdeteksi: $arch. Bila binari tidak cocok, unduh manual dari halaman rilis."
}

install_rules() {
  mkdir -p "$RULES_DIR"
  if ! have git; then warn 'git tidak tersedia; rule YARA dilewati.'; return 0; fi
  if [ ! -d "$RULES_DIR/signature-base" ]; then
    info 'Mengambil rule YARA signature-base ...'
    git clone --depth 1 https://github.com/Neo23x0/signature-base "$RULES_DIR/signature-base" >/dev/null 2>&1 \
      && ok 'rules/signature-base siap' || warn 'Clone signature-base gagal.'
  fi
}

verify_install() {
  info 'Verifikasi ketersediaan tool:'
  local tools=(pwsh python3 exiftool 7z tshark clamscan sqlite3 yara john steghide pngcheck strings vol capa floss olevba)
  for tool in "${tools[@]}"; do
    if have "$tool"; then printf '  [ok] %s\n' "$tool"; else printf '  [--] %s\n' "$tool"; fi
  done
  for tool in hayabusa chainsaw stegseek; do
    if [ -e "$BIN_DIR/$tool" ]; then printf '  [ok] %s (bin/)\n' "$tool"; else printf '  [--] %s\n' "$tool"; fi
  done
}

main() {
  detect_pkg

  if [ "$LIST_ONLY" = "1" ]; then
    info "Sistem: $(uname -s) $(uname -m); package manager: ${PKG:-tidak ada}"
    verify_install
    exit 0
  fi

  info "OpenForensic installer (POSIX) - $(uname -s) $(uname -m)"
  info "Package manager: ${PKG:-tidak ada}"
  if [ "$ASSUME_YES" != "1" ]; then
    printf 'Lanjutkan pemasangan? [Y/n] '
    read -r answer || answer="y"
    case "$answer" in [nN]*) info 'Dibatalkan.'; exit 0 ;; esac
  fi

  mkdir -p "$BIN_DIR"
  [ "$SKIP_PWSH" = "1" ] || install_pwsh
  [ "$SKIP_PACKAGES" = "1" ] || install_system_tools
  [ "$SKIP_PYTHON" = "1" ] || install_python_tools
  [ "$SKIP_DOWNLOAD" = "1" ] || { install_binary_releases; install_rules; }

  verify_install
  ok 'Selesai. Jalankan ./openforensic.sh untuk membuka menu.'
}

main "$@"
