# OpenForensic - image lintas platform.
#
# Image ini membuat OpenForensic dapat dipakai di sistem operasi apa pun yang bisa
# menjalankan kontainer (Linux, macOS, Windows, WSL2), tanpa memasang PowerShell
# atau tool forensik satu per satu di mesin pemeriksa.
#
# Build:
#   docker build -t openforensic:latest .
#
# Jalankan menu dengan folder bukti dan folder kasus di-mount:
#   docker run --rm -it \
#     -v "$PWD/evidence:/evidence:ro" \
#     -v "$PWD/cases:/opt/openforensic/cases" \
#     openforensic:latest
#
# Catatan: direktori kasus toolkit berada di /opt/openforensic/cases, jadi volume
# host harus dipasang ke path tersebut agar hasil pemeriksaan tidak hilang.
#
FROM mcr.microsoft.com/powershell:7.4-ubuntu-22.04

LABEL org.opencontainers.image.title="OpenForensic" \
      org.opencontainers.image.description="Toolkit forensik digital lintas platform dengan alur kerja end-to-end dan AI assistance" \
      org.opencontainers.image.source="https://github.com/stmarya/OpenForensic" \
      org.opencontainers.image.licenses="MIT"

ENV DEBIAN_FRONTEND=noninteractive \
    OPENFORENSIC_IN_CONTAINER=1 \
    OPENFORENSIC_HOME=/opt/openforensic \
    PATH="/root/.local/bin:/opt/openforensic/bin:${PATH}"

RUN apt-get update && apt-get install -y --no-install-recommends \
        python3 python3-pip \
        libimage-exiftool-perl \
        p7zip-full \
        tshark \
        sqlite3 \
        yara \
        binutils \
        pngcheck \
        steghide \
        john \
        testdisk \
        clamav \
        git curl unzip ca-certificates \
    && rm -rf /var/lib/apt/lists/*

RUN python3 -m pip install --no-cache-dir --upgrade pip \
    && python3 -m pip install --no-cache-dir \
        volatility3 \
        oletools \
        msoffcrypto-tool \
        flare-capa \
        flare-floss \
        uncompyle6

RUN pwsh -NoLogo -NoProfile -Command "Set-PSRepository -Name PSGallery -InstallationPolicy Trusted; Install-Module Pester -MinimumVersion 5.3.0 -Force -Scope AllUsers"

WORKDIR /opt/openforensic
COPY . /opt/openforensic

RUN chmod +x /opt/openforensic/openforensic.sh /opt/openforensic/setup_tools.sh || true

# Direktori kasus, laporan, dan bukti sebaiknya di-mount dari host.
RUN mkdir -p /opt/openforensic/cases /opt/openforensic/reports /evidence
VOLUME ["/opt/openforensic/cases", "/opt/openforensic/reports", "/evidence"]

ENTRYPOINT ["pwsh", "-NoLogo", "-NoProfile", "-File", "/opt/openforensic/menu.ps1"]
