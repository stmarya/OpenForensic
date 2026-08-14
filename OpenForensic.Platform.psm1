#Requires -Version 5.1
<#
    OpenForensic.Platform.psm1

    Lapisan kompatibilitas lintas platform (Windows, Linux, macOS).

    Modul ini tidak boleh memakai API khusus Windows secara langsung. Semua kode lain
    memakai fungsi di sini untuk mengetahui kemampuan platform, lokasi data, resolusi
    perintah, dan saran pemasangan tool sesuai sistem operasi pengguna.

    Catatan PowerShell 5.1: variabel otomatis $IsWindows/$IsLinux/$IsMacOS hanya ada di
    PowerShell 6+, jadi keberadaannya selalu diperiksa lewat Get-Variable.
#>

Set-StrictMode -Version Latest

$script:PlatUtf8 = New-Object System.Text.UTF8Encoding($false)

$script:PlatPackageNames = @{
    exiftool      = @{ winget = 'OliverBetz.ExifTool'; apt = 'libimage-exiftool-perl'; dnf = 'perl-Image-ExifTool'; pacman = 'perl-image-exiftool'; brew = 'exiftool' }
    '7z'          = @{ winget = '7zip.7zip'; apt = 'p7zip-full'; dnf = 'p7zip'; pacman = 'p7zip'; brew = 'p7zip' }
    tshark        = @{ winget = 'WiresharkFoundation.Wireshark'; apt = 'tshark'; dnf = 'wireshark-cli'; pacman = 'wireshark-cli'; brew = 'wireshark' }
    capinfos      = @{ winget = 'WiresharkFoundation.Wireshark'; apt = 'tshark'; dnf = 'wireshark-cli'; pacman = 'wireshark-cli'; brew = 'wireshark' }
    clamscan      = @{ winget = 'ClamAV.ClamAV'; apt = 'clamav'; dnf = 'clamav'; pacman = 'clamav'; brew = 'clamav' }
    sqlite3       = @{ winget = 'SQLite.SQLite'; apt = 'sqlite3'; dnf = 'sqlite'; pacman = 'sqlite'; brew = 'sqlite' }
    binwalk       = @{ pip = 'binwalk'; apt = 'binwalk'; dnf = 'binwalk'; pacman = 'binwalk'; brew = 'binwalk' }
    strings       = @{ apt = 'binutils'; dnf = 'binutils'; pacman = 'binutils'; brew = 'binutils' }
    yara          = @{ apt = 'yara'; dnf = 'yara'; pacman = 'yara'; brew = 'yara' }
    john          = @{ apt = 'john'; dnf = 'john'; pacman = 'john'; brew = 'john-jumbo' }
    steghide      = @{ apt = 'steghide'; dnf = 'steghide'; pacman = 'steghide'; brew = 'steghide' }
    zsteg         = @{ gem = 'zsteg'; apt = 'ruby-full'; brew = 'ruby' }
    pngcheck      = @{ apt = 'pngcheck'; dnf = 'pngcheck'; pacman = 'pngcheck'; brew = 'pngcheck' }
    photorec      = @{ apt = 'testdisk'; dnf = 'testdisk'; pacman = 'testdisk'; brew = 'testdisk' }
    rizin         = @{ apt = 'rizin'; dnf = 'rizin'; pacman = 'rizin'; brew = 'rizin' }
    jadx          = @{ apt = 'jadx'; pacman = 'jadx'; brew = 'jadx' }
    bulkextractor = @{ apt = 'bulk-extractor'; brew = 'bulk_extractor' }
    vol           = @{ pip = 'volatility3' }
    uncompyle6    = @{ pip = 'uncompyle6' }
    decompyle3    = @{ pip = 'decompyle3' }
    oleid         = @{ pip = 'oletools' }
    olevba        = @{ pip = 'oletools' }
    mraptor       = @{ pip = 'oletools' }
    rtfobj        = @{ pip = 'oletools' }
    oleobj        = @{ pip = 'oletools' }
    msoffcrypto   = @{ pip = 'msoffcrypto-tool' }
    capa          = @{ pip = 'flare-capa' }
    floss         = @{ pip = 'flare-floss' }
}

function Get-OFPlatformFlag {
    param([Parameter(Mandatory)][string]$Name)

    $variable = Get-Variable -Name $Name -ErrorAction SilentlyContinue
    if ($variable) { return [bool]$variable.Value }
    return $null
}

function Test-OFWindows {
    <#
        .SYNOPSIS
        True bila sesi berjalan di Windows.
    #>
    [CmdletBinding()]
    [OutputType([bool])]
    param()

    $flag = Get-OFPlatformFlag -Name 'IsWindows'
    if ($null -ne $flag) { return $flag }

    # PowerShell 5.1 (Desktop edition) hanya berjalan di Windows.
    return $true
}

function Test-OFLinuxPlatform {
    $flag = Get-OFPlatformFlag -Name 'IsLinux'
    if ($null -ne $flag) { return $flag }
    return $false
}

function Test-OFMacPlatform {
    $flag = Get-OFPlatformFlag -Name 'IsMacOS'
    if ($null -ne $flag) { return $flag }
    return $false
}

function Test-OFInteractive {
    <#
        .SYNOPSIS
        True bila sesi dapat meminta input dari pengguna (bukan CI atau pipeline).
    #>
    [CmdletBinding()]
    [OutputType([bool])]
    param()

    if ($env:CI) { return $false }
    if ($env:OPENFORENSIC_NONINTERACTIVE) { return $false }
    try {
        if (-not [System.Environment]::UserInteractive) { return $false }
    } catch {
        Write-Verbose 'UserInteractive tidak tersedia pada runtime ini.'
    }
    return $true
}

function Get-OFDataRoot {
    <#
        .SYNOPSIS
        Direktori data OpenForensic yang benar untuk platform ini.

        .DESCRIPTION
        Urutan prioritas:
          1. $env:OPENFORENSIC_HOME
          2. Windows  : %LOCALAPPDATA%\OpenForensic
          3. macOS    : ~/Library/Application Support/OpenForensic
          4. Linux    : $XDG_DATA_HOME/openforensic atau ~/.local/share/openforensic

        .PARAMETER Create
        Buat direktori bila belum ada.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param([switch]$Create)

    $root = $null
    if ($env:OPENFORENSIC_HOME) {
        $root = $env:OPENFORENSIC_HOME
    } elseif (Test-OFWindows) {
        $base = if ($env:LOCALAPPDATA) { $env:LOCALAPPDATA } else { Join-Path $HOME 'AppData\Local' }
        $root = Join-Path $base 'OpenForensic'
    } elseif (Test-OFMacPlatform) {
        $root = Join-Path $HOME 'Library/Application Support/OpenForensic'
    } else {
        $base = if ($env:XDG_DATA_HOME) { $env:XDG_DATA_HOME } else { Join-Path $HOME '.local/share' }
        $root = Join-Path $base 'openforensic'
    }

    if ($Create -and -not (Test-Path -LiteralPath $root)) {
        New-Item -ItemType Directory -Path $root -Force | Out-Null
    }
    return [string]$root
}

function Get-OFSecureStorageMode {
    <#
        .SYNOPSIS
        Mode penyimpanan rahasia dan penyegelan yang tersedia pada platform ini.

        .DESCRIPTION
        dpapi   : Windows, terikat akun dan mesin (DPAPI).
        pbkdf2  : lintas platform, memakai passphrase dan PBKDF2-HMAC-SHA256.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param()

    if (-not (Test-OFWindows)) { return 'pbkdf2' }
    try {
        Add-Type -AssemblyName System.Security -ErrorAction Stop
        return 'dpapi'
    } catch {
        return 'pbkdf2'
    }
}

function Get-OFPlatform {
    <#
        .SYNOPSIS
        Mengembalikan detail platform tempat OpenForensic berjalan.

        .EXAMPLE
        Get-OFPlatform | Format-List
    #>
    [CmdletBinding()]
    param()

    $windows = Test-OFWindows
    $linux = Test-OFLinuxPlatform
    $mac = Test-OFMacPlatform

    $osName = if ($windows) { 'Windows' } elseif ($linux) { 'Linux' } elseif ($mac) { 'macOS' } else { 'Unknown' }

    $architecture = 'unknown'
    try {
        $architecture = [string][System.Runtime.InteropServices.RuntimeInformation]::OSArchitecture
    } catch {
        Write-Verbose "Arsitektur tidak dapat dideteksi: $($_.Exception.Message)"
    }

    $description = ''
    try {
        $description = [string][System.Runtime.InteropServices.RuntimeInformation]::OSDescription
    } catch {
        $description = [string][System.Environment]::OSVersion.VersionString
    }

    $inContainer = $false
    if ($env:OPENFORENSIC_IN_CONTAINER) {
        $inContainer = $true
    } elseif (-not $windows -and (Test-Path -LiteralPath '/.dockerenv')) {
        $inContainer = $true
    }

    [pscustomobject]@{
        Os            = $osName
        OsDescription = $description
        Architecture  = $architecture
        IsWindows     = $windows
        IsLinux       = $linux
        IsMacOS       = $mac
        IsUnix        = (-not $windows)
        PSEdition     = $PSVersionTable.PSEdition
        PSVersion     = [string]$PSVersionTable.PSVersion
        IsCore        = ($PSVersionTable.PSEdition -eq 'Core')
        PathSeparator = [string][System.IO.Path]::DirectorySeparatorChar
        IsContainer   = $inContainer
        IsInteractive = (Test-OFInteractive)
        DataRoot      = (Get-OFDataRoot)
        SecureStorage = (Get-OFSecureStorageMode)
        DetectedAt    = (Get-Date).ToString('o')
    }
}

function Test-OFAdministrator {
    <#
        .SYNOPSIS
        True bila proses berjalan dengan hak administrator (Windows) atau root (Unix).
    #>
    [CmdletBinding()]
    [OutputType([bool])]
    param()

    if (Test-OFWindows) {
        try {
            $identity = [System.Security.Principal.WindowsIdentity]::GetCurrent()
            $principal = New-Object System.Security.Principal.WindowsPrincipal($identity)
            return $principal.IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator)
        } catch {
            return $false
        }
    }

    try {
        $userId = & id -u 2>$null
        if ($LASTEXITCODE -eq 0 -and $userId) { return ([int]$userId -eq 0) }
    } catch {
        Write-Verbose 'Perintah id tidak tersedia.'
    }
    return $false
}

function Get-OFTempDirectory {
    <#
        .SYNOPSIS
        Direktori sementara lintas platform (tidak bergantung pada %TEMP%).
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param([switch]$Create)

    $temp = Join-Path ([System.IO.Path]::GetTempPath()) 'openforensic'
    if ($Create -and -not (Test-Path -LiteralPath $temp)) {
        New-Item -ItemType Directory -Path $temp -Force | Out-Null
    }
    return [string]$temp
}

function Convert-OFPath {
    <#
        .SYNOPSIS
        Menormalkan pemisah path ke pemisah asli platform.

        .EXAMPLE
        Convert-OFPath -Path 'artifacts\logs\out.csv'
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param([Parameter(Mandatory, ValueFromPipeline)][AllowEmptyString()][string]$Path)

    process {
        if ([string]::IsNullOrEmpty($Path)) { return $Path }
        $separator = [string][System.IO.Path]::DirectorySeparatorChar
        $replacement = [System.Text.RegularExpressions.Regex]::Escape($separator)
        return ($Path -replace '[\\/]+', $replacement)
    }
}

function Resolve-OFCommand {
    <#
        .SYNOPSIS
        Mencari executable lintas platform: direktori lokal, PATH, dan sufiks Windows.

        .PARAMETER Name
        Nama perintah tanpa ekstensi, mis. exiftool.

        .PARAMETER SearchPath
        Direktori tambahan yang diperiksa lebih dahulu (mis. .\bin).
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Name,
        [string[]]$SearchPath = @()
    )

    $suffixes = if (Test-OFWindows) { @('.exe', '.cmd', '.bat', '.ps1', '') } else { @('', '.sh', '.py') }

    foreach ($directory in @($SearchPath)) {
        if (-not $directory -or -not (Test-Path -LiteralPath $directory)) { continue }
        foreach ($suffix in $suffixes) {
            $candidate = Join-Path $directory ($Name + $suffix)
            if (Test-Path -LiteralPath $candidate -PathType Leaf) {
                return [pscustomobject]@{
                    Name   = $Name
                    Path   = (Resolve-Path -LiteralPath $candidate).Path
                    Source = 'local'
                    Found  = $true
                }
            }
        }
    }

    foreach ($suffix in $suffixes) {
        $command = Get-Command -Name ($Name + $suffix) -CommandType Application -ErrorAction SilentlyContinue |
            Select-Object -First 1
        if ($command) {
            return [pscustomobject]@{ Name = $Name; Path = $command.Source; Source = 'path'; Found = $true }
        }
    }

    return [pscustomobject]@{ Name = $Name; Path = $null; Source = 'none'; Found = $false }
}

function Get-OFPackageManager {
    <#
        .SYNOPSIS
        Daftar package manager yang tersedia pada mesin ini, berurutan sesuai preferensi.
    #>
    [CmdletBinding()]
    param()

    $candidates = if (Test-OFWindows) {
        @('winget', 'choco', 'scoop', 'pip', 'pip3')
    } elseif (Test-OFMacPlatform) {
        @('brew', 'port', 'pip3', 'pip')
    } else {
        @('apt-get', 'dnf', 'yum', 'pacman', 'zypper', 'apk', 'pip3', 'pip')
    }

    $found = New-Object System.Collections.ArrayList
    foreach ($candidate in $candidates) {
        $resolved = Resolve-OFCommand -Name $candidate
        if ($resolved.Found) { [void]$found.Add($candidate) }
    }
    return , @($found)
}

function Get-OFInstallHint {
    <#
        .SYNOPSIS
        Saran pemasangan tool yang sesuai dengan sistem operasi dan package manager pengguna.

        .PARAMETER ToolId
        Id tool pada tools.json, mis. exiftool.

        .PARAMETER FallbackHint
        Petunjuk dari katalog yang dipakai bila tidak ada pemetaan khusus platform.

        .EXAMPLE
        Get-OFInstallHint -ToolId exiftool
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory)][string]$ToolId,
        [string]$FallbackHint = ''
    )

    if (-not $script:PlatPackageNames.ContainsKey($ToolId)) {
        if ($FallbackHint) { return $FallbackHint }
        return "Pasang '$ToolId' secara manual lalu pastikan tersedia di PATH."
    }
    $map = $script:PlatPackageNames[$ToolId]

    $order = if (Test-OFWindows) {
        @(
            @{ Key = 'winget'; Template = 'winget install --id {0} -e' },
            @{ Key = 'pip'; Template = 'pip install {0}' },
            @{ Key = 'gem'; Template = 'gem install {0}' }
        )
    } elseif (Test-OFMacPlatform) {
        @(
            @{ Key = 'brew'; Template = 'brew install {0}' },
            @{ Key = 'pip'; Template = 'pip3 install {0}' },
            @{ Key = 'gem'; Template = 'gem install {0}' }
        )
    } else {
        @(
            @{ Key = 'apt'; Template = 'sudo apt-get install -y {0}' },
            @{ Key = 'dnf'; Template = 'sudo dnf install -y {0}' },
            @{ Key = 'pacman'; Template = 'sudo pacman -S --noconfirm {0}' },
            @{ Key = 'pip'; Template = 'pip3 install {0}' },
            @{ Key = 'gem'; Template = 'gem install {0}' }
        )
    }

    foreach ($entry in $order) {
        if ($map.ContainsKey($entry.Key) -and $map[$entry.Key]) {
            return ($entry.Template -f $map[$entry.Key])
        }
    }

    if ($FallbackHint) { return $FallbackHint }
    return "Pasang '$ToolId' secara manual lalu pastikan tersedia di PATH."
}

function Test-OFPlatformCompatibility {
    <#
        .SYNOPSIS
        Matriks kemampuan OpenForensic pada platform saat ini.

        .EXAMPLE
        Test-OFPlatformCompatibility | Format-Table Feature, Supported, Notes -AutoSize
    #>
    [CmdletBinding()]
    param()

    $platform = Get-OFPlatform
    $features = New-Object System.Collections.ArrayList

    $add = {
        param([string]$Feature, [bool]$Supported, [string]$Notes)
        [void]$features.Add([pscustomobject]@{ Feature = $Feature; Supported = $Supported; Notes = $Notes })
    }

    & $add 'Alur kerja kasus (bukti, tool, artefak, temuan)' $true 'Berjalan di semua platform.'
    & $add 'Hash bukti dan manifest SHA256' $true 'Memakai API .NET lintas platform.'
    & $add 'Timeline ternormalisasi, MITRE, ekspor IOC' $true 'Berjalan di semua platform.'
    & $add 'Report Markdown dan HTML' $true 'Berjalan di semua platform.'
    & $add 'Lapisan AI dan registry model pengguna' $true 'HTTP lintas platform; model lokal via Ollama, LM Studio, atau vLLM.'
    & $add 'Segel kasus mode passphrase (PBKDF2)' $true 'Direkomendasikan untuk lingkungan campuran dan penyerahan bukti.'
    & $add 'Segel kasus mode DPAPI' ($platform.SecureStorage -eq 'dpapi') 'Hanya Windows. Di Linux dan macOS gunakan -SealPassphrase.'
    & $add 'Penyimpanan API key terenkripsi DPAPI' ($platform.SecureStorage -eq 'dpapi') 'Di Linux dan macOS gunakan variabel environment API key.'

    $dialog = $false
    if ($platform.IsWindows -and $platform.IsInteractive) {
        try {
            Add-Type -AssemblyName System.Windows.Forms -ErrorAction Stop
            $dialog = $true
        } catch {
            $dialog = $false
        }
    }
    & $add 'Pemilih berkas grafis (dialog)' $dialog 'Di luar Windows, path bukti diminta lewat teks atau argumen CLI.'

    $managers = @(Get-OFPackageManager)
    $managerText = if ($managers.Count -gt 0) { $managers -join ', ' } else { 'tidak ada' }
    & $add 'Installer otomatis tool pihak ketiga' ($managers.Count -gt 0) "Package manager terdeteksi: $managerText. Windows: setup_tools.ps1, Linux dan macOS: setup_tools.sh."

    & $add 'Tool khusus Windows (MFTECmd, RegRipper, Get-ZimmermanTools)' $platform.IsWindows 'Di Linux dan macOS pakai analyzeMFT atau RegRipper via Perl, atau proses artefak yang sudah diekspor.'
    & $add 'Volatility 3, YARA, capa, FLOSS, oletools, binwalk' $true 'Tersedia lintas platform via pip atau package manager.'
    & $add 'Hayabusa, Chainsaw, Stegseek, rizin, jadx' $true 'Tersedia rilis Linux dan macOS pada halaman rilis masing-masing.'
    & $add 'Write-block lunak pada berkas bukti' $true 'Windows memakai atribut read-only, Unix mencabut bit tulis.'
    & $add 'Eksekusi proses dengan timeout' $true 'Memakai System.Diagnostics.Process, lintas platform.'

    return , @($features)
}

function Format-OFPlatformSummary {
    <#
        .SYNOPSIS
        Ringkasan platform dan kompatibilitas dalam Markdown, siap disisipkan ke report.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param([switch]$IncludeMatrix)

    $platform = Get-OFPlatform
    $lines = New-Object System.Collections.ArrayList
    [void]$lines.Add('### Lingkungan Pemeriksaan')
    [void]$lines.Add('')
    [void]$lines.Add("- Sistem operasi: $($platform.Os) ($($platform.OsDescription))")
    [void]$lines.Add("- Arsitektur: $($platform.Architecture)")
    [void]$lines.Add("- PowerShell: $($platform.PSVersion) ($($platform.PSEdition))")
    [void]$lines.Add("- Direktori data: $($platform.DataRoot)")
    [void]$lines.Add("- Mode penyimpanan rahasia: $($platform.SecureStorage)")
    if ($platform.IsContainer) { [void]$lines.Add('- Dijalankan di dalam kontainer') }

    if ($IncludeMatrix) {
        [void]$lines.Add('')
        [void]$lines.Add('| Kemampuan | Didukung | Catatan |')
        [void]$lines.Add('| --- | --- | --- |')
        foreach ($feature in Test-OFPlatformCompatibility) {
            $mark = if ($feature.Supported) { 'ya' } else { 'tidak' }
            [void]$lines.Add("| $($feature.Feature) | $mark | $($feature.Notes) |")
        }
    }

    return ($lines -join [System.Environment]::NewLine)
}

Export-ModuleMember -Function @(
    'Get-OFPlatform',
    'Test-OFWindows',
    'Test-OFInteractive',
    'Test-OFAdministrator',
    'Get-OFDataRoot',
    'Get-OFTempDirectory',
    'Convert-OFPath',
    'Resolve-OFCommand',
    'Get-OFPackageManager',
    'Get-OFInstallHint',
    'Get-OFSecureStorageMode',
    'Test-OFPlatformCompatibility',
    'Format-OFPlatformSummary'
)
