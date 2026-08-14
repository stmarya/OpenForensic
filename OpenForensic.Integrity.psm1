#Requires -Version 5.1
<#
    OpenForensic.Integrity - lapisan integritas & kredibilitas bukti.

    Modul ini menangani hal-hal yang menentukan apakah hasil pemeriksaan layak
    dipakai sebagai alat bukti:
      - Manifest SHA256 seluruh isi folder kasus (case.manifest.sha256)
      - Segel kriptografis atas manifest (case.seal.json, HMAC-SHA256)
      - Snapshot versi setiap tool yang dipakai (reproduktifitas)
      - Write-block tingkat aplikasi pada salinan bukti
      - Allowlist hash untuk menekan positif palsu
      - Deduplikasi bukti berdasarkan SHA256
      - Eksekusi proses dengan batas waktu (anti-hang)

    Catatan lintas platform:
      - Mode kunci segel dipilih otomatis lewat Get-OFSecureStorageMode: DPAPI di
        Windows, PBKDF2 (passphrase) di Linux/macOS.
      - Manifest memakai path relatif bergaya POSIX dan akhiran baris LF agar hash
        manifest identik di Windows, Linux, dan macOS.
      - Identitas pemeriksa diambil dari API .NET, bukan %USERNAME%/%COMPUTERNAME%.

    Dimuat sebagai NestedModule oleh OpenForensic.psd1 sehingga dapat memanggil
    fungsi modul inti (Resolve-OFTool, Get-OFEvidenceHash) dan modul workflow
    (Get-OFCase, Save-OFCase, Add-OFCaseFinding).
#>

Set-StrictMode -Version Latest

$script:IntUtf8 = New-Object System.Text.UTF8Encoding($false)
$script:IntAllowlistDir = Join-Path $PSScriptRoot 'allowlist'
$script:IntAllowlistPath = Join-Path $script:IntAllowlistDir 'hashes.txt'
$script:IntAllowlistCache = $null
$script:IntManifestName = 'case.manifest.sha256'
$script:IntSealName = 'case.seal.json'
$script:IntToolVersionCache = @{}
$script:IntVersionProbes = @('--version', '-version', '-V', '-v', 'version')
$script:IntPbkdf2Iterations = 120000
$script:IntToolkitVersion = 'OpenForensic 0.5.0'
$script:IntSealSchemaVersion = 2

try { Add-Type -AssemblyName System.Security -ErrorAction Stop } catch { Write-Verbose 'System.Security tidak tersedia; segel DPAPI dilewati.' }

# ---------------------------------------------------------------------------
# Helper privat
# ---------------------------------------------------------------------------

function Test-OFIntProperty {
    param([Parameter(Mandatory)]$InputObject, [Parameter(Mandatory)][string]$Name)
    if ($null -eq $InputObject) { return $false }
    if ($InputObject -is [hashtable]) { return $InputObject.ContainsKey($Name) }
    return [bool]($InputObject.PSObject.Properties.Name -contains $Name)
}

function Set-OFIntProperty {
    param([Parameter(Mandatory)]$InputObject, [Parameter(Mandatory)][string]$Name, $Value)
    if (Test-OFIntProperty -InputObject $InputObject -Name $Name) {
        $InputObject.$Name = $Value
    } else {
        Add-Member -InputObject $InputObject -MemberType NoteProperty -Name $Name -Value $Value -Force
    }
}

function Test-OFIntWindows {
    if (Get-Command -Name 'Test-OFWindows' -ErrorAction SilentlyContinue) { return [bool](Test-OFWindows) }
    $flag = Get-Variable -Name 'IsWindows' -ErrorAction SilentlyContinue
    if ($flag) { return [bool]$flag.Value }
    return $true
}

function Get-OFIntStorageMode {
    if (Get-Command -Name 'Get-OFSecureStorageMode' -ErrorAction SilentlyContinue) {
        return [string](Get-OFSecureStorageMode)
    }
    if (Test-OFIntWindows) { return 'dpapi' }
    return 'pbkdf2'
}

function Get-OFIntActor {
    if ($env:OPENFORENSIC_EXAMINER) { return [string]$env:OPENFORENSIC_EXAMINER }
    try {
        $name = [string][System.Environment]::UserName
        if ($name) { return $name }
    } catch {
        Write-Verbose 'Nama pengguna tidak tersedia dari runtime.'
    }
    if ($env:USER) { return [string]$env:USER }
    return 'unknown'
}

function Get-OFIntHostName {
    try {
        $name = [string][System.Environment]::MachineName
        if ($name) { return $name }
    } catch {
        Write-Verbose 'Nama host tidak tersedia dari runtime.'
    }
    if ($env:HOSTNAME) { return [string]$env:HOSTNAME }
    return 'unknown'
}

function Get-OFIntCaseDir {
    param([Parameter(Mandatory)]$Case)
    if (-not (Test-OFIntProperty -InputObject $Case -Name 'caseDir')) {
        throw 'Objek kasus tidak memiliki properti caseDir. Muat ulang dengan Get-OFCase.'
    }
    $dir = $Case.caseDir
    if (-not (Test-Path -LiteralPath $dir)) { throw "Direktori kasus tidak ditemukan: $dir" }
    return (Resolve-Path -LiteralPath $dir).ProviderPath
}

function Get-OFIntRelativePath {
    <#
        Path relatif bergaya POSIX (selalu '/') agar manifest dan hash manifest
        identik di Windows, Linux, dan macOS.
    #>
    param([Parameter(Mandatory)][string]$Root, [Parameter(Mandatory)][string]$FullPath)
    $separators = [char[]]@([char]92, [char]47)
    $normalizedRoot = $Root.TrimEnd($separators)
    if ($FullPath.Length -le $normalizedRoot.Length) {
        return (Split-Path -Path $FullPath -Leaf)
    }
    $relative = $FullPath.Substring($normalizedRoot.Length).TrimStart($separators)
    return $relative.Replace([char]92, [char]47)
}

function ConvertFrom-OFIntSecureString {
    param([Parameter(Mandatory)][System.Security.SecureString]$Secure)
    $pointer = [System.Runtime.InteropServices.Marshal]::SecureStringToGlobalAllocUnicode($Secure)
    try {
        return [System.Runtime.InteropServices.Marshal]::PtrToStringUni($pointer)
    } finally {
        [System.Runtime.InteropServices.Marshal]::ZeroFreeGlobalAllocUnicode($pointer)
    }
}

function Get-OFIntDerivedKey {
    <#
        Menurunkan kunci 32 byte dari passphrase. Segel baru memakai SHA-256 bila
        runtime mendukung; segel lama (kdfHash = sha1) tetap dapat diverifikasi.
    #>
    param(
        [Parameter(Mandatory)][string]$Passphrase,
        [Parameter(Mandatory)][byte[]]$Salt,
        [int]$Iterations = $script:IntPbkdf2Iterations,
        [ValidateSet('sha1', 'sha256')][string]$HashName = 'sha256'
    )

    if ($HashName -eq 'sha256') {
        try {
            $derive = New-Object System.Security.Cryptography.Rfc2898DeriveBytes(
                $Passphrase, $Salt, $Iterations,
                [System.Security.Cryptography.HashAlgorithmName]::SHA256)
            try { return $derive.GetBytes(32) } finally { $derive.Dispose() }
        } catch {
            Write-Verbose "PBKDF2-SHA256 tidak tersedia, memakai SHA-1: $($_.Exception.Message)"
        }
    }

    $derive = New-Object System.Security.Cryptography.Rfc2898DeriveBytes($Passphrase, $Salt, $Iterations)
    try { return $derive.GetBytes(32) } finally { $derive.Dispose() }
}

function Test-OFIntPbkdf2Sha256 {
    try {
        $salt = New-Object 'byte[]' 8
        $derive = New-Object System.Security.Cryptography.Rfc2898DeriveBytes(
            'probe', $salt, 1, [System.Security.Cryptography.HashAlgorithmName]::SHA256)
        try { [void]$derive.GetBytes(1) } finally { $derive.Dispose() }
        return $true
    } catch {
        return $false
    }
}

# ---------------------------------------------------------------------------
# Eksekusi proses dengan batas waktu (dipakai probe versi & tool yang rawan hang)
# ---------------------------------------------------------------------------

function Invoke-OFProcessWithTimeout {
    <#
    .SYNOPSIS
        Menjalankan proses eksternal dengan batas waktu dan menangkap stdout/stderr.
    .DESCRIPTION
        Argumen dilewatkan sebagai array (tanpa evaluasi shell). Bila proses melewati
        batas waktu, proses dihentikan dan TimedOut bernilai true.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$FilePath,
        [AllowEmptyCollection()][string[]]$Arguments = @(),
        [ValidateRange(1, 86400)][int]$TimeoutSeconds = 30,
        [string]$WorkingDirectory
    )

    $psi = New-Object System.Diagnostics.ProcessStartInfo
    $psi.FileName = $FilePath
    $psi.UseShellExecute = $false
    $psi.RedirectStandardOutput = $true
    $psi.RedirectStandardError = $true
    $psi.CreateNoWindow = $true
    if ($WorkingDirectory) { $psi.WorkingDirectory = $WorkingDirectory }
    foreach ($argument in $Arguments) { [void]$psi.ArgumentList.Add([string]$argument) }

    $process = New-Object System.Diagnostics.Process
    $process.StartInfo = $psi
    $stdout = New-Object System.Text.StringBuilder
    $stderr = New-Object System.Text.StringBuilder
    $outHandler = {
        if ($null -ne $EventArgs.Data) { [void]$Event.MessageData.AppendLine($EventArgs.Data) }
    }
    $outSubscription = Register-ObjectEvent -InputObject $process -EventName OutputDataReceived -Action $outHandler -MessageData $stdout
    $errSubscription = Register-ObjectEvent -InputObject $process -EventName ErrorDataReceived -Action $outHandler -MessageData $stderr

    $timedOut = $false
    $exitCode = $null
    $stopwatch = [System.Diagnostics.Stopwatch]::StartNew()
    try {
        [void]$process.Start()
        $process.BeginOutputReadLine()
        $process.BeginErrorReadLine()
        if (-not $process.WaitForExit($TimeoutSeconds * 1000)) {
            $timedOut = $true
            try { $process.Kill() } catch { Write-Verbose "Gagal menghentikan proses: $($_.Exception.Message)" }
            try { [void]$process.WaitForExit(5000) } catch { Write-Verbose 'Proses tidak merespons setelah Kill.' }
        } else {
            $exitCode = $process.ExitCode
        }
    } finally {
        $stopwatch.Stop()
        Start-Sleep -Milliseconds 100
        Unregister-Event -SubscriptionId $outSubscription.Id -ErrorAction SilentlyContinue
        Unregister-Event -SubscriptionId $errSubscription.Id -ErrorAction SilentlyContinue
        $process.Dispose()
    }

    return [pscustomobject]@{
        Command         = $FilePath
        Arguments       = ($Arguments -join ' ')
        StandardOutput  = $stdout.ToString()
        StandardError   = $stderr.ToString()
        ExitCode        = $exitCode
        TimedOut        = $timedOut
        DurationSeconds = [math]::Round($stopwatch.Elapsed.TotalSeconds, 2)
        Success         = (-not $timedOut -and $exitCode -eq 0)
    }
}

# ---------------------------------------------------------------------------
# Versi tool (reproduktifitas)
# ---------------------------------------------------------------------------

function Get-OFToolVersion {
    <#
    .SYNOPSIS
        Mendeteksi versi sebuah tool dari katalog.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$ToolId,
        $Catalog,
        [switch]$Refresh,
        [ValidateRange(1, 300)][int]$TimeoutSeconds = 15
    )

    if (-not $Refresh -and $script:IntToolVersionCache.ContainsKey($ToolId)) {
        return $script:IntToolVersionCache[$ToolId]
    }

    $tool = if ($Catalog) { Resolve-OFTool -Id $ToolId -Catalog $Catalog } else { Resolve-OFTool -Id $ToolId }
    $result = [pscustomobject]@{
        ToolId     = $ToolId
        Name       = if ($tool) { $tool.Name } else { $ToolId }
        Path       = if ($tool) { $tool.Path } else { $null }
        Available  = [bool]($tool -and $tool.Available)
        Version    = 'tidak diketahui'
        ProbedWith = $null
        CheckedAt  = (Get-Date).ToString('o')
    }

    if (-not $result.Available) {
        $result.Version = 'tidak terpasang'
        $script:IntToolVersionCache[$ToolId] = $result
        return $result
    }
    if ($tool.Source -eq 'builtin') {
        $result.Version = "built-in ($($script:IntToolkitVersion))"
        $result.ProbedWith = 'modul'
        $script:IntToolVersionCache[$ToolId] = $result
        return $result
    }

    foreach ($probe in $script:IntVersionProbes) {
        try {
            $run = Invoke-OFProcessWithTimeout -FilePath $tool.Path -Arguments @($probe) -TimeoutSeconds $TimeoutSeconds
        } catch {
            continue
        }
        if ($run.TimedOut) { continue }
        $text = ($run.StandardOutput + "`n" + $run.StandardError)
        $lines = @($text -split "`r?`n" | Where-Object { $_ -and $_.Trim() })
        if ($lines.Count -eq 0) { continue }
        $versionLine = $lines | Where-Object { $_ -match '\d+\.\d+' } | Select-Object -First 1
        if (-not $versionLine) { $versionLine = $lines[0] }
        $result.Version = $versionLine.Trim()
        $result.ProbedWith = $probe
        break
    }

    $script:IntToolVersionCache[$ToolId] = $result
    return $result
}

function Update-OFCaseToolVersions {
    <#
    .SYNOPSIS
        Mencatat versi seluruh tool yang dipakai pada kasus ke dalam case.json.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]$Case,
        [switch]$AllTools,
        [switch]$Quiet
    )

    $catalog = Get-OFToolCatalog
    $toolIds = New-Object System.Collections.ArrayList

    if ($AllTools) {
        foreach ($entry in @($catalog)) {
            if ($entry.id -and -not $toolIds.Contains($entry.id)) { [void]$toolIds.Add($entry.id) }
        }
    } else {
        if (Test-OFIntProperty -InputObject $Case -Name 'evidence') {
            foreach ($evidence in @($Case.evidence)) {
                if (-not (Test-OFIntProperty -InputObject $evidence -Name 'analyses')) { continue }
                foreach ($analysis in @($evidence.analyses)) {
                    if ($analysis.toolId -and -not $toolIds.Contains($analysis.toolId)) { [void]$toolIds.Add($analysis.toolId) }
                }
            }
        }
    }

    $versions = New-Object System.Collections.ArrayList
    foreach ($toolId in ($toolIds | Select-Object -Unique)) {
        if ($toolId -like 'ai:*') { continue }
        $version = Get-OFToolVersion -ToolId $toolId -Catalog $catalog
        [void]$versions.Add([pscustomobject]@{
            toolId    = $version.ToolId
            name      = $version.Name
            version   = $version.Version
            path      = $version.Path
            available = $version.Available
            checkedAt = $version.CheckedAt
        })
        if (-not $Quiet) { Write-Host ("    [ver] {0,-16} {1}" -f $version.ToolId, $version.Version) -ForegroundColor DarkGray }
    }

    Set-OFIntProperty -InputObject $Case -Name 'toolVersions' -Value @($versions)
    Save-OFCase -Case $Case | Out-Null
    return @($versions)
}

# ---------------------------------------------------------------------------
# Write-block tingkat aplikasi
# ---------------------------------------------------------------------------

function Protect-OFEvidenceFile {
    <#
    .SYNOPSIS
        Menandai berkas bukti sebagai read-only (write-block tingkat aplikasi).
    .DESCRIPTION
        Bukan pengganti write blocker perangkat keras. Di Windows atribut ReadOnly
        dipakai; di Linux/macOS PowerShell memetakannya ke bit tulis pada mode file.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Path,
        [switch]$Release
    )

    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) { throw "Berkas tidak ditemukan: $Path" }
    $item = Get-Item -LiteralPath $Path -Force
    $wasReadOnly = $item.IsReadOnly
    try {
        $item.IsReadOnly = -not [bool]$Release
    } catch {
        Write-Warning "Tidak dapat mengubah atribut tulis di platform ini: $($_.Exception.Message)"
    }
    return [pscustomobject]@{
        Path        = $item.FullName
        ReadOnly    = (Get-Item -LiteralPath $Path -Force).IsReadOnly
        WasReadOnly = $wasReadOnly
        Released    = [bool]$Release
    }
}

function Test-OFEvidenceLock {
    <#
    .SYNOPSIS
        Memeriksa apakah berkas bukti dapat dibaca tanpa mengubahnya, dan apakah ada
        proses lain yang menahannya secara eksklusif.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$Path)

    $result = [pscustomobject]@{
        Path          = $Path
        Readable      = $false
        LockedByOther = $false
        ReadOnly      = $false
        Message       = ''
    }
    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) {
        $result.Message = 'Berkas tidak ditemukan.'
        return $result
    }
    $result.ReadOnly = (Get-Item -LiteralPath $Path -Force).IsReadOnly
    $stream = $null
    try {
        $stream = [System.IO.File]::Open($Path, [System.IO.FileMode]::Open, [System.IO.FileAccess]::Read, [System.IO.FileShare]::Read)
        $result.Readable = $true
        $result.Message = 'Berkas dapat dibaca (mode read-only, FileShare.Read).'
    } catch [System.IO.IOException] {
        $result.LockedByOther = $true
        $result.Message = "Berkas sedang ditahan proses lain: $($_.Exception.Message)"
    } catch {
        $result.Message = $_.Exception.Message
    } finally {
        if ($stream) { $stream.Dispose() }
    }
    return $result
}

# ---------------------------------------------------------------------------
# Allowlist hash (penekan positif palsu)
# ---------------------------------------------------------------------------

function Get-OFHashAllowlist {
    <#
    .SYNOPSIS
        Memuat allowlist SHA256 dari allowlist/hashes.txt.
    #>
    [CmdletBinding()]
    param([switch]$Refresh)

    if (-not $Refresh -and $null -ne $script:IntAllowlistCache) { return $script:IntAllowlistCache }
    $table = @{}
    if (Test-Path -LiteralPath $script:IntAllowlistPath) {
        foreach ($line in (Get-Content -LiteralPath $script:IntAllowlistPath -Encoding UTF8)) {
            $trimmed = $line.Trim()
            if (-not $trimmed -or $trimmed.StartsWith('#')) { continue }
            $parts = $trimmed -split '\s+', 2
            $hash = $parts[0].ToUpperInvariant()
            if ($hash -notmatch '^[0-9A-F]{64}$') { continue }
            $note = if ($parts.Count -gt 1) { $parts[1] } else { '' }
            $table[$hash] = $note
        }
    }
    $script:IntAllowlistCache = $table
    return $table
}

function Test-OFHashAllowlist {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$Sha256)
    $table = Get-OFHashAllowlist
    return $table.ContainsKey($Sha256.ToUpperInvariant())
}

function Add-OFHashToAllowlist {
    <#
    .SYNOPSIS
        Menambahkan hash yang sudah diverifikasi sah ke allowlist.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][ValidatePattern('^[0-9a-fA-F]{64}$')][string]$Sha256,
        [string]$Note = ''
    )

    if (-not (Test-Path -LiteralPath $script:IntAllowlistDir)) {
        New-Item -ItemType Directory -Path $script:IntAllowlistDir -Force | Out-Null
    }
    if (-not (Test-Path -LiteralPath $script:IntAllowlistPath)) {
        $header = @(
            '# OpenForensic - allowlist SHA256',
            '# Format: <SHA256> <catatan opsional>',
            '# Hash di daftar ini tidak dipromosikan menjadi temuan.'
        )
        Set-Content -LiteralPath $script:IntAllowlistPath -Value $header -Encoding UTF8
    }
    $upper = $Sha256.ToUpperInvariant()
    if (Test-OFHashAllowlist -Sha256 $upper) { return $false }
    $stamp = (Get-Date).ToString('yyyy-MM-dd')
    $entry = '{0} {1} (ditambahkan {2} oleh {3})' -f $upper, $Note, $stamp, (Get-OFIntActor)
    Add-Content -LiteralPath $script:IntAllowlistPath -Value $entry -Encoding UTF8
    $script:IntAllowlistCache = $null
    return $true
}

function Import-OFHashAllowlist {
    <#
    .SYNOPSIS
        Mengimpor daftar hash dari berkas eksternal (mis. NSRL yang sudah difilter).
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Path,
        [string]$Note = 'impor'
    )

    if (-not (Test-Path -LiteralPath $Path)) { throw "Berkas tidak ditemukan: $Path" }
    $added = 0
    foreach ($line in (Get-Content -LiteralPath $Path)) {
        $match = [regex]::Match($line, '[0-9a-fA-F]{64}')
        if (-not $match.Success) { continue }
        if (Add-OFHashToAllowlist -Sha256 $match.Value -Note $Note) { $added++ }
    }
    $script:IntAllowlistCache = $null
    return $added
}

# ---------------------------------------------------------------------------
# Deduplikasi bukti
# ---------------------------------------------------------------------------

function Test-OFEvidenceDuplicate {
    <#
    .SYNOPSIS
        Mencari bukti yang sudah ada di kasus dengan SHA256 sama.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]$Case,
        [Parameter(Mandatory)][string]$Sha256
    )

    if (-not (Test-OFIntProperty -InputObject $Case -Name 'evidence')) { return $null }
    $upper = $Sha256.ToUpperInvariant()
    foreach ($evidence in @($Case.evidence)) {
        if (-not (Test-OFIntProperty -InputObject $evidence -Name 'sha256')) { continue }
        if ($evidence.sha256 -and $evidence.sha256.ToUpperInvariant() -eq $upper) { return $evidence }
    }
    return $null
}

# ---------------------------------------------------------------------------
# Manifest kasus
# ---------------------------------------------------------------------------

function New-OFCaseManifest {
    <#
    .SYNOPSIS
        Membuat manifest SHA256 atas seluruh isi folder kasus.
    .DESCRIPTION
        Manifest memakai path relatif POSIX dan akhiran baris LF sehingga hash
        manifest tidak berubah hanya karena berpindah OS. Berkas manifest dan segel
        tidak ikut dihitung agar tidak melingkar.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]$Case,
        [switch]$Quiet
    )

    $caseDir = Get-OFIntCaseDir -Case $Case
    $manifestPath = Join-Path $caseDir $script:IntManifestName
    $sealPath = Join-Path $caseDir $script:IntSealName

    $files = @(Get-ChildItem -LiteralPath $caseDir -Recurse -File -Force |
        Where-Object { $_.FullName -ne $manifestPath -and $_.FullName -ne $sealPath })

    $entries = New-Object System.Collections.ArrayList
    $totalBytes = 0
    foreach ($file in $files) {
        $hash = (Get-FileHash -LiteralPath $file.FullName -Algorithm SHA256).Hash
        $relative = Get-OFIntRelativePath -Root $caseDir -FullPath $file.FullName
        [void]$entries.Add([pscustomobject]@{ Hash = $hash; Relative = $relative; Length = $file.Length })
        $totalBytes += $file.Length
    }

    # Urutkan berdasarkan path relatif POSIX agar urutan sama di semua OS.
    $sorted = @($entries | Sort-Object -Property Relative)

    $lines = New-Object System.Collections.ArrayList
    [void]$lines.Add('# OpenForensic case manifest (SHA256)')
    [void]$lines.Add("# caseId: $($Case.caseId)")
    [void]$lines.Add("# dibuat: $((Get-Date).ToString('o'))")
    [void]$lines.Add("# oleh  : $(Get-OFIntActor) @ $(Get-OFIntHostName)")
    [void]$lines.Add("# toolkit: $($script:IntToolkitVersion)")
    [void]$lines.Add('# format: <SHA256>  <path relatif POSIX>  <bytes>')
    foreach ($entry in $sorted) {
        [void]$lines.Add(('{0}  {1}  {2}' -f $entry.Hash, $entry.Relative, $entry.Length))
    }

    [System.IO.File]::WriteAllText($manifestPath, (($lines -join "`n") + "`n"), $script:IntUtf8)
    if (-not $Quiet) { Write-Host "    [manifest] $($sorted.Count) berkas -> $script:IntManifestName" -ForegroundColor DarkGray }

    return [pscustomobject]@{
        ManifestPath = $manifestPath
        FileCount    = $sorted.Count
        TotalBytes   = $totalBytes
        CreatedAt    = (Get-Date).ToString('o')
    }
}

function Test-OFCaseManifest {
    <#
    .SYNOPSIS
        Membandingkan isi folder kasus dengan manifest yang tersimpan.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)]$Case)

    $caseDir = Get-OFIntCaseDir -Case $Case
    $manifestPath = Join-Path $caseDir $script:IntManifestName
    $sealPath = Join-Path $caseDir $script:IntSealName

    $result = [pscustomobject]@{
        ManifestPath = $manifestPath
        Present      = (Test-Path -LiteralPath $manifestPath)
        Ok           = $false
        Parsed       = $false
        Modified     = @()
        Missing      = @()
        Added        = @()
        FileCount    = 0
        Message      = ''
        CheckedAt    = (Get-Date).ToString('o')
    }
    if (-not $result.Present) {
        $result.Message = 'Manifest belum dibuat.'
        return $result
    }

    $expected = @{}
    $lineRegex = '^([0-9A-Fa-f]{64})\s\s(.+?)\s\s(\d+)$'
    foreach ($line in (Get-Content -LiteralPath $manifestPath -Encoding UTF8)) {
        $trimmed = $line.TrimEnd()
        if (-not $trimmed -or $trimmed.StartsWith('#')) { continue }
        $match = [regex]::Match($trimmed, $lineRegex)
        if (-not $match.Success) { continue }
        $relative = $match.Groups[2].Value.Replace([char]92, [char]47)
        $expected[$relative] = $match.Groups[1].Value.ToUpperInvariant()
    }
    $result.FileCount = $expected.Count
    $result.Parsed = ($expected.Count -gt 0)

    if (-not $result.Parsed) {
        $result.Message = 'Manifest ada tetapi tidak satu barisnya dapat diurai - anggap tidak valid.'
        return $result
    }

    $modified = New-Object System.Collections.ArrayList
    $missing = New-Object System.Collections.ArrayList
    $added = New-Object System.Collections.ArrayList
    $seen = @{}

    foreach ($file in @(Get-ChildItem -LiteralPath $caseDir -Recurse -File -Force |
            Where-Object { $_.FullName -ne $manifestPath -and $_.FullName -ne $sealPath })) {
        $relative = Get-OFIntRelativePath -Root $caseDir -FullPath $file.FullName
        $seen[$relative] = $true
        if (-not $expected.ContainsKey($relative)) {
            [void]$added.Add($relative)
            continue
        }
        $actual = (Get-FileHash -LiteralPath $file.FullName -Algorithm SHA256).Hash.ToUpperInvariant()
        if ($actual -ne $expected[$relative]) { [void]$modified.Add($relative) }
    }
    foreach ($relative in $expected.Keys) {
        if (-not $seen.ContainsKey($relative)) { [void]$missing.Add($relative) }
    }

    $result.Modified = @($modified)
    $result.Missing = @($missing)
    $result.Added = @($added)
    $result.Ok = ($modified.Count -eq 0 -and $missing.Count -eq 0)
    $result.Message = if ($result.Ok) {
        'Seluruh berkas pada manifest masih utuh.'
    } else {
        "Manifest tidak cocok: $($modified.Count) berubah, $($missing.Count) hilang."
    }
    return $result
}

# ---------------------------------------------------------------------------
# Segel kriptografis atas manifest
# ---------------------------------------------------------------------------

function New-OFCaseSeal {
    <#
    .SYNOPSIS
        Menyegel manifest kasus dengan HMAC-SHA256.
    .DESCRIPTION
        Mode kunci dipilih otomatis sesuai platform:
          - Windows tanpa -Passphrase: kunci acak 32 byte dilindungi DPAPI CurrentUser.
          - Linux/macOS atau bila -Passphrase diberikan: kunci diturunkan dengan PBKDF2
            (120.000 iterasi, salt acak) sehingga segel dapat diverifikasi di mesin lain.
        Di Linux/macOS tanpa passphrase, segel tidak dapat dibuat karena tidak ada
        penyimpanan kunci setara DPAPI; fungsi akan menolak dengan pesan yang jelas.
    .PARAMETER Force
        Mengizinkan pembuatan segel PBKDF2 dari $env:OPENFORENSIC_SEAL_PASSPHRASE
        pada sesi non-interaktif (mis. pipeline CI atau container).
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]$Case,
        [securestring]$Passphrase,
        [switch]$Force,
        [switch]$Quiet
    )

    $caseDir = Get-OFIntCaseDir -Case $Case
    $manifestPath = Join-Path $caseDir $script:IntManifestName
    if (-not (Test-Path -LiteralPath $manifestPath)) {
        New-OFCaseManifest -Case $Case -Quiet:$Quiet | Out-Null
    }
    $manifestBytes = [System.IO.File]::ReadAllBytes($manifestPath)

    $storageMode = Get-OFIntStorageMode

    # Passphrase dari environment dipakai bila tersedia dan belum diberikan eksplisit.
    if (-not $Passphrase -and $env:OPENFORENSIC_SEAL_PASSPHRASE) {
        $Passphrase = ConvertTo-SecureString -String $env:OPENFORENSIC_SEAL_PASSPHRASE -AsPlainText -Force
        if (-not $Quiet) { Write-Host '    [seal] passphrase diambil dari OPENFORENSIC_SEAL_PASSPHRASE' -ForegroundColor DarkGray }
    }

    if (-not $Passphrase -and $storageMode -ne 'dpapi') {
        throw ('Segel di platform ini memerlukan passphrase karena DPAPI tidak tersedia. ' +
            'Jalankan ulang dengan -Passphrase, atau set $env:OPENFORENSIC_SEAL_PASSPHRASE.')
    }

    $mode = if ($Passphrase) { 'pbkdf2' } else { 'dpapi' }
    $salt = New-Object 'byte[]' 16
    $rng = [System.Security.Cryptography.RandomNumberGenerator]::Create()
    try { $rng.GetBytes($salt) } finally { $rng.Dispose() }

    $protectedKey = $null
    $key = $null
    $kdfHash = $null

    if ($mode -eq 'pbkdf2') {
        $kdfHash = if (Test-OFIntPbkdf2Sha256) { 'sha256' } else { 'sha1' }
        $plain = ConvertFrom-OFIntSecureString -Secure $Passphrase
        if ([string]::IsNullOrEmpty($plain)) { throw 'Passphrase segel kosong.' }
        $key = Get-OFIntDerivedKey -Passphrase $plain -Salt $salt -Iterations $script:IntPbkdf2Iterations -HashName $kdfHash
    } else {
        $key = New-Object 'byte[]' 32
        $rngKey = [System.Security.Cryptography.RandomNumberGenerator]::Create()
        try { $rngKey.GetBytes($key) } finally { $rngKey.Dispose() }
        try {
            $protectedBytes = [System.Security.Cryptography.ProtectedData]::Protect(
                $key, $null, [System.Security.Cryptography.DataProtectionScope]::CurrentUser)
            $protectedKey = [Convert]::ToBase64String($protectedBytes)
        } catch {
            throw "DPAPI tidak tersedia di sistem ini. Gunakan -Passphrase. Detail: $($_.Exception.Message)"
        }
    }

    $hmac = New-Object System.Security.Cryptography.HMACSHA256($key)
    try {
        $signature = [Convert]::ToBase64String($hmac.ComputeHash($manifestBytes))
    } finally {
        $hmac.Dispose()
    }

    $environmentText = "$($PSVersionTable.PSEdition) $($PSVersionTable.PSVersion)"
    if (Get-Command -Name 'Get-OFPlatform' -ErrorAction SilentlyContinue) {
        $platform = Get-OFPlatform
        $environmentText = "$($platform.Os) $($platform.Architecture) / PowerShell $($platform.PSVersion)"
    }

    $seal = [ordered]@{
        schemaVersion  = $script:IntSealSchemaVersion
        caseId         = $Case.caseId
        algorithm      = 'HMACSHA256'
        keyMode        = $mode
        kdfHash        = $kdfHash
        iterations     = if ($mode -eq 'pbkdf2') { $script:IntPbkdf2Iterations } else { $null }
        salt           = [Convert]::ToBase64String($salt)
        protectedKey   = $protectedKey
        manifestSha256 = (Get-FileHash -LiteralPath $manifestPath -Algorithm SHA256).Hash
        signature      = $signature
        sealedAt       = (Get-Date).ToString('o')
        sealedBy       = "$(Get-OFIntActor)@$(Get-OFIntHostName)"
        sealedOn       = $environmentText
        toolkit        = $script:IntToolkitVersion
    }

    $sealPath = Join-Path $caseDir $script:IntSealName
    [System.IO.File]::WriteAllText($sealPath, ($seal | ConvertTo-Json -Depth 5), $script:IntUtf8)
    if (-not $Quiet) {
        Write-Host "    [seal] mode $mode -> $script:IntSealName" -ForegroundColor DarkGray
        if ($mode -eq 'dpapi') {
            Write-Host '    [seal] catatan: segel DPAPI hanya dapat diverifikasi oleh akun Windows ini.' -ForegroundColor DarkGray
        }
    }

    return [pscustomobject]@{
        SealPath       = $sealPath
        KeyMode        = $mode
        KdfHash        = $kdfHash
        ManifestSha256 = $seal.manifestSha256
        SealedAt       = $seal.sealedAt
    }
}

function Test-OFCaseSeal {
    <#
    .SYNOPSIS
        Memverifikasi segel kasus terhadap manifest saat ini.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]$Case,
        [securestring]$Passphrase
    )

    $caseDir = Get-OFIntCaseDir -Case $Case
    $manifestPath = Join-Path $caseDir $script:IntManifestName
    $sealPath = Join-Path $caseDir $script:IntSealName

    $result = [pscustomobject]@{
        Present   = (Test-Path -LiteralPath $sealPath)
        Valid     = $false
        KeyMode   = $null
        SealedAt  = $null
        SealedBy  = $null
        Message   = ''
        CheckedAt = (Get-Date).ToString('o')
    }
    if (-not $result.Present) {
        $result.Message = 'Kasus belum disegel.'
        return $result
    }
    if (-not (Test-Path -LiteralPath $manifestPath)) {
        $result.Message = 'Manifest hilang - segel tidak dapat diverifikasi.'
        return $result
    }

    $seal = Get-Content -LiteralPath $sealPath -Raw -Encoding UTF8 | ConvertFrom-Json
    $result.KeyMode = $seal.keyMode
    $result.SealedAt = $seal.sealedAt
    $result.SealedBy = $seal.sealedBy

    $currentHash = (Get-FileHash -LiteralPath $manifestPath -Algorithm SHA256).Hash
    if ($currentHash -ne $seal.manifestSha256) {
        $result.Message = 'Manifest berubah setelah disegel (hash manifest tidak cocok).'
        return $result
    }

    if (-not $Passphrase -and $seal.keyMode -eq 'pbkdf2' -and $env:OPENFORENSIC_SEAL_PASSPHRASE) {
        $Passphrase = ConvertTo-SecureString -String $env:OPENFORENSIC_SEAL_PASSPHRASE -AsPlainText -Force
    }

    $key = $null
    try {
        $salt = [Convert]::FromBase64String($seal.salt)
        if ($seal.keyMode -eq 'pbkdf2') {
            if (-not $Passphrase) {
                $result.Message = 'Segel memakai passphrase. Berikan -Passphrase untuk verifikasi.'
                return $result
            }
            $plain = ConvertFrom-OFIntSecureString -Secure $Passphrase
            $iterations = if ($seal.iterations) { [int]$seal.iterations } else { $script:IntPbkdf2Iterations }
            $kdfHash = 'sha1'
            if (($seal.PSObject.Properties.Name -contains 'kdfHash') -and $seal.kdfHash) { $kdfHash = [string]$seal.kdfHash }
            $key = Get-OFIntDerivedKey -Passphrase $plain -Salt $salt -Iterations $iterations -HashName $kdfHash
        } else {
            if (-not (Test-OFIntWindows)) {
                $result.Message = 'Segel dibuat dengan DPAPI di Windows dan tidak dapat diverifikasi di platform ini. Segel ulang dengan -Passphrase agar portabel.'
                return $result
            }
            $protectedBytes = [Convert]::FromBase64String($seal.protectedKey)
            $key = [System.Security.Cryptography.ProtectedData]::Unprotect(
                $protectedBytes, $null, [System.Security.Cryptography.DataProtectionScope]::CurrentUser)
        }
    } catch {
        $result.Message = "Kunci segel tidak dapat dibuka: $($_.Exception.Message)"
        return $result
    }

    $manifestBytes = [System.IO.File]::ReadAllBytes($manifestPath)
    $hmac = New-Object System.Security.Cryptography.HMACSHA256($key)
    try {
        $signature = [Convert]::ToBase64String($hmac.ComputeHash($manifestBytes))
    } finally {
        $hmac.Dispose()
    }

    if ($signature -eq $seal.signature) {
        $result.Valid = $true
        $result.Message = 'Segel valid: manifest identik dengan saat disegel.'
    } else {
        $result.Message = 'Segel TIDAK valid: tanda tangan tidak cocok.'
    }
    return $result
}

# ---------------------------------------------------------------------------
# Status integritas gabungan (dipakai report dan AI)
# ---------------------------------------------------------------------------

function Get-OFIntegrityStatus {
    <#
    .SYNOPSIS
        Merangkum status integritas kasus: hash bukti, manifest, segel, versi tool.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]$Case,
        [securestring]$Passphrase
    )

    $evidenceChecks = New-Object System.Collections.ArrayList
    if (Test-OFIntProperty -InputObject $Case -Name 'evidence') {
        foreach ($evidence in @($Case.evidence)) {
            $path = if ((Test-OFIntProperty -InputObject $evidence -Name 'workingPath') -and $evidence.workingPath) { $evidence.workingPath } else { $evidence.originalPath }
            $present = [bool]($path -and (Test-Path -LiteralPath $path))
            $currentHash = $null
            $hashMatches = $null
            if ($present) {
                $currentHash = (Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash.ToUpperInvariant()
                if ($evidence.sha256) { $hashMatches = ($currentHash -eq $evidence.sha256.ToUpperInvariant()) }
            }
            [void]$evidenceChecks.Add([pscustomobject]@{
                EvidenceId   = $evidence.id
                Name         = $evidence.name
                Path         = $path
                Present      = $present
                RecordedHash = $evidence.sha256
                CurrentHash  = $currentHash
                HashMatches  = $hashMatches
                Allowlisted  = [bool]($evidence.sha256 -and (Test-OFHashAllowlist -Sha256 $evidence.sha256))
            })
        }
    }

    $manifest = Test-OFCaseManifest -Case $Case
    $seal = if ($Passphrase) { Test-OFCaseSeal -Case $Case -Passphrase $Passphrase } else { Test-OFCaseSeal -Case $Case }
    $toolVersions = if (Test-OFIntProperty -InputObject $Case -Name 'toolVersions') { @($Case.toolVersions) } else { @() }

    $tampered = @($evidenceChecks | Where-Object { $_.HashMatches -eq $false })
    $missing = @($evidenceChecks | Where-Object { -not $_.Present })

    return [pscustomobject]@{
        CaseId          = $Case.caseId
        EvidenceChecked = $evidenceChecks.Count
        EvidenceOk      = ($tampered.Count -eq 0 -and $missing.Count -eq 0)
        Tampered        = $tampered
        MissingFiles    = $missing
        Allowlisted     = @($evidenceChecks | Where-Object { $_.Allowlisted })
        Manifest        = $manifest
        Seal            = $seal
        ToolVersions    = $toolVersions
        StorageMode     = (Get-OFIntStorageMode)
        OverallOk       = ($tampered.Count -eq 0 -and $missing.Count -eq 0 -and ($manifest.Present -eq $false -or $manifest.Ok) -and ($seal.Present -eq $false -or $seal.Valid))
        CheckedAt       = (Get-Date).ToString('o')
    }
}

function Format-OFIntegritySummary {
    <#
    .SYNOPSIS
        Mengubah status integritas menjadi blok Markdown untuk report dan konteks AI.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)]$Status)

    $lines = New-Object System.Collections.ArrayList
    [void]$lines.Add('### Integritas dan Reproduktifitas')
    [void]$lines.Add('')
    [void]$lines.Add(('- Bukti diperiksa ulang: {0} berkas, status {1}' -f $Status.EvidenceChecked, $(if ($Status.EvidenceOk) { 'seluruh hash cocok' } else { 'ADA KETIDAKCOCOKAN' })))
    foreach ($item in @($Status.Tampered)) {
        [void]$lines.Add(('  - PERINGATAN {0} ({1}): hash tercatat {2}, hash saat ini {3}' -f $item.EvidenceId, $item.Name, $item.RecordedHash, $item.CurrentHash))
    }
    foreach ($item in @($Status.MissingFiles)) {
        [void]$lines.Add(('  - PERINGATAN {0} ({1}): berkas tidak ditemukan di {2}' -f $item.EvidenceId, $item.Name, $item.Path))
    }
    if ($Status.Manifest.Present) {
        [void]$lines.Add(('- Manifest kasus: {0} berkas, {1}' -f $Status.Manifest.FileCount, $(if ($Status.Manifest.Ok) { 'utuh' } else { "berubah ($($Status.Manifest.Modified.Count) modifikasi, $($Status.Manifest.Missing.Count) hilang)" })))
    } else {
        [void]$lines.Add('- Manifest kasus: belum dibuat')
    }
    if ($Status.Seal.Present) {
        [void]$lines.Add(('- Segel kasus: mode {0}, disegel {1} oleh {2}, {3}' -f $Status.Seal.KeyMode, $Status.Seal.SealedAt, $Status.Seal.SealedBy, $(if ($Status.Seal.Valid) { 'VALID' } else { 'TIDAK VALID' })))
        if (-not $Status.Seal.Valid -and $Status.Seal.Message) {
            [void]$lines.Add(('  - Catatan verifikasi: {0}' -f $Status.Seal.Message))
        }
    } else {
        [void]$lines.Add('- Segel kasus: belum disegel')
    }
    if ($Status.PSObject.Properties.Name -contains 'StorageMode' -and $Status.StorageMode) {
        [void]$lines.Add(('- Mode penyimpanan kunci pada platform ini: {0}' -f $Status.StorageMode))
    }
    if (@($Status.ToolVersions).Count -gt 0) {
        [void]$lines.Add('- Versi tool yang dipakai:')
        foreach ($tool in @($Status.ToolVersions)) {
            [void]$lines.Add(('  - {0}: {1}' -f $tool.toolId, $tool.version))
        }
    } else {
        [void]$lines.Add('- Versi tool: belum dicatat (jalankan Update-OFCaseToolVersions)')
    }
    if (@($Status.Allowlisted).Count -gt 0) {
        [void]$lines.Add(('- {0} bukti ada di allowlist hash (berkas sah yang diketahui)' -f @($Status.Allowlisted).Count))
    }
    return ($lines -join "`n")
}

function Invoke-OFCaseSealWorkflow {
    <#
    .SYNOPSIS
        Langkah penutup kasus: catat versi tool, buat manifest, segel, lalu verifikasi.
    .DESCRIPTION
        Di Linux/macOS tanpa passphrase, tahap segel dilewati dengan peringatan
        (manifest tetap dibuat) sehingga penutupan kasus tidak gagal total.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]$Case,
        [securestring]$Passphrase,
        [switch]$Quiet
    )

    if (-not $Quiet) { Write-Host '  Menutup kasus (versi tool -> manifest -> segel)' -ForegroundColor Cyan }
    Update-OFCaseToolVersions -Case $Case -Quiet:$Quiet | Out-Null
    New-OFCaseManifest -Case $Case -Quiet:$Quiet | Out-Null

    $storageMode = Get-OFIntStorageMode
    $canSeal = [bool]($Passphrase -or $storageMode -eq 'dpapi' -or $env:OPENFORENSIC_SEAL_PASSPHRASE)

    if ($canSeal) {
        try {
            if ($Passphrase) {
                New-OFCaseSeal -Case $Case -Passphrase $Passphrase -Quiet:$Quiet | Out-Null
            } else {
                New-OFCaseSeal -Case $Case -Quiet:$Quiet | Out-Null
            }
        } catch {
            Write-Warning "Segel gagal dibuat: $($_.Exception.Message)"
        }
    } elseif (-not $Quiet) {
        Write-Host '  [!] Segel dilewati: platform ini butuh passphrase (-Passphrase atau OPENFORENSIC_SEAL_PASSPHRASE).' -ForegroundColor Yellow
    }

    $status = if ($Passphrase) { Get-OFIntegrityStatus -Case $Case -Passphrase $Passphrase } else { Get-OFIntegrityStatus -Case $Case }

    if (-not $Quiet) {
        if ($status.OverallOk) {
            Write-Host '  Integritas kasus: OK' -ForegroundColor Green
        } else {
            Write-Host '  Integritas kasus: PERLU PERHATIAN' -ForegroundColor Red
        }
    }
    return $status
}

Export-ModuleMember -Function @(
    'Invoke-OFProcessWithTimeout',
    'Get-OFToolVersion',
    'Update-OFCaseToolVersions',
    'Protect-OFEvidenceFile',
    'Test-OFEvidenceLock',
    'Get-OFHashAllowlist',
    'Test-OFHashAllowlist',
    'Add-OFHashToAllowlist',
    'Import-OFHashAllowlist',
    'Test-OFEvidenceDuplicate',
    'New-OFCaseManifest',
    'Test-OFCaseManifest',
    'New-OFCaseSeal',
    'Test-OFCaseSeal',
    'Get-OFIntegrityStatus',
    'Format-OFIntegritySummary',
    'Invoke-OFCaseSealWorkflow'
)
