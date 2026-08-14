#Requires -Version 5.1
<#
    .SYNOPSIS
    Diagnostik lingkungan OpenForensic (padanan ./openforensic.sh doctor untuk Windows).

    .DESCRIPTION
    Menampilkan platform, kemampuan yang didukung di sistem operasi ini, ketersediaan tool,
    package manager yang terdeteksi, dan konfigurasi AI aktif. Berguna sebelum memulai
    pemeriksaan dan saat melaporkan masalah.

    .PARAMETER Markdown
    Cetak ringkasan dalam Markdown agar mudah disisipkan ke laporan atau issue.

    .PARAMETER ToolsOnly
    Hanya tampilkan status tool.

    .EXAMPLE
    .\doctor.ps1

    .EXAMPLE
    .\doctor.ps1 -Markdown
#>
[CmdletBinding()]
param(
    [switch]$Markdown,
    [switch]$ToolsOnly
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

Import-Module (Join-Path $PSScriptRoot 'OpenForensic.psd1') -Force -DisableNameChecking

if ($Markdown) {
    Format-OFPlatformSummary -IncludeMatrix
    Write-Output ''
    Write-Output '### Status Tool'
    Write-Output ''
    Write-Output '| Tool | Tersedia | Path |'
    Write-Output '| --- | --- | --- |'
    foreach ($tool in (Get-OFToolStatus)) {
        $mark = if ($tool.Available) { 'ya' } else { 'tidak' }
        Write-Output ("| {0} | {1} | {2} |" -f $tool.Id, $mark, $tool.Path)
    }
    return
}

if (-not $ToolsOnly) {
    Write-Host ''
    Write-Host '=============== DIAGNOSTIK OPENFORENSIC ===============' -ForegroundColor Magenta
    Get-OFPlatform | Format-List

    Write-Host 'Kemampuan pada platform ini:' -ForegroundColor Cyan
    Test-OFPlatformCompatibility | Format-Table Feature, Supported, Notes -AutoSize -Wrap

    $managers = @(Get-OFPackageManager)
    $managerText = if ($managers.Count -gt 0) { $managers -join ', ' } else { 'tidak ada' }
    Write-Host "Package manager terdeteksi: $managerText" -ForegroundColor DarkGray

    if (Get-Command -Name 'Get-OFAiModelList' -ErrorAction SilentlyContinue) {
        $active = @(Get-OFAiModelList | Where-Object { $_.Active })
        if ($active.Count -gt 0) {
            Write-Host "Profil AI aktif  : $($active[0].Name) ($($active[0].BaseProvider) / $($active[0].Model))" -ForegroundColor DarkGray
        } else {
            Write-Host 'Profil AI aktif  : belum ada (jalankan Initialize-OFAiModelDefaults)' -ForegroundColor DarkGray
        }
    }
    Write-Host ''
}

$tools = @(Get-OFToolStatus)
$available = @($tools | Where-Object { $_.Available })
Write-Host ("Tool tersedia: {0} dari {1}" -f $available.Count, $tools.Count) -ForegroundColor Cyan
$tools | Sort-Object -Property @{ Expression = 'Available'; Descending = $true }, Id |
    Format-Table Id, Name, Available, Path -AutoSize

$missing = @($tools | Where-Object { -not $_.Available })
if ($missing.Count -gt 0) {
    Write-Host 'Saran pemasangan untuk tool yang belum tersedia (sesuai OS ini):' -ForegroundColor Yellow
    foreach ($tool in $missing) {
        $hint = Get-OFInstallHint -ToolId $tool.Id -FallbackHint ([string]$tool.InstallHint)
        Write-Host ("  {0,-14} {1}" -f $tool.Id, $hint) -ForegroundColor DarkGray
    }
    Write-Host ''
    if (Test-OFWindows) {
        Write-Host 'Jalankan .\setup_tools.ps1 untuk pemasangan otomatis.' -ForegroundColor DarkGray
    } else {
        Write-Host 'Jalankan ./setup_tools.sh untuk pemasangan otomatis.' -ForegroundColor DarkGray
    }
}
