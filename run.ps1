#Requires -Version 5.1
<#
    OpenForensic - entry point CLI.

    Contoh:
      .\run.ps1 vol -f memory.dmp windows.pslist
      .\run.ps1 olevba "sample macro.xls"
      .\run.ps1 strings evidence.png
      .\run.ps1 -OFList

    Semua argumen setelah tool id diteruskan apa adanya ke tool sebagai array,
    sehingga tidak ada evaluasi shell terhadap nama file.
    Flag internal diberi prefiks -OF agar tidak bertabrakan dengan flag tool.
#>

[CmdletBinding()]
param(
    [Parameter(Position = 0)]
    [string]$ToolId,

    [Parameter(Position = 1, ValueFromRemainingArguments = $true)]
    [string[]]$OFArguments = @(),

    [switch]$OFList,
    [switch]$OFNoReport,
    [string]$OFPlugin = ''
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

Import-Module (Join-Path $PSScriptRoot 'OpenForensic.psd1') -Force

if ($OFList -or [string]::IsNullOrWhiteSpace($ToolId)) {
    Write-Host ''
    Write-Host 'Tool OpenForensic yang terdaftar:' -ForegroundColor Cyan
    Get-OFToolStatus |
        Select-Object @{ N = 'Id'; E = { $_.Id } },
                      @{ N = 'Tersedia'; E = { if ($_.Available) { 'ya' } else { 'tidak' } } },
                      @{ N = 'Kategori'; E = { $_.Category } },
                      @{ N = 'Nama'; E = { $_.Name } },
                      @{ N = 'Cara pasang'; E = { $_.InstallHint } } |
        Format-Table -AutoSize
    Write-Host 'Pemakaian: .\run.ps1 <id> <argumen tool...>' -ForegroundColor DarkGray
    return
}

Initialize-OFWorkspace

$tool = Resolve-OFTool -Id $ToolId
if (-not $tool.Available) {
    Write-Host "[-] Tool '$ToolId' tidak tersedia. Cara memasang: $($tool.InstallHint)" -ForegroundColor Red
    exit 2
}

# Cari file bukti di antara argumen untuk keperluan hashing & report.
$targetPath = $null
foreach ($argument in $OFArguments) {
    if (Test-Path -LiteralPath $argument -PathType Leaf) {
        $targetPath = (Get-Item -LiteralPath $argument).FullName
        break
    }
}

$report = $null
if ($targetPath -and -not $OFNoReport) {
    $report = New-OFReport -TargetPath $targetPath
    Write-Host "[*] Target : $targetPath" -ForegroundColor Green
    Write-Host "[*] SHA256 : $($report.Hashes.SHA256)" -ForegroundColor DarkGray
    Write-Host "[*] Tipe   : $($report.FileType.Kind)" -ForegroundColor DarkGray
    if ($report.FileType.TypeMismatch) {
        Write-Host "[!] Ekstensi tidak cocok dengan isi file (kemungkinan disamarkan)." -ForegroundColor Yellow
    }
    Write-Host "[*] Report : $($report.TextPath)" -ForegroundColor DarkGray
} elseif (-not $targetPath) {
    Write-Host '[i] Tidak ada file bukti yang terdeteksi di argumen; report tidak dibuat.' -ForegroundColor DarkGray
}

if ($tool.Source -eq 'builtin') {
    if (-not $targetPath) {
        Write-Host "[-] Tool '$ToolId' memerlukan path file yang valid." -ForegroundColor Red
        exit 2
    }
    $result = Invoke-OFToolById -ToolId $ToolId -TargetPath $targetPath -Report $report
} elseif ($OFArguments.Count -gt 0) {
    $result = Invoke-OFTool -ToolPath $tool.Path -Arguments $OFArguments -Report $report
} elseif ($targetPath) {
    $result = Invoke-OFToolById -ToolId $ToolId -TargetPath $targetPath -Plugin $OFPlugin -Report $report
} else {
    Write-Host "[-] Tidak ada argumen. Contoh: .\run.ps1 $ToolId <file>" -ForegroundColor Red
    exit 2
}

if ($report) {
    [void](Save-OFReport -Report $report)
    Write-Host "[+] Report tersimpan: $($report.TextPath)" -ForegroundColor Cyan
    Write-Host "[+] Report JSON    : $($report.JsonPath)" -ForegroundColor DarkGray
}

if ($result) { exit $result.ExitCode }
exit 0
