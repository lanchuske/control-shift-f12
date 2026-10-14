param(
    [switch]$Uninstall,
    [string]$AssetFile = $env:SEAMLESS_INPUT_ASSET_FILE,
    [string]$AssetUrl = $env:SEAMLESS_INPUT_ASSET_URL,
    [string]$Sha256 = $env:SEAMLESS_INPUT_SHA256
)
$ErrorActionPreference = 'Stop'
$InstallDir = Join-Path $env:LOCALAPPDATA 'SeamlessInput\bin'
$Target = Join-Path $InstallDir 'seamless-input.exe'

if ($Uninstall) {
    Remove-Item -LiteralPath $Target -Force -ErrorAction SilentlyContinue
    $Current = [Environment]::GetEnvironmentVariable('Path', [EnvironmentVariableTarget]::User)
    $Filtered = @($Current -split ';' | Where-Object { $_ -and $_ -ne $InstallDir }) -join ';'
    [Environment]::SetEnvironmentVariable('Path', $Filtered, [EnvironmentVariableTarget]::User)
    Write-Host 'Removed the SeamlessInput executable. Pairing identities and configuration were preserved.'
    exit 0
}
if ((-not $AssetFile -and -not $AssetUrl) -or -not $Sha256) {
    throw 'Provide a pinned release asset (file or HTTPS URL) and its published SHA-256.'
}
New-Item -ItemType Directory -Force -Path $InstallDir | Out-Null
$Temp = "$Target.new"
$Backup = "$Target.rollback"
if ($AssetFile) {
    Copy-Item -LiteralPath $AssetFile -Destination $Temp -Force
} else {
    if (-not $AssetUrl.StartsWith('https://', [StringComparison]::OrdinalIgnoreCase)) {
        throw 'Remote assets must use HTTPS.'
    }
    Invoke-WebRequest -Uri $AssetUrl -OutFile $Temp -UseBasicParsing
}
if ((Get-FileHash -Algorithm SHA256 -LiteralPath $Temp).Hash -ne $Sha256) {
    Remove-Item -LiteralPath $Temp -Force
    throw 'Checksum verification failed; existing installation was not changed.'
}
if (Test-Path -LiteralPath $Target) { Copy-Item $Target $Backup -Force }
try {
    Move-Item -LiteralPath $Temp -Destination $Target -Force
} catch {
    if (Test-Path -LiteralPath $Backup) { Move-Item $Backup $Target -Force }
    throw
}
Remove-Item -LiteralPath $Backup -Force -ErrorAction SilentlyContinue
$Current = [Environment]::GetEnvironmentVariable('Path', [EnvironmentVariableTarget]::User)
$Parts = @($Current -split ';' | Where-Object { $_ })
if ($Parts -notcontains $InstallDir) {
    [Environment]::SetEnvironmentVariable('Path', (($Parts + $InstallDir) -join ';'), [EnvironmentVariableTarget]::User)
}
Write-Host 'Installed for the current user. Open a new terminal and run: seamless-input doctor'
