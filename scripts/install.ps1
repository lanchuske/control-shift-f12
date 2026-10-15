param(
    [switch]$Uninstall,
    [string]$AssetFile = $env:SEAMLESS_INPUT_ASSET_FILE,
    [string]$AssetUrl = $env:SEAMLESS_INPUT_ASSET_URL,
    [string]$Sha256 = $env:SEAMLESS_INPUT_SHA256,
    [string]$AttestationFile = $env:SEAMLESS_INPUT_ATTESTATION_FILE,
    [string]$AttestationUrl = $env:SEAMLESS_INPUT_ATTESTATION_URL,
    [string]$ExpectedTag = $env:SEAMLESS_INPUT_EXPECTED_TAG
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
if ((-not $AssetFile -and -not $AssetUrl) -or -not $Sha256 -or -not $ExpectedTag -or (-not $AttestationFile -and -not $AttestationUrl)) {
    throw 'Provide a release asset, its SHA-256, and its GitHub provenance attestation.'
}
if ($ExpectedTag -notmatch '^v[0-9]+\.[0-9]+\.[0-9]+$') {
    throw 'Expected tag must be a reviewed semantic release tag.'
}
if (-not (Get-Command gh -ErrorAction SilentlyContinue)) {
    throw 'GitHub CLI is required to verify release provenance.'
}
New-Item -ItemType Directory -Force -Path $InstallDir | Out-Null
$Temp = "$Target.new"
$Backup = "$Target.rollback"
$AttestationTemp = "$Target.attestation"
if ($AssetFile) {
    Copy-Item -LiteralPath $AssetFile -Destination $Temp -Force
} else {
    if (-not $AssetUrl.StartsWith('https://', [StringComparison]::OrdinalIgnoreCase)) {
        throw 'Remote assets must use HTTPS.'
    }
    Invoke-WebRequest -Uri $AssetUrl -OutFile $Temp -UseBasicParsing
}
if ($AttestationFile) {
    Copy-Item -LiteralPath $AttestationFile -Destination $AttestationTemp -Force
} else {
    if (-not $AttestationUrl.StartsWith('https://', [StringComparison]::OrdinalIgnoreCase)) {
        throw 'Remote attestations must use HTTPS.'
    }
    Invoke-WebRequest -Uri $AttestationUrl -OutFile $AttestationTemp -UseBasicParsing
}
if ((Get-FileHash -Algorithm SHA256 -LiteralPath $Temp).Hash -ne $Sha256) {
    Remove-Item -LiteralPath $Temp -Force
    Remove-Item -LiteralPath $AttestationTemp -Force -ErrorAction SilentlyContinue
    throw 'Checksum verification failed; existing installation was not changed.'
}
& gh attestation verify $Temp --repo lanchuske/seamless-input --bundle $AttestationTemp --source-ref "refs/tags/$ExpectedTag" | Out-Null
if ($LASTEXITCODE -ne 0) {
    Remove-Item -LiteralPath $Temp -Force -ErrorAction SilentlyContinue
    Remove-Item -LiteralPath $AttestationTemp -Force -ErrorAction SilentlyContinue
    throw 'Provenance verification failed; existing installation was not changed.'
}
Remove-Item -LiteralPath $AttestationTemp -Force -ErrorAction SilentlyContinue
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
