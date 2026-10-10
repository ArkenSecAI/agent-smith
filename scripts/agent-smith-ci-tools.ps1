param([Parameter(Mandatory=$true)][ValidateSet('bun', 'gitleaks')][string]$Tool)
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

# Public release metadata and SHA-256 evidence are recorded in the development guide.
# Downloads are extracted only after comparing against the committed hash.
if ($Tool -eq 'bun') {
    switch ("$env:RUNNER_OS-$env:RUNNER_ARCH") {
        'Linux-X64' { $asset = 'bun-linux-x64.zip'; $sha = '36368faef7527875d5ffa52e53cd48021741f2a83eb6208a8dd64068d422a913'; $binary = 'bun-linux-x64/bun' }
        'Windows-X64' { $asset = 'bun-windows-x64.zip'; $sha = 'ce4c17497b2f29712a99d3d53f028de28cd42e3bacb8589599e7f000e49b6405'; $binary = 'bun-windows-x64/bun.exe' }
        'macOS-ARM64' { $asset = 'bun-darwin-aarch64.zip'; $sha = '90987a3a16d7db556d886ac3d551e7b6d3edf0a1cf43acaed622e8676be1d12f'; $binary = 'bun-darwin-aarch64/bun' }
        default { throw "Unsupported candidate runner: $env:RUNNER_OS-$env:RUNNER_ARCH" }
    }
    $url = "https://github.com/oven-sh/bun/releases/download/bun-v1.4.2/$asset"
} else {
    if ("$env:RUNNER_OS-$env:RUNNER_ARCH" -ne 'Linux-X64') { throw 'Gitleaks CI bootstrap requires Linux x64' }
    $asset = 'gitleaks_8.30.1_linux_x64.tar.gz'
    $sha = '551f6fc83ea457d62a0d98237cbad105af8d557003051f41f3e7ca7b3f2470eb'
    $binary = 'gitleaks'
    $url = "https://github.com/gitleaks/gitleaks/releases/download/v8.30.1/$asset"
}

if (-not $env:RUNNER_TEMP -or -not $env:GITHUB_PATH) { throw 'This bootstrap is for disposable GitHub-hosted jobs only; Main supplies local toolchains' }
$destination = Join-Path $env:RUNNER_TEMP "agent-smith-$Tool"
New-Item -ItemType Directory -Path $destination | Out-Null
$download = Join-Path $destination $asset
Invoke-WebRequest -Uri $url -OutFile $download
$actual = (Get-FileHash -Algorithm SHA256 -LiteralPath $download).Hash.ToLowerInvariant()
if ($actual -ne $sha) { throw "$asset SHA-256 mismatch: $actual" }
if ($Tool -eq 'bun') {
    Expand-Archive -LiteralPath $download -DestinationPath $destination
} else {
    & tar -xzf $download -C $destination gitleaks LICENSE
    if ($LASTEXITCODE -ne 0) { throw 'Gitleaks extraction failed' }
}
$executable = Join-Path $destination $binary
if ($env:RUNNER_OS -ne 'Windows') {
    & chmod 755 $executable
    if ($LASTEXITCODE -ne 0) { throw 'Could not set tool executable permission' }
}
$version = if ($Tool -eq 'bun') { & $executable --version } else { & $executable version }
if ($LASTEXITCODE -ne 0) { throw "$Tool version command failed" }
$expected = if ($Tool -eq 'bun') { '1.4.2' } else { '8.30.1' }
if ($version.Trim() -ne $expected) { throw "Expected $Tool $expected, got $version" }
Split-Path -Parent $executable | Out-File -FilePath $env:GITHUB_PATH -Encoding utf8 -Append
Write-Host "$Tool $expected verified from $url ($sha)"
