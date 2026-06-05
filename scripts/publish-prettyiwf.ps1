# Publish PrettyIWF to GitHub (run once after: gh auth login)
# Author: Ahmad Raeiji <ahmad.rayeji@gmail.com>

$ErrorActionPreference = "Stop"
$gh = "C:\Program Files\GitHub CLI\gh.exe"
$repoRoot = Split-Path $PSScriptRoot -Parent
Set-Location $repoRoot

& $gh auth status
if ($LASTEXITCODE -ne 0) {
    Write-Host "Run: & '$gh' auth login"
    exit 1
}

$exists = & $gh repo view arayeji/PrettyIWF 2>$null
if ($LASTEXITCODE -ne 0) {
    & $gh repo create arayeji/PrettyIWF --public `
        --description "GTP and GSUP interworking function for Osmocom and Open5GS"
    if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
} else {
    Write-Host "Repository arayeji/PrettyIWF already exists."
}

git remote remove pretty 2>$null
git remote add pretty https://github.com/arayeji/PrettyIWF.git

git push pretty master:main --force
git push pretty feature/gtpv1-gtpv2-interworking `
            feature/gsup-hss-diameter-proxy `
            feature/map-s6d-interworking `
            feature/public-docs-and-config

Write-Host "Done: https://github.com/arayeji/PrettyIWF"
