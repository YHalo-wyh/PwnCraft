# PwnCraft Electron Workbench 一键启动（新版）
$ErrorActionPreference = 'Stop'
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8
$mode = 'start'
$skipInstall = $false
if ($args -contains '--smoke' -or $args -contains '--check') { $mode = 'smoke' }
elseif ($args -contains '--shot') { $mode = 'shot' }
if ($args -contains '--no-install') { $skipInstall = $true }

$here = Split-Path -Parent $MyInvocation.MyCommand.Path
Set-Location $here

if (Test-Path (Join-Path $here 'pwncraft-electron/package.json')) {
  $root = $here
} elseif (Test-Path (Join-Path $here 'pwncraft/pwncraft-electron/package.json')) {
  $root = Join-Path $here 'pwncraft'
} else {
  throw "找不到 pwncraft-electron/package.json，当前目录：$here"
}

if (-not (Get-Command node -ErrorAction SilentlyContinue)) { throw '未找到 Node.js，请先安装 Node.js LTS。' }
if (-not (Get-Command npm -ErrorAction SilentlyContinue)) { throw '未找到 npm，请确认 Node.js 已加入 PATH。' }
if (-not (Get-Command python -ErrorAction SilentlyContinue) -and -not (Get-Command py -ErrorAction SilentlyContinue)) { throw '未找到 Python，请安装 Python 并加入 PATH。' }

$electronDir = Join-Path $root 'pwncraft-electron'
Set-Location $electronDir
if (-not $skipInstall -and -not (Test-Path 'node_modules/electron')) {
  Write-Host '[首次启动] 正在安装 Electron 依赖...'
  npm install --registry=https://registry.npmmirror.com
}

$env:PYTHONPATH = $root
$env:PYTHONIOENCODING = 'utf-8'
Write-Host '[启动] PwnCraft Electron Workbench'
if ($mode -eq 'smoke') {
  npm run smoke
} elseif ($mode -eq 'shot') {
  npm start -- --shot
} else {
  npm start
}
