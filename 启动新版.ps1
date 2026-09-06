$ErrorActionPreference = 'Stop'
$inner = Join-Path (Split-Path -Parent $MyInvocation.MyCommand.Path) 'pwn宝'
Set-Location $inner
& (Join-Path $inner '启动新版.ps1')
