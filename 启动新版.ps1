$ErrorActionPreference = 'Stop'
$inner = Join-Path (Split-Path -Parent $MyInvocation.MyCommand.Path) 'pwncraft'
Set-Location $inner
& (Join-Path $inner '启动新版.ps1')
