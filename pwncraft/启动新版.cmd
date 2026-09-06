@echo off
setlocal EnableExtensions
if exist "%~dp0launch-new.bat" (
  call "%~dp0launch-new.bat" %*
  exit /b %errorlevel%
)
for /d %%D in ("%~dp0*") do (
  if exist "%%~fD\launch-new.bat" (
    call "%%~fD\launch-new.bat" %*
    exit /b %errorlevel%
  )
)
echo Cannot find launch-new.bat
pause
exit /b 1
