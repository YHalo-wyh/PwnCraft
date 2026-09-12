@echo off
setlocal EnableExtensions
call "%~dp0launch-new.bat" %*
exit /b %errorlevel%
