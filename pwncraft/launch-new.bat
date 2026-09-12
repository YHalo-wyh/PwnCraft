@echo off
setlocal EnableExtensions
chcp 65001 >nul 2>nul

title PwnCraft Launcher
set "MODE=start"
set "SKIP_INSTALL=0"
if /I "%~1"=="--smoke" set "MODE=smoke"
if /I "%~1"=="--shot" set "MODE=shot"
if /I "%~1"=="--check" set "MODE=smoke"
if /I "%~1"=="--no-install" set "SKIP_INSTALL=1"
if /I "%~2"=="--no-install" set "SKIP_INSTALL=1"
set "LAUNCH_DIR=%~dp0"
set "LOG=%LAUNCH_DIR%pwncraft-launch.log"
>"%LOG%" echo [%date% %time%] launcher start

echo [PwnCraft] 正在定位项目目录...
echo launch_dir=%LAUNCH_DIR%>>"%LOG%"

set "ROOT="
if exist "%LAUNCH_DIR%pwncraft-electron\package.json" set "ROOT=%LAUNCH_DIR%."
if not defined ROOT (
  for /d %%D in ("%LAUNCH_DIR%*") do (
    if exist "%%~fD\pwncraft-electron\package.json" set "ROOT=%%~fD"
  )
)
if not defined ROOT (
  echo [错误] 找不到 pwncraft-electron\package.json。
  echo [错误] 找不到 package.json>>"%LOG%"
  goto fail
)
for %%I in ("%ROOT%") do set "ROOT=%%~fI"
echo root=%ROOT%>>"%LOG%"
echo [PwnCraft] 项目目录: %ROOT%

where node.exe >nul 2>nul
if errorlevel 1 (
  echo [错误] 未找到 node.exe。请安装 Node.js LTS，或把 Node.js 加到 PATH。
  echo missing node>>"%LOG%"
  goto fail
)
where npm.cmd >nul 2>nul
if errorlevel 1 (
  echo [错误] 未找到 npm.cmd。请确认 Node.js 安装完整并加入 PATH。
  echo missing npm>>"%LOG%"
  goto fail
)
where python.exe >nul 2>nul
if errorlevel 1 (
  where py.exe >nul 2>nul
  if errorlevel 1 (
    echo [错误] 未找到 python.exe/py.exe。请安装 Python 并加入 PATH。
    echo missing python>>"%LOG%"
    goto fail
  )
)

cd /d "%ROOT%\pwncraft-electron" || goto fail

echo [PwnCraft] 当前目录: %CD%
echo electron_dir=%CD%>>"%LOG%"

if "%SKIP_INSTALL%"=="0" if not exist "node_modules\electron" (
  echo [首次启动] 缺少 Electron 依赖，正在 npm install...
  echo npm install start>>"%LOG%"
  call npm install --registry=https://registry.npmmirror.com >>"%LOG%" 2>&1
  if errorlevel 1 (
    echo [错误] npm install 失败，详情见: %LOG%
    goto fail
  )
)

set "PYTHONPATH=%ROOT%"
set "PYTHONIOENCODING=utf-8"
if /I "%MODE%"=="smoke" (
  echo [PwnCraft] 运行启动冒烟测试...
  echo npm run smoke>>"%LOG%"
  call npm run smoke >>"%LOG%" 2>&1
) else if /I "%MODE%"=="shot" (
  echo [PwnCraft] 启动截图审计模式...
  echo npm start -- --shot>>"%LOG%"
  call npm start -- --shot >>"%LOG%" 2>&1
) else (
  echo [PwnCraft] 启动新版 Electron Workbench...
  echo npm start>>"%LOG%"
  call npm start >>"%LOG%" 2>&1
)
set "EC=%ERRORLEVEL%"
echo exit_code=%EC% >>"%LOG%"
if not "%EC%"=="0" (
  echo [错误] Electron 退出码: %EC%，详情见: %LOG%
  goto fail
)
exit /b 0

:fail
echo.
echo 启动失败。日志: %LOG%
echo 请把这个窗口内容或 pwncraft-launch.log 发给我。
pause
exit /b 1
