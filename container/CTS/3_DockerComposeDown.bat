@echo off
rem NOTE: keep this file pure ASCII. cmd.exe reads a batch file by byte offset, so non-ASCII text
rem       can break lines depending on the console code page (root/11_CODING.md section 4. #342).
rem
rem Stop and remove the conformance suite and its OP (#350).
rem
rem   The steps live in 3_DockerComposeDown.ps1 (#439). This file only calls it, so that the steps are
rem   not kept twice. On Linux, call 3_DockerComposeDown.ps1 with pwsh.
rem
rem   The OP keeps no state (UserStoreType=mem). The suite's results stay in mongo\ on the host,
rem   and the DataProtection keys (keys\) and logs (logs\) also stay.
setlocal
powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp03_DockerComposeDown.ps1" %*
set "RC=%ERRORLEVEL%"
endlocal & exit /b %RC%
