@echo off
rem NOTE: keep this file pure ASCII. cmd.exe reads a batch file by byte offset, so non-ASCII text
rem       can break lines depending on the console code page (root/11_CODING.md section 4. #342).
rem
rem Stop and remove the MPAS stub (#340).
rem
rem   Usage: 3_DockerComposeDown.bat [parameter file]
rem     Pass the same file as 2_DockerComposeUp.bat. (The compose project name is fixed to
rem     mpas-stub, so it is removed even if omitted.)
rem
rem   The steps live in 3_DockerComposeDown.ps1 (#401). This file only calls it, so that the steps are
rem   not kept twice. On Linux, call 3_DockerComposeDown.ps1 with pwsh (README.md section 1).
rem
rem   No state remains (UserStoreType=mem). The DataProtection keys (keys\) and logs (logs\) remain on the host.
setlocal
powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp03_DockerComposeDown.ps1" %*
set "RC=%ERRORLEVEL%"
endlocal & exit /b %RC%
