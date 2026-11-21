@echo off
rem NOTE: keep this file pure ASCII. cmd.exe reads a batch file by byte offset, so non-ASCII text
rem       can break lines depending on the console code page (root/11_CODING.md section 4. #342).
rem
rem Start the MPAS stub (#294 / #340).
rem
rem   Usage: 2_DockerComposeUp.bat [parameter file]
rem     parameter file : a copy of .env.sample (e.g. my-stub.env. README.md section 2).
rem                      If omitted, the defaults in docker-compose.yml are used.
rem
rem   The steps live in 2_DockerComposeUp.ps1 (#401). This file only calls it, so that the steps are
rem   not kept twice. On Linux, call 2_DockerComposeUp.ps1 with pwsh (README.md section 1).
rem
rem   Preparation (publish and certificate) is 1_PublishStub.ps1 (first time, and after updating MPAS).
setlocal
powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp02_DockerComposeUp.ps1" %*
set "RC=%ERRORLEVEL%"
endlocal & exit /b %RC%
