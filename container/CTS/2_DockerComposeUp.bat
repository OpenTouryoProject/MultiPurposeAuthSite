@echo off
rem NOTE: keep this file pure ASCII. cmd.exe reads a batch file by byte offset, so non-ASCII text
rem       can break lines depending on the console code page (root/11_CODING.md section 4. #342).
rem
rem Start the conformance suite (OpenID Foundation, pinned version) and its OP (MPAS net10.0, mem) (#350).
rem
rem   The steps live in 2_DockerComposeUp.ps1 (#439). This file only calls it, so that the steps are
rem   not kept twice. On Linux, call 2_DockerComposeUp.ps1 with pwsh.
rem
rem   The OP uses the published output and the certificate of ..\E2E\ (run ..\E2E\1_PublishIdP.ps1 first).
rem   The suite and MongoDB need memory: stop other containers you do not need (..\E2E\, ..\Store\).
setlocal
powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp02_DockerComposeUp.ps1" %*
set "RC=%ERRORLEVEL%"
endlocal & exit /b %RC%
