@echo off
rem NOTE: keep this file pure ASCII. cmd.exe reads a batch file by byte offset, so non-ASCII text
rem       can break lines depending on the console code page (root/CODING.md section 4. #342).
rem
rem Start the conformance suite (OpenID Foundation, pinned version) and its OP (MPAS net10.0, mem) (#350).
rem
rem   The OP uses the published output and the certificate of ..\E2E\ (run ..\E2E\1_PublishIdP.ps1 first).
rem   The certificate password is read from ..\E2E\.env (made by 1_PublishIdP.ps1).
rem   The local appsettings.json is mounted at startup; the image contains the template (#340).
rem   The suite and MongoDB need memory: stop other containers you do not need (..\E2E\, ..\Store\).
pushd "%~dp0"

if not exist "..\E2E\.env" goto :noprep

powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0..\Common\CheckPublishFreshness.ps1" -PublishDir "%~dp0..\E2E\app\publish"

rem docker compose (v2). "--build" puts the published output into the OP image (#294).
docker compose --env-file "..\E2E\.env" up -d --build
if errorlevel 1 goto :error

echo.
echo  The conformance suite and its OP have been started.
echo    conformance suite : https://localhost.emobix.co.uk:8443/
echo    OP (issuer)       : https://mpas-cts.localhost:44311
echo    discovery         : https://mpas-cts.localhost:44311/.well-known/openid-configuration
echo.
echo  The suite takes a minute or two to start. Test plans and configs: config\ and README.md.
echo  When done:  3_DockerComposeDown.bat
popd
goto :eof

:noprep
echo.
echo  ..\E2E\.env was not found. Run ..\E2E\1_PublishIdP.ps1 first.
popd
exit /b 1

:error
echo.
echo  Failed.
popd
exit /b 1
