@echo off
rem NOTE: keep this file pure ASCII. cmd.exe reads a batch file by byte offset, so non-ASCII text
rem       can break lines depending on the console code page (root/CODING.md section 4. #342).
rem
rem Rebuild and start the IdPs (upstream, upstream2, downstream) and jwks (#250 / #281 / #284 / #292).
rem
rem   Preparation (publish and certificate) is 1_PublishIdP.ps1 (#340). Run it first after changing MPAS.
rem   If the published output is older than the sources, a warning is shown (..\Common\CheckPublishFreshness.ps1).
rem   The local appsettings.json is mounted at startup; the image contains the template (#340).
rem   The DBs for E2E are in ..\Store\ (#318); they are not started here.
pushd "%~dp0"

powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0..\Common\CheckPublishFreshness.ps1" -PublishDir "%~dp0app\publish"

rem docker compose (v2). "--build" is required (#294): without it, the published output does not get into the image.
docker compose up -d --build
if errorlevel 1 goto :error

echo.
echo  The IdP containers have been started (UserStoreType=mem).
echo    upstream     : https://localhost:44301
echo    upstream2    : https://localhost:44304
echo    downstream   : https://localhost:44303
echo    jwks (nginx) : http://localhost:44305   (stands in for a client's jwks_uri. RT-309.*)
echo.
echo  E2E CN-* tests measure these containers.
echo  When done:  3_DockerComposeDown.bat  (or "docker compose stop" to just stop them)
popd
goto :eof

:error
echo.
echo  Failed.
popd
exit /b 1
