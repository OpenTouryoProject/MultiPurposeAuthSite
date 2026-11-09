@echo off
rem NOTE: keep this file pure ASCII. cmd.exe reads a batch file by byte offset, so non-ASCII text
rem       can break lines depending on the console code page (root/CODING.md section 4. #342).
rem
rem Start the MPAS stub (#294 / #340).
rem
rem   Usage: 2_DockerComposeUp.bat [parameter file]
rem     parameter file : a copy of .env.sample (e.g. my-stub.env. README.md section 2).
rem                      If omitted, the defaults in docker-compose.yml are used.
rem
rem   Preparation (publish and certificate) is 1_PublishStub.ps1 (first time, and after updating MPAS).
rem   If the published output is older than the sources, a warning is shown (..\Common\CheckPublishFreshness.ps1).
rem   "--build" is required (same as ..\E2E\): without it, the published output does not get into the image.
setlocal

set "ENVARG="
if not "%~1"=="" (
    if not exist "%~f1" goto :noenvfile
    set "ENVARG=--env-file "%~f1""
)

pushd "%~dp0"

powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0..\Common\CheckPublishFreshness.ps1" -PublishDir "%~dp0app\publish"

docker compose %ENVARG% up -d --build
if errorlevel 1 goto :error

echo.
echo  The MPAS stub has been started (check: /.well-known/openid-configuration returns 200).
echo  To reset its state:  docker compose %ENVARG% restart
echo  To stop and remove:  3_DockerComposeDown.bat [parameter file]
popd
endlocal
goto :eof

:error
echo.
echo  Failed.
popd
endlocal
exit /b 1

:noenvfile
rem Do not "exit /b" inside parentheses: called via "cmd /c", the exit code can become 0.
echo  Parameter file not found: %~f1
endlocal
exit /b 1
