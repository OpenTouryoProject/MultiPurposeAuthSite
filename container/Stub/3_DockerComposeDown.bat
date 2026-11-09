@echo off
rem NOTE: keep this file pure ASCII. cmd.exe reads a batch file by byte offset, so non-ASCII text
rem       can break lines depending on the console code page (root/CODING.md section 4. #342).
rem
rem Stop and remove the MPAS stub (#340).
rem
rem   Usage: 3_DockerComposeDown.bat [parameter file]
rem     Pass the same file as 2_DockerComposeUp.bat. (The compose project name is fixed to
rem     mpas-stub, so it is removed even if omitted.)
rem
rem   No state remains (UserStoreType=mem). The DataProtection keys (keys\) and logs (logs\) remain on the host.
setlocal

set "ENVARG="
if not "%~1"=="" (
    if not exist "%~f1" goto :noenvfile
    set "ENVARG=--env-file "%~f1""
)

pushd "%~dp0"
docker compose %ENVARG% down
popd
endlocal
goto :eof

:noenvfile
rem Do not "exit /b" inside parentheses: called via "cmd /c", the exit code can become 0.
echo  Parameter file not found: %~f1
endlocal
exit /b 1
