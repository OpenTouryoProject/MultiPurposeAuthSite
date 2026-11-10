@echo off
rem NOTE: keep this file pure ASCII. cmd.exe reads a batch file by byte offset, so non-ASCII text
rem       can break lines depending on the console code page (root/CODING.md section 4. #342).
rem
rem Stop and remove the conformance suite and its OP (#350).
rem The OP keeps no state (UserStoreType=mem). The suite's results stay in mongo\ on the host,
rem and the DataProtection keys (keys\) and logs (logs\) also stay.
pushd "%~dp0"
rem Pass .env.cts too (made by Prepare.ps1), otherwise compose warns that CTS_REGISTRATION_OWNER is not set.
if exist ".env.cts" (
    docker compose --env-file "..\E2E\.env" --env-file ".env.cts" down
) else (
    docker compose --env-file "..\E2E\.env" down
)
popd
