@echo off
rem NOTE: keep this file pure ASCII. cmd.exe reads a batch file by byte offset, so non-ASCII text
rem       can break lines depending on the console code page (root/CODING.md section 4. #342).
rem
rem Stop and remove the IdP and jwks containers. No state remains (every IdP uses UserStoreType=mem).
rem The DataProtection keys (keys*\) and logs (logs*\) remain on the host.
rem The DBs for E2E are removed by ..\Store\2_DockerComposeDown.bat (#318).
rem (Renamed from 2_DockerComposeDown.bat in #340.)
pushd "%~dp0"
docker compose down
popd
