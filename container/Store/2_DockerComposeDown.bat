@echo off
rem NOTE: keep this file pure ASCII. cmd.exe reads a batch file by byte offset, so non-ASCII text
rem       can break lines depending on the console code page (root/CODING.md section 4. #342).
rem
rem Stop and remove the DB containers, with their volumes (-v). They are for E2E and can be recreated.
rem All three profiles must be listed. Services with profiles are not targets of "down" otherwise,
rem and "--remove-orphans" does not remove them either (..\README.md).
docker compose --profile postgres --profile sqlserver --profile oracle down -v
