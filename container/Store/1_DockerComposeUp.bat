@echo off
rem NOTE: keep this file pure ASCII. cmd.exe reads a batch file by byte offset, so non-ASCII text
rem       can break lines depending on the console code page (root/CODING.md section 4. #342).
rem
rem Copy the DDL first, so that a stale schema is never started (#250 step 1).
powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp00_CopyInitSql.ps1"
if errorlevel 1 goto :error

rem The DBs are NOT started here. They have profiles, so "up -d" starts nothing.
rem Start only the one you use, by name. Starting all three at once can exhaust the VM memory
rem (see "memory" in docker-compose.yml). In the full E2E run, test.ps1 starts and stops it.
rem The IdPs for ID federation are in ..\E2E\ (#318). Details: ..\README.md.

echo.
echo  The DDL has been copied. No DB has been started.
echo  Start only the one you use, by name:
echo.
echo    docker compose up -d sqlserver     (UserStoreType=sql, port 1434)
echo    docker compose up -d oracle        (UserStoreType=ora, port 1522)
echo    docker compose up -d postgres      (UserStoreType=npg, port 5433)
echo.
echo  Do not start two or more at the same time (E2E uses one store at a time).
echo  Stop it when done:  docker compose stop ^<service^>
echo.
echo  The first start of Oracle takes a few minutes.
echo  Wait until "docker compose ps" shows healthy.
echo.
echo  How to pass the connection string: root\TESTING.md section 1.
goto :eof

:error
echo.
echo  Failed.
exit /b 1
