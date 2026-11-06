@echo off
rem **DDL を先に流し込む**（コピー忘れで古いスキーマのまま起動するのを防ぐ。#250 の段階 1）
powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp00_CopyInitSql.ps1"
if errorlevel 1 goto :error

rem **DB は、ここでは起動しない。** 3 つの DB には profiles が付いているので、
rem   up -d では何も起動しない。**使う 1 つだけを、名前を指定して起動する。**
rem   **DB を 3 つ同時に起動すると、VM がメモリを使い切って固まることがある**ため
rem   （docker-compose.yml の「メモリの節約」）。
rem
rem   **E2E の通しでは、test.ps1 が起動・停止する**（-UserStoreType が mem 以外のとき）。
rem   **ID 連携の IdP 群は ..\E2E\ に在る**（#318 で分けた）。

echo.
echo  DDL を流し込みました。**DB は起動していません。** 使う 1 つだけを、名前を指定して起動してください。
echo.
echo    docker compose up -d sqlserver     ：sql で回すとき（1434）
echo    docker compose up -d oracle        ：ora で回すとき（1522）
echo    docker compose up -d postgres      ：npg で回すとき（5433）
echo.
echo  **同時に 2 つ以上を起動しないでください。**
echo    E2E は 1 回に 1 つのストアしか使いません。
echo    使い終わったら  docker compose stop ^<サービス名^>  で止めてください。
echo.
echo  **Oracle の初回起動は数分かかります。**
echo    docker compose ps  で healthy になるのを待ってください。
echo.
echo  接続文字列の渡し方は root\TESTING.md 1 節を見てください。
goto :eof

:error
echo.
echo  失敗しました。
exit /b 1
