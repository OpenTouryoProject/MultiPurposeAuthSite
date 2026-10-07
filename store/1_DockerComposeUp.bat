@echo off
rem **DDL を先に流し込む**（コピー忘れで古いスキーマのまま起動するのを防ぐ。#250 の段階 1）
powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp00_CopyInitSql.ps1"
if errorlevel 1 goto :error

rem **IdP コンテナの publish と証明書**（#250 の段階 2）。
rem   **成果物は 1 つで、上流も下流も同じイメージを使う**（#281）。
powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp03_PublishUpstream.ps1"
if errorlevel 1 goto :error

rem **docker compose（v2）**。docker-compose（v1）は廃止
docker compose up -d
if errorlevel 1 goto :error

echo.
echo  E2E 用の UserStore を起動しました（ポートは +1）。
echo    SQL Server : 1434 / Oracle : 1522 / PostgreSQL : 5433
echo  上流 IdP    : https://localhost:44301  （UserStoreType=mem）
echo.
echo  **下流 IdP コンテナは、ここでは起動しません**（#281）。
echo    E2E は下流をホストで動かすためです。
echo    コンテナ 2 つでハイブリッド IdP 構成を取るときは、次を実行してください。
echo      docker compose up -d downstream      （https://localhost:44303）
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
