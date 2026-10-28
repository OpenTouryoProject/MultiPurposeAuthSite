@echo off
rem **DDL を先に流し込む**（コピー忘れで古いスキーマのまま起動するのを防ぐ。#250 の段階 1）
powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp00_CopyInitSql.ps1"
if errorlevel 1 goto :error

rem **IdP コンテナの publish と証明書**（#250 の段階 2）。
rem   **成果物は 1 つで、上流も下流も同じイメージを使う**（#281）。
powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp03_PublishUpstream.ps1"
if errorlevel 1 goto :error

rem **docker compose（v2）**。docker-compose（v1）は廃止
rem
rem   **DB は起動しない。** 3 つの DB には profiles が付いているので、
rem   up -d では IdP のコンテナ（上流・上流 2・下流）だけが起動する。
rem   **DB を 3 つ同時に起動すると、VM がメモリを使い切って固まることがある**ため
rem   （docker-compose.yml の「メモリの節約」）。
rem
rem   **--build を付ける**（#294）。付けないと、イメージが在る限り作り直さず、
rem   **上で publish した成果物がコンテナに入らない**（古いアプリのまま動き続ける）。
docker compose up -d --build
if errorlevel 1 goto :error

echo.
echo  IdP のコンテナを起動しました。
echo  上流 IdP    : https://localhost:44301  （UserStoreType=mem）
echo  上流 IdP 2  : https://localhost:44304  （UserStoreType=mem）
echo  下流 IdP    : https://localhost:44303  （UserStoreType=mem）
echo.
echo  **コンテナ 3 つでハイブリッド IdP 構成になっています**（#281 / #284 / #292）。
echo    E2E の CN-* がこれらを測ります。
echo.
echo  **相手の JWK Set を配るコンテナも起動しています**（http://localhost:44305）。
echo    クライアントの jwks_uri の代わりです（RT-309.* がこれを測ります。#309）。
echo.
echo  **DB は起動していません。** 使う 1 つだけを、名前を指定して起動してください。
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
