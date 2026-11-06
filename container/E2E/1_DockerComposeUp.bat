@echo off
rem **IdP コンテナの publish と証明書**（#250 の段階 2）。
rem   **成果物は 1 つで、上流も下流も同じイメージを使う**（#281）。
powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp00_PublishIdP.ps1"
if errorlevel 1 goto :error

rem **docker compose（v2）**。docker-compose（v1）は廃止
rem
rem   **--build を付ける**（#294）。付けないと、イメージが在る限り作り直さず、
rem   **上で publish した成果物がコンテナに入らない**（古いアプリのまま動き続ける）。
rem
rem   **E2E 用の DB は ..\Store\ に在る**（#318 で分けた）。ここでは起動しない。
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
echo  使い終わったら  docker compose stop  で止めてください。
goto :eof

:error
echo.
echo  失敗しました。
exit /b 1
