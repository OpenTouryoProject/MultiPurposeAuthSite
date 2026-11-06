@echo off
rem **IdP 群（上流・上流 2・下流）と jwks のコンテナを、作り直して起動する**（#250 / #281 / #284 / #292）。
rem
rem   **用意（publish と証明書）は 1_PublishIdP.ps1**（#340 で分けた。..\Stub\ と同じ作法）。
rem   **MPAS を直したら、先に 1_PublishIdP.ps1 を実行すること。**
rem   **成果物がソースより古ければ、警告する**（起動は止めない。..\Common\CheckPublishFreshness.ps1）。
rem
rem   **手元の appsettings.json を、起動時にマウントする**（docker-compose.yml。イメージの中は雛形。#340）。
rem
rem   **E2E 用の DB は ..\Store\ に在る**（#318 で分けた）。ここでは起動しない。
pushd "%~dp0"

powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0..\Common\CheckPublishFreshness.ps1" -PublishDir "%~dp0app\publish"

rem **docker compose（v2）**。docker-compose（v1）は廃止
rem
rem   **--build を付ける**（#294）。付けないと、イメージが在る限り作り直さず、
rem   **publish した成果物がコンテナに入らない**（古いアプリのまま動き続ける）。
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
echo  使い終わったら  3_DockerComposeDown.bat  で止めて消してください（docker compose stop で止めるだけでもよい）。
popd
goto :eof

:error
echo.
echo  失敗しました。
popd
exit /b 1
