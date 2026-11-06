@echo off
rem **docker compose（v2）**。IdP 群と jwks のコンテナを止めて消す。
rem
rem   **状態は残らない**（どの IdP も UserStoreType=mem）。
rem   **DataProtection の鍵（keys*\）とログ（logs*\）はホストに残る。**
rem   **E2E 用の DB は ..\Store\2_DockerComposeDown.bat で消す**（#318 で分けた）。
rem   （#340 で 2_DockerComposeDown.bat から改名した。起動を 2_DockerComposeUp.bat にしたため）
pushd "%~dp0"
docker compose down
popd
