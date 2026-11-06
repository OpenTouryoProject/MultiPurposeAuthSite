@echo off
rem **MPAS のスタブを起動する**（#294 / #340）。
rem
rem   使い方 : 2_DockerComposeUp.bat [パラメタのファイル]
rem     パラメタのファイル : .env.sample を写して作ったもの（my-stub.env など。README.md 2 節）。
rem                          **省略すると docker-compose.yml の既定値で起動する。**
rem
rem   **用意（publish と証明書）は 1_PublishStub.ps1**（最初と、MPAS を更新したとき）。
rem   **成果物がソースより古ければ、警告する**（起動は止めない。..\Common\CheckPublishFreshness.ps1）。
rem
rem   **--build を付ける**（..\E2E\ と同じ。付けないと、publish した成果物がイメージに入らない）。
setlocal

set "ENVARG="
if not "%~1"=="" (
    if not exist "%~f1" goto :noenvfile
    set "ENVARG=--env-file "%~f1""
)

pushd "%~dp0"

powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0..\Common\CheckPublishFreshness.ps1" -PublishDir "%~dp0app\publish"

docker compose %ENVARG% up -d --build
if errorlevel 1 goto :error

echo.
echo  MPAS のスタブを起動しました（起動の確認 : /.well-known/openid-configuration が 200 を返せばよい）。
echo  まっさらに戻すなら  docker compose %ENVARG% restart 、止めて消すなら  3_DockerComposeDown.bat [パラメタのファイル] 。
popd
endlocal
goto :eof

:error
echo.
echo  失敗しました。
popd
endlocal
exit /b 1

:noenvfile
rem **括弧の中で exit /b しない**（cmd /c から呼ぶと、終了コードが 0 になることがある）。
echo  パラメタのファイルがありません : %~f1
endlocal
exit /b 1
