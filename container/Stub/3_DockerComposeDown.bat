@echo off
rem **MPAS のスタブを止めて消す**（#340）。
rem
rem   使い方 : 3_DockerComposeDown.bat [パラメタのファイル]
rem     **起動（2_DockerComposeUp.bat）と同じファイルを渡す**（compose のプロジェクトは同じ名前 mpas-stub なので、省略しても消える）。
rem
rem   **状態は残らない**（UserStoreType=mem）。**DataProtection の鍵（keys\）とログ（logs\）はホストに残る。**
setlocal

set "ENVARG="
if not "%~1"=="" (
    if not exist "%~f1" goto :noenvfile
    set "ENVARG=--env-file "%~f1""
)

pushd "%~dp0"
docker compose %ENVARG% down
popd
endlocal
goto :eof

:noenvfile
rem **括弧の中で exit /b しない**（cmd /c から呼ぶと、終了コードが 0 になることがある）。
echo  パラメタのファイルがありません : %~f1
endlocal
exit /b 1
