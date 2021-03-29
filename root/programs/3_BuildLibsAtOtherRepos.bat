@echo off

@rem 本バッチファイルの作成にあたり、以下のサイトを参考にしました。
@rem 【Bat】【vim】香り屋Vimをダウンロードしてインストールまでするbatファイル - Qiita
@rem https://qiita.com/koryuohproject/items/beed1a28ad6a1f60256d

setlocal

@rem ZIPファイル名
set zipfilename=Temp.zip

@rem GitHubのZIPパス
set branchName=02-70
set srcUrl=https://github.com/OpenTouryoProject/OpenTouryoTemplates/archive/%branchName%.zip

@rem 解凍ディレクトリ
set extDir=%CD%

@rem 一時ディレクトリ
set tmpDir=Temp

:Download
@rem ダウンロードされたZIPファイルがあるなら解凍
if exist %extDir%\%zipfilename% GOTO Extract

@rem ZIPファイルのダウンロード
@powershell -NoProfile -ExecutionPolicy Bypass -Command "$d=new-object System.Net.WebClient; [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.SecurityProtocolType]::Tls12; $d.Proxy.Credentials=[System.Net.CredentialCache]::DefaultNetWorkCredentials; $d.DownloadFile('%srcUrl%','%extDir%/%zipfilename%')"

:Extract
@rem 一時ディレクトリがあるならビルドへ
if exist %extDir%\%tmpDir% GOTO Build

@rem ZIPファイルを一時ディレクトリに解凍
@powershell -NoProfile -ExecutionPolicy Bypass -Command "expand-archive %zipfilename%"

:Build
@rem ビルドがあるならコピーへ
if exist "Temp\OpenTouryoTemplates-%branchName%\root_VS2019\programs\CS\Frameworks\Infrastructure\Build_netcore50" GOTO Xcopy

@rem batファイルを使用してビルド
cd "Temp\OpenTouryoTemplates-%branchName%\root_VS2019\programs\CS\"
echo | call 3_Build_Business_net48.bat
echo | call 3_Build_Business_netcore50.bat

:Xcopy
@rem ビルド出力をコピー
cd %extDir%
xcopy /Y /E "Temp\OpenTouryoTemplates-%branchName%\root_VS2019\programs\CS\Frameworks\Infrastructure\Build_net48" "OpenTouryoAssemblies\Build_net48\"
xcopy /Y /E "Temp\OpenTouryoTemplates-%branchName%\root_VS2019\programs\CS\Frameworks\Infrastructure\Build_netcore50" "OpenTouryoAssemblies\Build_netcore50\"

pause

:EOF
endlocal