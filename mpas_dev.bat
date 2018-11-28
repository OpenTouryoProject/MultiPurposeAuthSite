@echo off
@echo 開発中のOpenTouryoのdllをMultiPurposeAuthSiteに渡すbat。
@echo 一つ上のフォルダ階層に配置してダブルクリックして実行する。
xcopy /E /Y "OpenTouryo\root\programs\CS\Frameworks\Infrastructure\Build" "MultiPurposeAuthSite\root\programs\Frameworks\Infrastructure\Build\"
xcopy /E /Y "OpenTouryo\root\programs\CS\Frameworks\Infrastructure\Build_netcore20\netcoreapp2.0" "MultiPurposeAuthSite\root\programs\Frameworks\Infrastructure\Build_netcore20\"