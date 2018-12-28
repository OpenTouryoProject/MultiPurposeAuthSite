@echo off
@echo 開発中のOpenTouryoのdllをMultiPurposeAuthSiteに、
@echo （3_BuildLibsByBatsAtOtherReposInTimeOfDev.batより迅速に、）渡すbat。
@echo 本ファイルを一つ上のフォルダ階層に配置してダブルクリックして実行する。
xcopy /E /Y /I "OpenTouryo\root\programs\CS\Frameworks\Infrastructure\Build_net47" "MultiPurposeAuthSite\root\programs\OpenTouryoAssemblies\Build_net47\"
xcopy /E /Y /I "OpenTouryo\root\programs\CS\Frameworks\Infrastructure\Build_netcore20" "MultiPurposeAuthSite\root\programs\OpenTouryoAssemblies\Build_netcore20\"