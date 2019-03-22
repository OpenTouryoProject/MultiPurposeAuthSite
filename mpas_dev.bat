@echo off

@rem 開発中のOpenTouryoのdllをMultiPurposeAuthSiteに、
@rem （3_BuildLibsAtOtherReposInTimeOfDev.batより迅速に、）渡すbat。

@rem 本ファイルを適切なフォルダに配置するか、以下のパスを修正してからダブルクリックして実行する。

@rem 既定値は、フォルダ X にOpenTouryoとMultiPurposeAuthSiteをcloneした場合、
@rem フォルダ X に本 bat ファイルをコピーして実行することを想定している。

xcopy /E /Y /I "OpenTouryo\root\programs\CS\Frameworks\Infrastructure\Build_net47" "MultiPurposeAuthSite\root\programs\OpenTouryoAssemblies\Build_net47\"
xcopy /E /Y /I "OpenTouryo\root\programs\CS\Frameworks\Infrastructure\Build_netcore20" "MultiPurposeAuthSite\root\programs\OpenTouryoAssemblies\Build_netcore20\"
xcopy /E /Y /I "OpenTouryo\root\programs\CS\Frameworks\Infrastructure\Build_netcore30" "MultiPurposeAuthSite\root\programs\OpenTouryoAssemblies\Build_netcore30\"