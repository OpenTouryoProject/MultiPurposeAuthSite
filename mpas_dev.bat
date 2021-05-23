@echo off

@rem 開発中のOpenTouryoのdllをMultiPurposeAuthSiteに、
@rem （3_BuildLibsAtOtherReposInTimeOfDev.batより迅速に、）渡すbat。

@rem 本ファイルを適切なフォルダに配置するか、以下のパスを修正してからダブルクリックして実行する。

@rem 既定では、任意のフォルダにOpenTouryoとMultiPurposeAuthSiteをcloneし、
@rem 当該フォルダに本バッチファイルをコピーして実行することを想定している。

xcopy /E /Y /I "OpenTouryo\root\programs\CS\Frameworks\Infrastructure\Build_net48" "MultiPurposeAuthSite\root\programs\OpenTouryoAssemblies\Build_net48\"
xcopy /E /Y /I "OpenTouryo\root\programs\CS\Frameworks\Infrastructure\Build_netcore50" "MultiPurposeAuthSite\root\programs\OpenTouryoAssemblies\Build_netcore50\"