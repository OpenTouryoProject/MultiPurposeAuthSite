@echo off
@echo �J������OpenTouryo��dll��MultiPurposeAuthSite�ɁA
@echo �i3_BuildLibsByBatsAtOtherReposInTimeOfDev.bat���v���ɁA�j�n��bat�B
@echo �{�t�@�C�������̃t�H���_�K�w�ɔz�u���ă_�u���N���b�N���Ď��s����B
xcopy /E /Y /I "OpenTouryo\root\programs\CS\Frameworks\Infrastructure\Build_net47" "MultiPurposeAuthSite\root\programs\OpenTouryoAssemblies\Build_net47\"
xcopy /E /Y /I "OpenTouryo\root\programs\CS\Frameworks\Infrastructure\Build_netcore20" "MultiPurposeAuthSite\root\programs\OpenTouryoAssemblies\Build_netcore20\"