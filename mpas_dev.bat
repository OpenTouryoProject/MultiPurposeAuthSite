@echo off

@rem �J������OpenTouryo��dll��MultiPurposeAuthSite�ɁA
@rem �i3_BuildLibsAtOtherReposInTimeOfDev.bat���v���ɁA�j�n��bat�B

@rem �{�t�@�C����K�؂ȃt�H���_�ɔz�u���邩�A�ȉ��̃p�X���C�����Ă���_�u���N���b�N���Ď��s����B

@rem ����l�́A�t�H���_ X ��OpenTouryo��MultiPurposeAuthSite��clone�����ꍇ�A
@rem �t�H���_ X �ɖ{ bat �t�@�C�����R�s�[���Ď��s���邱�Ƃ�z�肵�Ă���B

xcopy /E /Y /I "OpenTouryo\root\programs\CS\Frameworks\Infrastructure\Build_net47" "MultiPurposeAuthSite\root\programs\OpenTouryoAssemblies\Build_net47\"
xcopy /E /Y /I "OpenTouryo\root\programs\CS\Frameworks\Infrastructure\Build_netcore20" "MultiPurposeAuthSite\root\programs\OpenTouryoAssemblies\Build_netcore20\"
xcopy /E /Y /I "OpenTouryo\root\programs\CS\Frameworks\Infrastructure\Build_netcore30" "MultiPurposeAuthSite\root\programs\OpenTouryoAssemblies\Build_netcore30\"