@echo off

@rem �J������OpenTouryo��dll��MultiPurposeAuthSite�ɁA
@rem �i3_BuildLibsAtOtherReposInTimeOfDev.bat���v���ɁA�j�n��bat�B

@rem �{�t�@�C����K�؂ȃt�H���_�ɔz�u���邩�A�ȉ��̃p�X���C�����Ă���_�u���N���b�N���Ď��s����B

@rem ����ł́A�C�ӂ̃t�H���_��OpenTouryo��MultiPurposeAuthSite��clone���A
@rem ���Y�t�H���_�ɖ{�o�b�`�t�@�C�����R�s�[���Ď��s���邱�Ƃ�z�肵�Ă���B

xcopy /E /Y /I "OpenTouryo\root\programs\CS\Frameworks\Infrastructure\Build_net48" "MultiPurposeAuthSite\root\programs\OpenTouryoAssemblies\Build_net48\"
xcopy /E /Y /I "OpenTouryo\root\programs\CS\Frameworks\Infrastructure\Build_netcore50" "MultiPurposeAuthSite\root\programs\OpenTouryoAssemblies\Build_netcore50\"