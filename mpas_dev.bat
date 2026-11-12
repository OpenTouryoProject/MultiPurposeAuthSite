@echo off
@rem NOTE: keep this file pure ASCII. cmd.exe reads a batch file by byte offset, so non-ASCII text
@rem       can break lines depending on the console code page (root/CODING.md section 4. #342).

@rem Copy the OpenTouryo DLLs under development to MultiPurposeAuthSite
@rem (faster than 3_BuildLibsAtOtherReposInTimeOfDev.bat).
@rem
@rem Where the two repositories are (#344, OpenTouryoProject/OpenTouryo#652):
@rem   1. If both environment variables OT_OTR_PATH (OpenTouryo) and OT_MPAS_PATH (MultiPurposeAuthSite)
@rem      are set, they are used. This batch file can then be run from anywhere.
@rem      To register them, see OpenTouryo root/files/tools/PowerShell/RepoPaths/Register-RepoPaths.ps1.
@rem      The old names OTR_PATH and MPAS_PATH are no longer read (renamed with the OT_ prefix,
@rem      OpenTouryoProject/OpenTouryo#652).
@rem   2. Otherwise, the paths are relative to the current folder, as before: it assumes that
@rem      OpenTouryo and MultiPurposeAuthSite are cloned into the same folder, and that this
@rem      batch file is copied to that folder and run there (double-click).
@rem
@rem Do not write parentheses inside "if" blocks: a closing one would end the block.

setlocal

if defined OT_OTR_PATH if defined OT_MPAS_PATH goto :fromenv

if defined OT_OTR_PATH echo  OT_MPAS_PATH is not set, so OT_OTR_PATH is not used either.
if defined OT_MPAS_PATH echo  OT_OTR_PATH is not set, so OT_MPAS_PATH is not used either.

set "OTR_ROOT=OpenTouryo"
set "MPAS_ROOT=MultiPurposeAuthSite"
echo  Using the paths relative to the current folder: %CD%
goto :copy

:fromenv
set "OTR_ROOT=%OT_OTR_PATH%"
set "MPAS_ROOT=%OT_MPAS_PATH%"
echo  Using the environment variables OT_OTR_PATH and OT_MPAS_PATH.

:copy
echo    OpenTouryo           : %OTR_ROOT%
echo    MultiPurposeAuthSite : %MPAS_ROOT%
echo.

xcopy /E /Y /I "%OTR_ROOT%\root\programs\CS\Frameworks\Infrastructure\Build_net48" "%MPAS_ROOT%\root\programs\OpenTouryoAssemblies\Build_net48\"
xcopy /E /Y /I "%OTR_ROOT%\root\programs\CS\Frameworks\Infrastructure\Build_netcore100" "%MPAS_ROOT%\root\programs\OpenTouryoAssemblies\Build_netcore100\"

endlocal
pause
