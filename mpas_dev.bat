@echo off
@rem NOTE: keep this file pure ASCII. cmd.exe reads a batch file by byte offset, so non-ASCII text
@rem       can break lines depending on the console code page (root/CODING.md section 4. #342).

@rem Copy the OpenTouryo DLLs under development to MultiPurposeAuthSite
@rem (faster than 3_BuildLibsAtOtherReposInTimeOfDev.bat).

@rem Put this file in a suitable folder, or fix the paths below, then double-click it.

@rem By default, it assumes that OpenTouryo and MultiPurposeAuthSite are cloned into the same folder,
@rem and that this batch file is copied to that folder and run there.

xcopy /E /Y /I "OpenTouryo\root\programs\CS\Frameworks\Infrastructure\Build_net48" "MultiPurposeAuthSite\root\programs\OpenTouryoAssemblies\Build_net48\"
xcopy /E /Y /I "OpenTouryo\root\programs\CS\Frameworks\Infrastructure\Build_netcore100" "MultiPurposeAuthSite\root\programs\OpenTouryoAssemblies\Build_netcore100\"

pause
