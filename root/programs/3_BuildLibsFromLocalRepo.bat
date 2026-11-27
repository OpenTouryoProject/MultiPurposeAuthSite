@echo off
@rem NOTE: keep this file pure ASCII. cmd.exe reads a batch file by byte offset, so non-ASCII text
@rem       can break lines depending on the console code page (root/11_CODING.md section 4. #342).
@rem
@rem Build the OpenTouryo assemblies from a local clone of OpenTouryo, and copy them to
@rem OpenTouryoAssemblies (#348). Called by 1_BuildAll.ps1 -OpenTouryoDir.
@rem
@rem   %1 : the root folder of the OpenTouryo clone (the folder that has root\programs\CS)
@rem
@rem It builds the same 4 steps as 3_BuildLibsAtOtherReposInTimeOfDev.bat (NuGet and Business,
@rem net48 and netcore100), but does not download the develop ZIP and does not pause.
@rem The CI (.github/workflows/build-and-test.yml) passes OpenTouryo checked out at a fixed commit (OTR_REF).
@rem
@rem Errors are reported as "[ERROR] ..." lines, which 1_BuildAll.ps1 counts.
@rem Do not write parentheses inside "if" blocks: a closing one would end the block.

setlocal

set "OTR_CS=%~1\root\programs\CS"
set "MPAS_PROG=%CD%"

if exist "%OTR_CS%\2_Build_NuGet_net48.bat" goto :build
echo [ERROR] OpenTouryo is not found: %OTR_CS%
goto :end

:build
echo  OpenTouryo           : %~1
echo  OpenTouryoAssemblies : %MPAS_PROG%\OpenTouryoAssemblies
echo.

@rem The OpenTouryo batch files call their siblings by bare name, so run them in their folder.
pushd "%OTR_CS%"
echo | call 2_Build_NuGet_net48.bat
echo | call 3_Build_Business_net48.bat
echo | call 2_Build_NuGet_netcore100.bat
echo | call 3_Build_Business_netcore100.bat
popd

xcopy /Y /E /I "%OTR_CS%\Frameworks\Infrastructure\Build_net48" "%MPAS_PROG%\OpenTouryoAssemblies\Build_net48\"
if errorlevel 1 echo [ERROR] xcopy failed: Build_net48
xcopy /Y /E /I "%OTR_CS%\Frameworks\Infrastructure\Build_netcore100" "%MPAS_PROG%\OpenTouryoAssemblies\Build_netcore100\"
if errorlevel 1 echo [ERROR] xcopy failed: Build_netcore100

:end
endlocal
