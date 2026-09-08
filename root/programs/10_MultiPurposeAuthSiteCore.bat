setlocal

@rem --------------------------------------------------
@rem Turn off the echo function.
@rem --------------------------------------------------
@echo off

@rem --------------------------------------------------
@rem Get the path to the executable file.
@rem --------------------------------------------------
set CURRENT_DIR="%~dp0"

@rem --------------------------------------------------
@rem Execution of the common processing.
@rem --------------------------------------------------
call %CURRENT_DIR%z_Common.bat

rem --------------------------------------------------
rem Batch build of CommandLineToolsCore.
rem --------------------------------------------------
dotnet restore "CommandLineTools\CommandLineToolsCore.sln"
dotnet msbuild %COMMANDLINE% "CommandLineTools\CommandLineToolsCore.sln"

pause

rem --------------------------------------------------
rem Batch build of MultiPurposeAuthSiteCore.
rem
rem The npm / grunt restore of the client libraries was removed.
rem   - wwwroot\lib is committed to the repository
rem   - there is no package.json and no Gruntfile
rem   - RestoreLib1.bat / RestoreLib2.bat no longer exist, so the calls
rem     here failed
rem This follows the same move made in the OpenTouryo repository
rem (10_Build_WebAppCore_sample.bat).
rem --------------------------------------------------
dotnet restore "MultiPurposeAuthSiteCore\MultiPurposeAuthSiteCore.sln"
dotnet msbuild %COMMANDLINE% "MultiPurposeAuthSiteCore\MultiPurposeAuthSiteCore.sln"

pause

rem -------------------------------------------------------
endlocal
