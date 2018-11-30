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
rem Batch build of 9_MultiPurposeAuthSiteCmn.
rem --------------------------------------------------
dotnet restore "CommonLibrary\NetStdLibrary\NetStdLibrary.sln"
dotnet msbuild %COMMANDLINE% "CommonLibrary\NetStdLibrary\NetStdLibrary.sln"

nuget.exe restore "CommonLibrary\IndividualLibrary\NetFxLibrary\NetFxLibrary.sln"
%BUILDFILEPATH% %COMMANDLINE% "CommonLibrary\IndividualLibrary\NetFxLibrary\NetFxLibrary.sln"

dotnet restore "CommonLibrary\IndividualLibrary\NetCoreLibrary\NetCoreLibrary.sln"
dotnet msbuild %COMMANDLINE% "CommonLibrary\IndividualLibrary\NetCoreLibrary\NetCoreLibrary.sln"

pause

rem -------------------------------------------------------
endlocal
