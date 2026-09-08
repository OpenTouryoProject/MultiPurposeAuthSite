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

@rem --------------------------------------------------
@rem nuget.exe is needed on the net48 side.
@rem MultiPurposeAuthSite\MultiPurposeAuthSite\packages.config cannot be
@rem restored by MSBuild -t:Restore.
@rem
@rem nuget.exe is kept next to this batch file, so this normally holds.
@rem Warn instead of stopping, for a working tree where it is missing:
@rem the build still works when packages\ has already been restored,
@rem for example by opening the solution in Visual Studio.
@rem --------------------------------------------------
if not defined NUGET_EXE (
  echo [WARNING] nuget.exe was not found. packages.config is not restored.
  echo           The build below works only when packages\ is already
  echo           in place. Restore nuget.exe next to this batch file,
  echo           or put it on PATH.
  pause
)

rem --------------------------------------------------
rem Batch build of CommandLineTools.
rem --------------------------------------------------
if defined NUGET_EXE %NUGET_EXE% restore "CommandLineTools\CommandLineTools.sln" %NUGET_MSBUILD%
%BUILDFILEPATH% %COMMANDLINE% "CommandLineTools\CommandLineTools.sln"

pause

rem --------------------------------------------------
rem Batch build of MultiPurposeAuthSite.
rem
rem Restore twice, then build.
rem - nuget.exe restore  : packages.config of the web app
rem - MSBuild -t:Restore : PackageReference of CommonLibrary
rem                        (NetFxLibrary.csproj)
rem
rem NOTE: the build line used to carry /t:Restore, so this solution was
rem       only restored and never built.
rem --------------------------------------------------
if defined NUGET_EXE %NUGET_EXE% restore "MultiPurposeAuthSite\MultiPurposeAuthSite.sln" %NUGET_MSBUILD%
%BUILDFILEPATH% %COMMANDLINE% /t:Restore "MultiPurposeAuthSite\MultiPurposeAuthSite.sln"
%BUILDFILEPATH% %COMMANDLINE% "MultiPurposeAuthSite\MultiPurposeAuthSite.sln"

pause

rem -------------------------------------------------------
endlocal
