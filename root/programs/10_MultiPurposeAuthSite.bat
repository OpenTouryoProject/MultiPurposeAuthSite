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
rem Batch build of MultiPurposeAuthSite.
rem --------------------------------------------------
nuget.exe restore "MultiPurposeAuthSite\MultiPurposeAuthSiteAll.sln"
%BUILDFILEPATH% %COMMANDLINE% "MultiPurposeAuthSite\MultiPurposeAuthSiteAll.sln"

pause

rem -------------------------------------------------------
endlocal
