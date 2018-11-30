@rem --------------------------------------------------
set CURRENT_DIR="%~dp0"

@rem --------------------------------------------------
@rem Execution of the common processing.
@rem --------------------------------------------------
call %CURRENT_DIR%z_Common2.bat

@rem --------------------------------------------------
@rem Open the CommonLibraries.
@rem --------------------------------------------------
start %BUILDFILEPATH4.7% "CommonLibrary\NetStdLibrary\NetStdLibrary.sln"
start %BUILDFILEPATH4.7% "CommonLibrary\IndividualLibrary\NetFxLibrary\NetFxLibrary.sln"
start %BUILDFILEPATH4.7% "CommonLibrary\IndividualLibrary\NetCoreLibrary\NetCoreLibrary.sln"

@rem --------------------------------------------------
@rem Open the MultiPurposeAuthSites.
@rem --------------------------------------------------
start %BUILDFILEPATH4.6% "MultiPurposeAuthSite\MultiPurposeAuthSite.sln"
start %BUILDFILEPATH4.7% "MultiPurposeAuthSiteCore\MultiPurposeAuthSiteCore.sln"

pause
