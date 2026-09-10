@echo on
timeout 5

@rem --------------------------------------------------
@rem Clean up.
@rem NOTE: the delete-file batch was named "1_..." here, which does not
@rem       exist in this repository - the file is 2_DeleteFile.bat, so
@rem       the step was silently skipped. The OpenTouryo repository does
@rem       number both as 1_, hence the mistake.
@rem --------------------------------------------------
echo | call 1_DeleteDir.bat
echo | call 2_DeleteFile.bat

@echo on
timeout 5

@rem --------------------------------------------------
@rem The OpenTouryo assemblies this repository builds against.
@rem Enable one of these when they need to be rebuilt.
@rem --------------------------------------------------
rem echo | call 3_BuildLibsAtOtherRepos.bat
rem echo | call 3_BuildLibsAtOtherReposInTimeOfDev.bat

@echo on
timeout 5

echo | call 10_MultiPurposeAuthSite.bat
echo | call 10_MultiPurposeAuthSiteCore.bat

@echo on
timeout 5
