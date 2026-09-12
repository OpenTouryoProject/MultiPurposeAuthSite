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
@rem
@rem These stay off here. ..\1_BuildAll.ps1 controls them instead:
@rem it runs the InTimeOfDev one when OpenTouryoAssemblies is missing
@rem (-Libs Auto, the default), never with -Libs None, and always with
@rem -Libs Force. Enabling a line here as well would fetch twice.
@rem
@rem Enable one of these only when building by double-click, without
@rem the wrapper.
@rem --------------------------------------------------
rem echo | call 3_BuildLibsAtOtherRepos.bat
rem echo | call 3_BuildLibsAtOtherReposInTimeOfDev.bat

@echo on
timeout 5

echo | call 10_MultiPurposeAuthSite.bat
echo | call 10_MultiPurposeAuthSiteCore.bat

@echo on
timeout 5
