echo | call 1_DeleteDir.bat
echo | call 1_DeleteFile.bat

@echo on
timeout 5

rem echo | 3_BuildLibsAtOtherRepos.bat
rem echo | 3_BuildLibsAtOtherReposInTimeOfDev.bat

@echo on
timeout 5

echo | 10_MultiPurposeAuthSite.bat
echo | 10_MultiPurposeAuthSiteCore.bat

@echo on
timeout 5
