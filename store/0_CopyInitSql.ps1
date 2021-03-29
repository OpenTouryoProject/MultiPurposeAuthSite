####################################################################################################
# pstgrs
####################################################################################################
echo "pstgrs"
echo "copy"
copy "..\root\files\resource\MultiPurposeAuthSite\Sql\pstgrs\Create_UserStore.sql" "postgres\init\1_Create_UserStore.sql"
pause

echo "cd"
push-location "postgres\init"
pause

echo "convert CRLF to LF"
ls -filter *.sql | foreach{ (cat -encoding UTF8  $_ ) -join "`n" | set-content -encoding UTF8 $_ }
pause

pop-location

####################################################################################################
# sqlserver
####################################################################################################
echo "sqlserver"
echo "copy"
copy "..\root\files\resource\MultiPurposeAuthSite\Sql\sqlserver\Create_UserStore.sql" "sqlserver\init\1_Create_UserStore.sql"
pause

echo "cd"
push-location "sqlserver\init"
pause

echo "convert CRLF to LF"
ls -filter *.sql | foreach{ (cat -encoding UTF8  $_ ) -join "`n" | set-content -encoding UTF8 $_ }
pause

pop-location

####################################################################################################
# function
####################################################################################################
function Pause
{
    if ($psISE) {
        $null = Read-Host 'Press Enter Key...'
    }
    else {
        Write-Host "Press Any Key..."
        (Get-Host).UI.RawUI.ReadKey("NoEcho,IncludeKeyDown") | Out-Null
    }
}