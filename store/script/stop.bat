rem MySQL
net stop "MySQL80"

rem postgresql
net stop "postgresql-x64-12"

rem MSSQL
net stop "SQLWriter"
net stop "SQLTELEMETRY$SQLEXPRESS"
net stop "MSSQL$SQLEXPRESS"

rem Oracle
net start "OracleServiceXE"
net start "OracleOraDB18Home1TNSListener"