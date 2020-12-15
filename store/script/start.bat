rem MySQL
net start "MySQL80"

rem postgresql
net start "postgresql-x64-12"

rem MSSQL
net start "MSSQL$SQLEXPRESS"
net start "SQLTELEMETRY$SQLEXPRESS"
net start "SQLWriter"

rem Oracle
net start "OracleOraDB18Home1TNSListener"
net start "OracleServiceXE"
