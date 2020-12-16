#!/bin/bash
wait_time=15s

# wait for SQL Server to come up
echo importing data will start in $wait_time ...
sleep $wait_time
echo importing data...

# echo $MSSQL_SA_PASSWORD

for filepath in "/init/*.sql"
do
  echo "import: " $filepath
  /opt/mssql-tools/bin/sqlcmd -S localhost -U SA -P "$MSSQL_SA_PASSWORD" -i $filepath
done
