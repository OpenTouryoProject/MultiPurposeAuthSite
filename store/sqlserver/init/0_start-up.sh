#!/bin/bash
# **固定の sleep では足りなかった**（#250 の段階 1）。
#   SQL Server 2022 のイメージは、20 秒ではログインを受け付けない。
#   **1 回きりの for ループだったため、DDL が流れないまま終わっていた**（実測）。
#   **開くまで待つ**形に直した。
#
# **mssql-tools18 へ移った**（2022 のイメージ）。
#   以前は /opt/mssql-tools/bin/sqlcmd を叩いていたが、そのパスは無い。
#   18 系は既定で暗号化を要求するので、自己署名を通すため -C を付ける。

SQLCMD=/opt/mssql-tools18/bin/sqlcmd
DEADLINE=$((SECONDS + 300))

echo "waiting for SQL Server to accept logins ..."

until "$SQLCMD" -S localhost -U SA -P "$MSSQL_SA_PASSWORD" -C -Q "SELECT 1" > /dev/null 2>&1
do
  if [ $SECONDS -ge $DEADLINE ]; then
    echo "SQL Server did not accept logins within the deadline."
    exit 1
  fi
  sleep 5
done

echo "importing data ..."

for filepath in /init/*.sql
do
  echo "import: $filepath"
  "$SQLCMD" -S localhost -U SA -P "$MSSQL_SA_PASSWORD" -C -i "$filepath"
done

echo "done."
