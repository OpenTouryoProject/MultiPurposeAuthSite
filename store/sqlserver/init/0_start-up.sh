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

# **キャッシュ（バッファプール）に上限を付ける。**
#   **イメージ本来の既定は上限なし**で、**VM のメモリに比例して大きく使う**。
#   **3 つの DB の中で、ここが一番効く**（LocalServicesOnDocker の CHEATSHEET と同じ方針）。
#
#   **起動の度に設定する。** データベースの設定なので、コンテナを作り直しても消えないが、
#   **compose の値を変えたときに追随させる**ため、毎回入れている。
#
#   **128 未満は設定できない**（SQL Server の制限）。小さすぎる値は 128 に丸める。
#   **バッファプール等の上限**なので、プロセス全体はこれより大きくなる。
if [ -n "$SQLSERVER_BUFFER_POOL_MB" ]; then

  if [ "$SQLSERVER_BUFFER_POOL_MB" -lt 128 ]; then
    echo "SQLSERVER_BUFFER_POOL_MB=$SQLSERVER_BUFFER_POOL_MB is too small. using 128."
    SQLSERVER_BUFFER_POOL_MB=128
  fi

  echo "setting 'max server memory (MB)' to $SQLSERVER_BUFFER_POOL_MB ..."

  "$SQLCMD" -S localhost -U SA -P "$MSSQL_SA_PASSWORD" -C -Q \
    "EXEC sp_configure 'show advanced options', 1; RECONFIGURE; \
     EXEC sp_configure 'max server memory (MB)', $SQLSERVER_BUFFER_POOL_MB; RECONFIGURE;"
fi

echo "importing data ..."

for filepath in /init/*.sql
do
  echo "import: $filepath"
  "$SQLCMD" -S localhost -U SA -P "$MSSQL_SA_PASSWORD" -C -i "$filepath"
done

echo "done."
