# container/Store（E2E 用の UserStore）

E2E テスト用の UserStore（SQL Server / Oracle / PostgreSQL）を Docker で起動する。
定義は [`docker-compose.yml`](docker-compose.yml)。**E2E 専用**で、手動確認は LocalServicesOnDocker を使う。
そのため**ポートを +1 にしてある**（同時に起動できるように）。

## 接続文字列

**E2E へは、設定ファイルではなく環境変数で渡す**（[`root/TESTING.md`](../../root/TESTING.md) 1 節「ストアを切り替える」）。
値は `docker-compose.yml` の環境変数と一致する（**E2E 用の使い捨ての資格情報**）。

| `-UserStoreType` | サービス | ポート（ホスト → コンテナ） | 環境変数 | 設定のキー |
|---|---|---|---|---|
| `sql` | `sqlserver` | 1434 → 1433 | `MPAS_CONNSTR_SQL` | `ConnectionString_SQL` |
| `ora` | `oracle` | 1522 → 1521 | `MPAS_CONNSTR_ODP` | `ConnectionString_ODP` |
| `npg` | `postgres` | 5433 → 5432 | `MPAS_CONNSTR_NPS` | `ConnectionString_NPS` |

```powershell
# SQL Server（sa / DB: UserStore）
$env:MPAS_CONNSTR_SQL = 'Data Source=localhost,1434;Initial Catalog=UserStore;User ID=sa;Password=seigi@123;Encrypt=false;'

# Oracle（SCOTT / PDB: FREEPDB1）
$env:MPAS_CONNSTR_ODP = 'User Id=SCOTT;Password=tiger;Data Source=localhost:1522/FREEPDB1;'

# PostgreSQL（postgres / DB: UserStore）
$env:MPAS_CONNSTR_NPS = 'HOST=localhost;PORT=5433;DATABASE=UserStore;USER ID=postgres;PASSWORD=seigi@123;'
```

- 資格情報の出どころ：SQL Server の `sa` と PostgreSQL の `postgres` は `seigi@123`、Oracle は `APP_USER=SCOTT` / `tiger`
- コミット済みの設定ファイル（`appsettings.json`・`Web.config`）の `ConnectionString_*` は**ポートを書いていない**ので既定ポートを指し、
  LocalServicesOnDocker（手動確認）を向く。**このコンテナへ向けるには、上の環境変数で上書きする**
- Oracle の PDB は `FREEPDB1`（`XEPDB1` ではない）。初回起動は数分かかる

## 起動と停止

**メモリの節約のため、サービスには profiles が付いており、`docker compose up -d` では何も起動しない。**
使う 1 つだけを、名前を指定して起動する（**同時に 2 つ以上を起動しない**）。

```powershell
docker compose up -d sqlserver   # sql で回すとき
docker compose up -d oracle      # ora で回すとき
docker compose up -d postgres    # npg で回すとき

docker compose stop <サービス名> # 使い終わったら止める
```

DDL は `0_CopyInitSql.ps1` が repo から流し込む（`1_DockerComposeUp.bat` が先に呼ぶ）。
データを残さず作り直すなら `2_DockerComposeDown.bat`（`down -v`）。
