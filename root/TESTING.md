# TESTING.md — E2E テストの実行と判定

対象: `root/programs/Tests`
配置: `root`

本書は、**どう実行し、どう合否を判定するか**を扱う。
テストそのものの設計方針と個々のテストの説明は
[`programs/Tests/README.md`](programs/Tests/README.md) が一次情報。

> **一次情報は本書ではない。** 迷ったら次を見ること。
>
> | 内容 | 一次情報 |
> |---|---|
> | **各テストが何を確かめるのか** | [`programs/Tests/TESTCASES.md`](programs/Tests/TESTCASES.md) |
> | テストの方針・構成・未修正項目 | [`programs/Tests/README.md`](programs/Tests/README.md) |
> | 適合上の穴の一覧 | [`programs/ANALYSIS-IdP.md`](programs/ANALYSIS-IdP.md) |
> | ビルド | [`BUILDING.md`](BUILDING.md) |
> | 設定と起動 URL | [`CONFIGURATION.md`](CONFIGURATION.md) |

---

## 1. 使い方

```powershell
cd root
.\2_RunAllTests.ps1 -Launch     # 2 つのサイトを起動 → テスト → 停止
.\2_RunAllTests.ps1             # 起動済みのサイトを叩く
.\2_RunAllTests.ps1 -Launch -Filter "FullyQualifiedName~RequestObjectTests"
```

1 件だけ試すときは、下の層を直接叩いてもよい。

```powershell
cd root\programs\Tests
.\test.ps1 -Launch -Filter "FullyQualifiedName~Issue186"
```

| 引数 | 意味 |
|---|---|
| `-Launch` | **net10.0 版と net48 版の両方**を起動してからテストし、終わったら停止する |
| `-Url` | net10.0 版（Kestrel）の待ち受け URL。既定 `https://localhost:44300` |
| `-NetFxUrl` | net48 版（IIS Express）の待ち受け URL。既定 `https://localhost:44302` |
| `-NoNetFx` | net48 版を起動しない。その分は Skip される |
| `-NoWebUI` | **ブラウザで測るもの**（`UI-n.n`）を走らせない。**既定は走る**（ブラウザが無ければ Skip） |
| `-Filter` | `dotnet test` の `--filter` |
| `-Configuration` | `Debug`（既定）/ `Release` |
| `-OutputDir` | TRX とログの保存先。既定は `programs\Tests\E2ETests\Result`（`.gitignore` 済み） |
| `-UpdateTestCases` | テストケースの原本（`programs\Tests\TESTCASES.md`）を作り直す |
| `-UserStoreType` | サイトが使うストア（`mem` 既定 / `sql` / `ora` / `npg`）。**`mem` 以外は下の「ストアを切り替える」を読む**（#207） |
| `-ConnectionString` | `mem` 以外のときの接続文字列。省略時は環境変数から読む |

### ストアを切り替える（#207）

**既定は `mem`。** これは変えない。`sql` / `ora` / `npg` は、対応する DBMS が
動いていることが前提になるため、既定にすると DBMS の無い環境でテストが回らなくなる。

> **`SessionStoreType`（#256）も、同じ理由で `mem` が既定である。**
> `redis` / `sql` を既定にすると、**Redis や SQL Server の無い環境でテストが回らなくなる。**
> **E2E はサイトを 1 インスタンスずつしか立てない**ので、共有する必要がない
> （**実測でも、置き場を変えても結果は変わらない**。下の「セッションの置き場も」）。
> **キーが無ければ `mem`** なので、書かない配備もそのまま回る。
> net48 版は `Web.config` の `sessionState` で選ぶので、この設定は読まない。

```powershell
# 接続文字列は環境変数で渡す（キー名ではなく、専用の名前を使う）
$env:MPAS_CONNSTR_SQL = '...'
.\2_RunAllTests.ps1 -Launch -UserStoreType sql
```

#### E2E 用の DBMS は `store/` で立てる（#250 の段階 1）

**このリポジトリの `store/` が、3 方言を定義している**（SQL Server / Oracle / PostgreSQL）。

```powershell
cd store
.\1_DockerComposeUp.bat      # DDL を流し込んでから、IdP のコンテナだけを起動する
.\2_DockerComposeDown.bat    # -v 付き。作り直せるように残さない
```

**DB は `1_DockerComposeUp.bat` では起動しない。**
**`2_RunAllTests.ps1` が、使う 1 つだけを、その実行の間だけ起動する。**

```powershell
$env:MPAS_CONNSTR_SQL = 'Data Source=localhost,1434;...'
.\2_RunAllTests.ps1 -Launch -UserStoreType sql    # 起動 → 待機 → テスト → 停止
```

| | |
|---|---|
| **対象の決め方** | **接続文字列から読めたポートが `store/` のもの（1434 / 1522 / 5433）なら、その DB を扱う** |
| **触らないとき** | **ポートが読めない**（＝ 既定ポート。手動確認の LocalServicesOnDocker）**や、別の番号のとき** |
| **停めるのは自分が起動したときだけ** | **先に人が起動していた DB は、そのまま残す** |
| **切る口** | **`-NoStoreContainer`**（別ホストの DB を指すときなど） |

> **1 回に 1 ストアである**（`-UserStoreType` は単数）。
> **複数のストアを回したいときは、呼ぶ側でループする** —
> **`test.ps1` が自己完結しているので、ループすれば DB 毎に起動・停止になる。**
>
> ```powershell
> foreach ($st in @('sql','ora','npg')) {
>     .\2_RunAllTests.ps1 -Launch -UserStoreType $st -Filter "..."
> }
> ```

> **実測 2026/10/17**（全コンテナ停止の状態から、`-Filter "FullyQualifiedName~AuthFailureLockoutTests"` を 3 方言とも）。
>
> | ストア | 結果 | コンテナ |
> |---|---|---|
> | `sql` | **8 件 / 成功 7 / 失敗 0 / Skip 1**（`RT-305.7` の netfx） | 起動 → 停止 |
> | `ora` | **8 件 / 成功 7 / 失敗 0 / Skip 1** | 起動 → 停止 |
> | `npg` | **8 件 / 成功 4 / 失敗 0 / Skip 4**（netfx は起動しない） | 起動 → 停止 |
>
> **前後とも「起動中なし」を確認している。**
> **先に人が起動していた場合に止めないことも、別に測った。**

> **net48 を測るときは `aspnet_state` を忘れない**（下の「前提」の節）。
> **止まっていると netfx の全要求が HTTP 500 になり、ストアの問題に見える** — **実測で踏んだ。**

**手で起動したいときは、名前を指定する。**

```powershell
docker compose up -d sqlserver     # sql で回すとき（1434）
docker compose up -d oracle        # ora で回すとき（1522）
docker compose up -d postgres      # npg で回すとき（5433）

docker compose stop sqlserver      # 使い終わったら止める
```

> **`sqlserver` は、起動の度に `UserStore` を作り直す。**
> **`init/1_Create_UserStore.sql` の先頭が `DROP DATABASE` ＋ `CREATE DATABASE`** で、
> **`init/0_start-up.sh` はコンテナ起動の度に走る**ためである。
> **前回のデータは残らない**（E2E はサイトが初回のサインインで種データを作るので、これで良い）。
> **`oracle` と `postgres` は、再起動では流れない**
> （`oracle` は初回作成時だけ、`postgres` はデータが空のときだけ）。
>
> **このため、`sqlserver` の待機は「ポートが開いた」では足りない** —
> **DDL が流れ終わるまで待つ**（`0_start-up.sh` が `done.` を出す）。
> **その際、ログは「起動した時刻から後」だけを見る**（`--since`）—
> **`docker compose logs` は再起動をまたいで残る**ので、
> **全部を見ると前回の `done.` で通ってしまう**（実測で踏んだ）。

> **同時に 2 つ以上を起動しないこと。** **E2E は 1 回に 1 つのストアしか使わない。**
> **3 つ同時に起動すると、Docker の VM がメモリを使い切って Windows ごと固まることがある**
> （方針は LocalServicesOnDocker の `CHEATSHEET.md` に倣った）。

**メモリの抑え方**（`store/docker-compose.yml` の頭に同じ表が在る）。

| サービス | パラメタ | 既定 | 変える変数 |
|---|---|---|---|
| `sqlserver` | `max server memory (MB)`（`sqlserver/init/0_start-up.sh` が起動の度に設定） | **300** | `SQLSERVER_BUFFER_POOL_MB` |
| `postgres` | `shared_buffers`（起動オプション `-c`） | **128** | `POSTGRES_BUFFER_POOL_MB` |
| `oracle` | **変更しない** | — | — |

> **効くのは `sqlserver`** — **イメージ本来の既定は上限なし**で、**VM のメモリに比例して大きく使う。**
> **128 未満は設定できない**（SQL Server の制限）。
> **バッファプール等の上限**なので、**プロセス全体はこれより大きくなる。**
>
> **実測 2026/10/17**（コンテナ 1 つだけを起動して `docker stats`）。
>
> | | 設定 | 実使用 |
> |---|---|---|
> | `sqlserver` | 300 MB | **766.6 MiB** |
> | `postgres` | 128 MB | **46.1 MiB** |
> | `oracle` | 変更しない（SGA 1536M / PGA 512M） | **2.342 GiB** |
>
> **`oracle` が圧倒的に重い。** **これ 1 つで、他の 2 つの合計の 3 倍近く使う** —
> **「使わない間は止める」が、ここでは一番効く。**

> **Oracle の SGA は小さくしない。** **小さくしすぎると DB が起動しなくなる。**
> **23ai Free は製品の制限で SGA ＋ PGA が 2GB まで**
> （**実測** : `sga_target` **1536M** ＋ `pga_aggregate_target` **512M** = ちょうど 2GB）。
> **メモリを空けたいときは、使わない間は止めること。**

> **`restart` は、`store/` のすべてのサービスで `"no"` にしてある**
> （DB の 3 つと IdP の 3 つ。**以前は `always`**）。
> **Docker エンジンを起動した拍子に、6 つとも一斉に復帰してメモリを食い切るのを防ぐ**
> （**実測で踏んだ** : Docker を起動しただけで 6 つとも起きていた）。
> **起動は、いつでも明示的に行う**（`up -d` / `start`）。
>
> **以前の `always` で作られたコンテナは、古い設定のままである。**
> **`down` で消す**か、**`docker update --restart=no <コンテナ名>` で変える。**
> **`update` ならデータを壊さない** — **Oracle は `down` で消すと、次の起動で再作成に数分かかる。**

> **`2_DockerComposeDown.bat` は profiles を 3 つとも並べている。**
> **並べないと DB が `down` の対象から外れ、コンテナが残る**（実測で確かめた）。**`--remove-orphans` では消えない。**

**ポートは +1 にしてある。**

| | `store/`（E2E） | 既定のポート |
|---|---|---|
| SQL Server | **1434** | 1433 |
| Oracle | **1522** | 1521 |
| PostgreSQL | **5433** | 5432 |

> **なぜ +1 か。** **手動確認は
> [LocalServicesOnDocker](https://github.com/NetDevInfraWGinOSSConsortium/LocalServicesOnDocker)
> を使い続ける**（RP アプリなどもそちらに繋ぐ）。
> **既定ポートを空けておくことで、E2E 用と同時に起動できる。**
>
> **コミット済みの `ConnectionString_*` はポートを書いていない**ので、
> **既定ポート ＝ LocalServicesOnDocker** を指す。**手動確認はそのまま。**

**E2E に渡す接続文字列。**

```powershell
$env:MPAS_CONNSTR_SQL = 'Data Source=localhost,1434;Initial Catalog=UserStore;User ID=sa;Password=<pw>;Encrypt=false;'
$env:MPAS_CONNSTR_ODP = 'User Id=SCOTT;Password=<pw>;Data Source=localhost:1522/FREEPDB1;'
$env:MPAS_CONNSTR_NPS = 'HOST=localhost;PORT=5433;DATABASE=UserStore;USER ID=postgres;PASSWORD=<pw>;'
```

- **DDL は `0_CopyInitSql.ps1` が repo から流し込む**（`1_DockerComposeUp.bat` が先に呼ぶ）。
  コピー先は**生成物**で `.gitignore` 済み。**原本は `root/files/resource/.../Sql/` だけ**
- **`store/` の DB は使い捨てにできる。** そのため、下の
  「古いデータベースを使い回すと、列が足りない」は **E2E 側では起きない**
  （手動側＝LocalServicesOnDocker では引き続き起こりうる）
- **Oracle の初回起動は数分かかる**（`docker compose ps` が healthy になるまで待つ）

| ストア | 接続文字列の環境変数 | 上書きされる設定キー |
|---|---|---|
| `sql` | `MPAS_CONNSTR_SQL` | `ConnectionString_SQL` |
| `ora` | `MPAS_CONNSTR_ODP` | `ConnectionString_ODP` |
| `npg` | `MPAS_CONNSTR_NPS` | `ConnectionString_NPS` |

**スクリプトに接続文字列の既定値は持たせていない。** 持たせると、それが事実上の資格情報になる。
渡していなければ、その場で止まる（どの環境変数を設定すればよいかを表示する）。

**DBMS は [LocalServicesOnDocker](https://github.com/NetDevInfraWGinOSSConsortium/LocalServicesOnDocker) で、まとめてコンテナとして起動できる**
（SQL Server / Oracle / PostgreSQL。#208 の実測はこれで行った）。
Oracle は `gvenzl/oracle-free:23-slim` で、接続先の PDB は **`FREEPDB1`**（`XEPDB1` ではない）。

切り替える前に、対象の DBMS で次が済んでいること。

1. 空のデータベース（スキーマ）を作る
2. `files/resource/MultiPurposeAuthSite/Sql/<dbms>/Create_UserStore.sql` を流す

**ロール・管理者・テスト ユーザは、サイトが初回の `/Account/Login` で作る**
（`CreateData` が `Roles` の件数で初期化済みかを判定する）。手で入れる必要はない。

> **net48 版は `npg` を選べない。** `Npgsql` の参照が `#if NETCORE` で囲まれているため、
> `-UserStoreType npg` のときは net48 版を起動しない（その分は Skip）。

> **`mem` と違い、net48 版と net10.0 版が同じデータベースを共有する。**
> `mem` は各サイトが別の入れ物なので、**ストアを変えると初めて出る失敗がある。**
>
> **実測（#242 の作業。`sql`）** : 通しで `RT-230.1`（core）が 1 件落ちた
> （`UnstructuredData` に書いた値が `/userinfo` に出ない）。
> **`UserClaimsTests` だけを回すと 8/8 通る**ので、通し実行のときだけ起きる。
> **原因は未特定。** 「両ターゲットの取り合い」は確かめたが**説明になっていない**
> （この値を書くのは `UserClaimsTests` だけで、同じクラスのケースは並列に走らない。
> 利用者の行が重複しているわけでもない）。**落ちたら、まず 1 クラスだけで回して切り分ける。**
>
> **実測（#250 の段階 1。`store/` の 3 方言）** : 同じ型が**別のテストでも出た。**
>
> | ストア | 落ちたもの | 1 クラスだけで回すと |
> |---|---|---|
> | `sql` | `RT-233.2`（core） | **22/22 通る** |
> | `ora` | `RT-230.3`（core） | **8/8 通る** |
> | `npg` | 無し（210 成功 / 失敗 0） | － |
>
> **分かっていること。** **core だけ／DB ストアのときだけ／通しのときだけ／毎回 1 件だけ。**
> **落ちるテストは毎回違う**（`RT-230.1` / `RT-230.3` / `RT-233.2`）。
> **`mem` では出ない**（各サイトが別の入れ物のため）。**原因は依然として未特定。**

#### 上流の IdP も `store/` で立てる（#250 の段階 2〜3）

**ハイブリッド ID フェデレーションの「上流側」を、コンテナで 1 つ建てる。**
**下流（連携する側）はホストで動かす**（Visual Studio / `test.ps1 -Launch`）。

```powershell
cd store
.\3_PublishUpstream.ps1      # publish と証明書（1_DockerComposeUp.bat が先に呼ぶ）
docker compose up -d upstream
```

| | 値 | なぜ |
|---|---|---|
| URL | **`https://localhost:44301`** | 雛形が上流として書いている番号 |
| パス | **root**（`/authorize`） | `UsePathBase` を呼んでいない |
| ストア | **`mem`（固定）** | 雛形のテスト利用者が自動で作られる。上流に DB は要らない。**下流は `-UserStoreType` で切り替わるが、上流は常に `mem`**（つまり **`sql` で回すとクロス ストアになる**。5 節の対応表） |
| 証明書 | **ホストの `dotnet dev-certs`** を書き出したもの | 既に信頼済み。**ブラウザが警告を出さない** |
| ログ | `store/logs/`（`ACCESS` / `OPERATION` / `SQLTRACE`） | **ホストから読める** |

**net48 版はコンテナ化しない。** 上流は 1 つあればよく、**net10.0 版で足りる**。

> **パスの形が VS と違う。** 雛形の `IdFederation{Authorize,Token,UserInfo}Endpoint` は
> **`https://localhost:44301/MultiPurposeAuthSite/...`** を指している。これは
> **IIS Express の仮想ディレクトリ**の形で、**Kestrel（コンテナ）は root で配信する。**
> **下流はこの 3 つを `/MultiPurposeAuthSite` 抜きに向ける必要がある**
> （E2E は `appSettings__...` の環境変数で渡せる。4 節と同じ形）。
>
> **`UsePathBase` を足して VS に合わせることはしなかった。**
> E2E の net10.0 版（`https://localhost:44300`）も**既に root で配信している**ので、
> **root がこのアプリの Kestrel での通常の形である。**

**どの口も、ポートで分けている。**
**仮想パスを VS と同じにできない**（コンテナは root 配信）ため、
**パスでは分けられないからである。**

| ポート | 何 |
|---|---|
| **44300** | 下流（net10.0）。VS / `test.ps1 -Launch` の Kestrel |
| **44301** | **上流コンテナ**（雛形が上流として書いている番号） |
| **44302** | 下流（net48）。IIS Express |
| **44303** | **下流コンテナ用に空けてある**（#281） |
| **44304** | **2 つ目の上流コンテナ**（#292 の段階 1。**上流が n 件になったことを測る**） |
| **44305** | **相手（RP）の `jwks_uri` を配るだけのコンテナ**（#309 の段階 1。**平文の http**） |

> **ポートを分けても Cookie は分かれない。**
> **Cookie のスコープにポートは入らない**（RFC 6265 §8.5）ので、
> **名前で分ける**（`CookieNamePrefix` / `AuthCookieName` / `sessionState:SessionCookieName`）。
> **パスが違っても解決しない**のも同じ理由である（#250 の段階 4 で実測）。
>
> **44300〜44399 は IIS Express の開発用証明書が http.sys に登録済み**なので、
> この範囲を使っている（5 節「net48 版も同時に測る」）。

**リソースはイメージに入れず、ホストの `C:\root\files\resource` をマウントする**（読み取り専用）。
**署名鍵（`X509` の pfx、`JwkSet.json`）を含む**ため、イメージに焼くべきではない。
中身は [`Readme.ja.md`](Readme.ja.md) の手順で用意されているものを、そのまま使う。

> **雛形の設定は 19 箇所が `C:/root/files/resource/...` である**
> （Windows 前提。**実測 2026/10/08**。以前の記述は 15 で、古くなっていた）。
> **Linux ではドライブ文字が効かない**ので、`docker-compose.yml` が
> **19 個すべてをマウント先（`/resource`）に振り替えている。**
> **1 つでも漏らすと、その設定を使った瞬間に落ちる**ので、
> `appsettings.json` を `"C:/root/files` で grep した数と突き合わせること。
>
> **`log4net` だけは中身（出力先）も Windows のパス**なので、
> **差し替えた構成**（`store/app/LogConf.xml`）をイメージに入れてある。

#### 接頭辞を付けた配備を測る（#282 / #283）

**`CookieNamePrefix` を使っている配備の Cookie 名は、通しでは現れない**
（E2E のサイトは接頭辞を使わない）。**環境変数で渡して測る。**

```powershell
# **FxContainerization=ON なので、環境変数が設定キーを上書きする**（2 節）
$env:CookieNamePrefix = 'probe_'
.\2_RunAllTests.ps1 -Launch -Filter "FullyQualifiedName~CookiePolicyTests"
```

**起動している間に `Set-Cookie` を見る**（別のプロセスから叩く）。
**実測（2026/10/08。`AuthCookieName` は空。サインイン後）。**

```
.probe_AspNetCore.Identity.Application          認証（枠組みの既定名 ＋ 接頭辞。#283）
.probe_AspNetCore.Antiforgery.…                AntiForgery（#282）
.probe_AspNetCore.Mvc.CookieTempDataProvider    TempData
probe_MultiPurposeAuthSiteCoreSession           セッション
probe_auth_time                                 max_age の判定
```

| 測ること | 期待 |
|---|---|
| `CookieNamePrefix` だけ | **500 にならず、認証 Cookie が `.probe_AspNetCore.Identity.Application`**（#283 より前は **500**） |
| `CookieNamePrefix` ＋ `AuthCookieName` | **`.probe_MultiPurposeAuthSite`**（従来どおり。コンテナの上流・下流はこれ） |
| `CookieNamePrefix` なし | **枠組みの既定のまま**（通しがこれ） |
| net48 版 | **`probe___RequestVerificationToken`**（既定名の先頭に `.` が無いので前に付く） |

> **通しに入れていない。**
> **接頭辞を使う配備を立てるには、サイトの起動条件を変える必要があり**、
> **`test.ps1` はサイトを 1 組しか立てない**ためである。
> **上の手順が、その代わりである。**

#### 下流もコンテナで建てる（#281）

**上流と同じイメージを、別の設定で建てる。**
**これでコンテナ 2 つだけでハイブリッド IdP 構成が取れる。**

```powershell
cd store
.\1_DockerComposeUp.bat    # DB 3 つ ＋ 上流 ＋ 下流をまとめて起動する
```

**上流だけ・下流だけを建て直すなら、サービスを名指す。**

```powershell
.\3_PublishUpstream.ps1          # 成果物は 1 つ。上流も下流も同じイメージ
docker compose up -d --build upstream downstream
```

> **#284 で、既定で起動するようにした**（profile を外した）。
> **`CN-*` がこの 2 つを測る**ので、起動していないとほぼ常に Skip になる —
> **「成功 0 件を NG にしている」のと同じ理屈で、測られないテストは危ない。**

| | 値 | なぜ |
|---|---|---|
| URL | **`https://localhost:44303`** | **口はポートで分ける**（上のポートの表） |
| `IssuerId` | **`https://downstream.ssoauth.opentouryo.com`** | **2 つの IdP が同じ `iss` を名乗らない**ようにする |
| `SpRp_Isser` | **上流の `IssuerId`**（据え置き） | **こちらは「上流に期待する `iss`」**で、役割が違う |
| `IdFederationAuthorizeEndpoint` | `https://localhost:44301/authorize` | **ブラウザが行く先**なので、ホストから届く URL |
| `IdFederationTokenEndpoint` / `UserInfoEndpoint` | **`http://upstream:8080/...`** | **サーバが呼ぶ先**なので、コンテナから届く宛先 |
| `IdFederationJwkSetUri` / `IdFederationSaml2MetadataUrl` | **`http://upstream:8080/...`**（#293 の段階 3） | **鍵を引くのもサーバである。** **`https://localhost:44301` には届かない** |
| 鍵の置き場 / ログ | `store/keys-downstream` / `store/logs-downstream` | **上流と分ける**（同じ鍵の置き場を共有すると Cookie を相互に復号できる。#279） |

**どのコンテナにも要る設定は `store/mpas-common.env` に 1 か所だけ置いてある**
（リソースのパス 19 件 ＋ log4net）。
**サービスごとに書くと 2 回書くことになり、片方だけ直す事故が起きる。**

> **`env_file` は LF でなければならない**（`.gitattributes` で `*.env text eol=lf` にしてある）。
> **CRLF になると値の末尾に CR が残り**、**そのパスを使った瞬間に落ちる。**

##### user store の秘密を暗号化した状態で測る（`RT-297.*`。#297）

**既定の通しは「暗号化した状態」で回している**（`test.ps1` が `UserStoreSecretPassword` を渡す）。

| | 測ること |
|---|---|
| **`RT-297.1`** | **クライアント登録の `client_secret` が往復する**（発行 → 登録 → 画面を開き直すと同じ値） |
| **`RT-297.2`** | **上流の登録の `client_secret` が往復する**（`/IdFederationAdmin`） |

**どちらも「暗号文がそのまま画面に出ていないこと」も見る。**

**DB に平文が残っていないことは、SELECT して確かめる**（**E2E からは DB を見ない** — 9 節）。

```powershell
# SQL Server（store/ のコンテナ）
docker exec store-sqlserver-1 /opt/mssql-tools18/bin/sqlcmd -S localhost -U sa -P '<pw>' -C -d UserStore `
  -Q "SELECT TOP 4 LEFT(ClientSecret, 24), LEN(ClientSecret) FROM Saml2OAuth2Data WHERE ClientSecret IS NOT NULL"
```

**実測（2026/10/14）** : **`enc:v1:…`（115 文字）**。
**`enc:v1:` で始まらない 4 行は、空文字**（public クライアント。暗号化の対象にならない）。

> **表を足した・列を広げたら、DB を作り直すこと**（上の #292 の段階 2 と同じ）。
> **`ClientSecret` は 512 に広げた**ので、**古い DB では溢れる。**

> **暗号化すると、通しが遅くなる。**
> **実測（2026/10/14。同じ機械で 612 件の通し）。**
>
> | | 時間 |
> |---|---|
> | 暗号化の前 | **137 秒** |
> | 暗号化（鍵のキャッシュ**なし**） | **922 秒**（**6.7 倍**。PBKDF2 10 万回 × 読み出しの回数） |
> | 暗号化（鍵のキャッシュ**あり**） | **196 秒**（**＋43%**。行ごとに 1 回だけ導く） |

##### 鍵の入れ替え（ロールオーバー。`SA-2.2` / `SA-6.6`。#292 の段階 3）

| | 測ること |
|---|---|
| **`SA-2.2`** | **`/samlmetadata` が、退役前の証明書も並べて広告する**（`PreviousSigningCerFilePaths`） |
| **`SA-6.6`** | **上流が 2 本広告していても、SAML2 の ID 連携ができる**（**受け取る側は全部試す**） |

**設定は E2E にも渡してある。**

| | |
|---|---|
| ホスト（core / netfx） | `test.ps1` が `PreviousSigningCerFilePaths` を渡す（**2 本広告する状態**を作る） |
| 上流コンテナ | `store/docker-compose.yml` の `PreviousSigningCerFilePaths`（`*_Server.cer`） |
| 上流コンテナの **JWK Set** | **RSA が 2 本**（`JwkSet_Upstream.json`。**新旧を並べた状態**） |

**歯抜け（実測 2026/10/14）。**

| 壊すもの | 期待する結果 |
|---|---|
| **上流の広告の 1 本目を「署名に使っていない証明書」にする**（`SpRp_RsaCerFilePath` と `PreviousSigningCerFilePaths` を入れ替える） | **`SA-6.*` は 12 / 12 通る**。**下流のログに `The SAML2 response was verified with key #2.`** が出る（**1 本目で失敗し、2 本目で検証した**ことの証拠） |
| 上流の JWK Set を 1 本に戻す | **`RT-140.*` は通る**（`kid` で選ぶので、本数には依らない） |

> **「通った」だけでは、どの鍵で通ったか分からない。**
> **ログの `verified with key #N` を見ること**（**2 本目以降で通ったときだけ出る**）。

##### 上流の登録を DB と管理画面で扱う（`RT-292.*`。#292 の段階 2）

**設定ファイルを書き換えずに上流を増やせること**を測る。

| | 測ること |
|---|---|
| **`RT-292.1`** | **管理画面で、足して・直して・消せる**（`/IdFederationAdmin`） |
| **`RT-292.2`** | **user store に足した上流が、サインイン画面の導線に出る**（**設定の行も残る**） |
| **`RT-292.3`** | **管理者（`SystemAdmin`）でなければ開かない** |
| **`RT-292.4`** | **上流ごとの署名鍵（`.pfx` のパスとパスワード）が往復する**（#292 の段階 4-b。**パスワードは暗号化して保管する**ので、**平文に戻ること**を見る） |

**ストアは 4 通りとも測った**（実測 2026/10/14。`RT-292.4` を足した後）。

| ストア | 結果 |
|---|---|
| `mem`（既定の通し） | **8 / 8**（core / netfx） |
| `sql`（SQL Server） | **10 / 10**（`RT-297.2` を含む） |
| `ora`（Oracle） | **10 / 10** |
| `npg`（PostgreSQL） | **5 / 5**（**netfx は PostgreSQL を使えないので Skip**。従来どおり） |

> **`RT-292.4` が測るのは、入れ物（表・辞書）と画面である。**
> **DB の行の鍵で実際に署名するところまでは測っていない** —
> **配備の `.pfx` のパスワードをテストに持たせない**ためである（9 節）。
> **指定した鍵で署名していることは、`CN-5.5`（設定の行）とその歯抜けで測っている。**

**暗号文で入っていることは、SELECT して確かめた**（実測 2026/10/14。`-UserStoreType sql`）。
**`RT-292.4` は行を消して戻す**ので、**後片付けだけを止めて 1 行残し、見てから消した。**

```powershell
docker exec store-sqlserver-1 /opt/mssql-tools18/bin/sqlcmd -S localhost -U sa -P '<pw>' -C -d UserStore `
  -Q "SELECT LEFT(SigningPfxPassword, 12), LEN(SigningPfxPassword) FROM IdFederationUpstreams"
```

**`enc:v1:…`（115 文字）** — **`SigningPfxFilePath` は平文**（**パスは秘密ではない**）。

**歯抜け（実測 2026/10/14）。**

| 壊すもの | 期待する結果 |
|---|---|
| `IdFederationUpstreamProvider.Unprotect` から **`SigningPfxPassword` の行を外す** | **`RT-292.4` だけが落ちる**（core / netfx とも。**パスワードが平文に戻る / 実測 = 別の値**）。**他の 8 件は通ったまま** |

> **これで「暗号化して保管し、読むときに戻している」ことが測れている** —
> **暗号化していなければ、外しても往復してしまう。**

##### 動的クライアント登録（`RT-307.*`。#307 の段階 1）

| | 測ること |
|---|---|
| **`RT-307.1`** | **`registration_endpoint` で登録でき、返った `client_id` / `client_secret` で実際に認可コードが取れる** |
| **`RT-307.2`** | **トークンが無ければ `401`**／**偽のトークンは `401` ＋ `invalid_token`**／**専用 scope を持たないトークンは `403` ＋ `insufficient_scope`** |
| **`RT-307.3`** | **2 件目以降も登録できる**（**1 利用者 n クライアント**。#307 の段階 5-a）／**別々に使え、別々に消せる** |
| **`RT-307.4`** | **メタデータの誤りは `400`**（`redirect_uris` 無し / フラグメント / 相対 URI / `jwks_uri` / **壊れた `software_statement`** / `response_types` と `grant_types` の不整合 / 専用 scope の自己付与）／**どの誤りでも登録は作られていない** |
| **`RT-307.5`** | **専用トークンは、scope が 1 本に絞られ、有効期限も短い** |
| **`RT-307.6`** | **登録した `response_types` が、認可エンドポイントで効く** |
| **`RT-307.7`** | **登録した `grant_types` が、トークン エンドポイントで効く** |
| **`RT-307.8`** | **登録した `scope` が、DB に登録したクライアントでも効く** |

**使い捨ての利用者を 2 人使う**（`ClientRegistrationTests.WithDcrAsync`）。

| | 役 |
|---|---|
| **A** | **管理 API を叩くクライアントの持ち主。** 画面から、`scope` に専用 scope（`client_registration`）を登録する（ロールは **`Admin`**） |
| **B** | **登録の所有者。** ROPC の `username` / `password` で本人になる（ロールは `User`） |

> **分けないと、A の管理クライアントと B の登録が、同じ利用者に混ざる** —
> **`Helper.GetClientIdByName` と管理画面が返すのは「所有者の先頭 1 件」**なので、
> **どちらを引くかが決まらない。**
>
> **段階 5-a-1 より前は、もっと硬く効いていた** — **B の登録が「2 件目」になって断られた**
> （**1 人 1 件だった**ため）。
>
> **A のクライアントは画面から登録する。** **動的登録では専用 scope を付けられない**
> （`RT-307.4` の (7) が、それを測っている）。

> **`test.ps1 -Launch` が `EnableDynamicClientRegistration=true` で起動する。**
> **雛形の既定は無効**（口そのものを張らない）なので、
> **既に動いているサイトへ向けたときは Skip する**
> （`DynamicClientRegistration.SkipIfNotSupportedAsync` が Discovery の
> `registration_endpoint` の有無で判定する）。
> **ROPC も要る**ので、`Flows.SkipIfGrantTypeNotSupportedAsync(client, "password")` も通す。

**`RT-307.6` は、管理画面で登録したクライアントで測る。**
**`redirect_uri` の照合が先に効く**（#187。誤りを RP へ返せるようにするため）ので、
**`redirect_uri_token` の列が空のクライアントでは `invalid_request` になり、
`response_types` の絞りまで届かない。**
**両方の列を登録し、`response_types` を `code` だけにしたクライアント**（A のもの）**で測る。**

**`RT-307.7` は、A のクライアントの `grant_types` を `password` だけにして測る。**
**認可エンドポイントは `grant_types` を見ない**ので、**認可コードは取れる。**
**その code の交換が `unauthorized_client` になる。**

**歯抜け（実測 2026/10/18）。**

| 壊すもの | 実測 |
|---|---|
| `CmnEndpoints.CheckClientResponseType` を**常に true** にする | **`RT-307.6` だけが落ちる**（core / netfx の 2 件。実測 = `access_denied`。**`unauthorized_client` で止まらなくなり、同意の段まで進む**）。**16 件 / 成功 14 / 失敗 2** |
| `CmnEndpoints.CheckClientGrantType` を**常に true** にする | **`RT-307.7` だけが落ちる**（2 件。実測 = 「`access_token` を**返してしまった**」）。**16 件 / 成功 14 / 失敗 2** |
| `Helper.FilterSupportedScopes` の**クライアントごとの絞りを外す** | **`RT-307.8` だけが落ちる**（2 件。実測 = 「登録に無い `email` が**載った**」）。**16 件 / 成功 14 / 失敗 2** |
| `Helper.GetClientScopes` の **DB 参照を外す**（= 以前の振る舞い） | **10 件が落ちる**（**`RT-307.8` だけではない**）。**専用 scope が出せなくなるので、動的登録そのものが止まる**（`403` / `insufficient_scope`）。**16 件 / 成功 6 / 失敗 10** |

> **最後の 1 行が、この段階でいちばん大事な確認である。**
> **`GetClientScopes` の DB 参照は、「絞りが効くかどうか」だけの話ではない** —
> **専用 scope を「登録に明記したクライアントにだけ出す」仕掛けが、そこに乗っている。**
> **構成ファイルだけを見ていた以前の実装では、DB に登録したクライアントに
> 専用 scope を許すことが、そもそも出来ない。**

> **`Helper.GetClientScopes` の DB 参照を外すと、`RT-198.3` / `RT-198.4` も落ちる**
> （**構成ファイルのクライアントの絞りは残るので、`netfx` 側だけ**。下の「踏んだこと」を参照）。

**実測（2026/10/18）。**

| | 結果 |
|---|---|
| クリーン ビルド | **net48 / net10.0 とも エラー 0 / 警告 0** |
| `RT-307.*`（単独） | **16 件 / 成功 16 / 失敗 0**（8 ケース × core / netfx） |
| `mem`（既定の通し） | **658 件 / 成功 652 / 失敗 0 / Skip 6**（原本 **337 件**。**Skip は従来の 6 件のまま**） |
| `sql`（SQL Server） | **16 件 / 成功 16 / 失敗 0** |
| `ora`（Oracle） | **16 件 / 成功 16 / 失敗 0** |
| `npg`（PostgreSQL） | **16 件 / 成功 8 / 失敗 0 / Skip 8**（netfx は PostgreSQL を使えない。従来どおり） |

> **3 方言は、新しい DDL が流れた状態で測っている**（列を 11 本足した）。
> **`mem` の通しでは `Create_UserStore.sql` が流れない**ので、**列の追加は何も確かめられない。**
> **`oracle` と `postgres` はコンテナを作り直した**（`init` は新しいコンテナでしか流れない）。
> **`docker compose rm` には必ずサービス名を付けること**（#306 で踏んだ）。

> **1 回目の通しで `RT-305.5`（netfx）が 1 件だけ落ちた。**
> **単独では通り、2 回目の通しでは 失敗 0 だった**ので、**間欠である。**
> **`RT-305.5` は「窓の中で 330 回叩き切る」テスト**で、
> **通しの窓は 20 秒**（`RateLimitWindowSeconds`）しかない。
> **通しが重くなると、叩き切る前に窓が変わって回数が 0 に戻る。**
> **RT-307 で netfx 側のケースが 16 件増えた**ので、**踏む確率は上がっている。**

###### 踏んだこと : `test.ps1 -Launch` は net48 版をビルドし直さない

**歯抜けを戻した直後、ビルドせずに通しを回して 3 件落ちた**（実測）。

| 落ちたもの | なぜ |
|---|---|
| `RT-198.3` / `RT-198.4` / `RT-307.8`（**すべて netfx**） | **net48 版が、歯抜けを入れたままのビルドで動いていた** |

**`test.ps1 -Launch` は、net10.0 版だけを `dotnet build` してから起動する。**
**net48 版は、既にビルドされている出力を IIS Express に読ませるだけ**である。

> **`CommonLibrary` を触ったら、`1_BuildAll.ps1` を回してから通すこと。**
> **core だけ直っていて netfx が古い、という状態は、
> 「片方だけ落ちる」という形で現れる**（この実装がいちばん検出したい形と同じ見え方になる）。

##### 管理 API（`RT-307.9` 〜 `.13`。#307 の段階 2）

**登録の応答で返る `registration_client_uri` と `registration_access_token`**（RFC 7592 §3 で、
**どちらも REQUIRED**）**を使って、`GET` / `PUT` / `DELETE` を叩く。**

| | 測ること |
|---|---|
| **`RT-307.9`** | **`GET` で登録の全体が読める**（`client_id` が変わらない・`registration_client_uri` と `registration_access_token` が返る・**`client_secret` は返らない**） |
| **`RT-307.10`** | **`PUT` の全置換が、実際に効く**（**新しい `redirect_uri` で認可コードが取れ、古い方では取れない**・**外した `scope` がトークンに載らない**） |
| **`RT-307.11`** | **`DELETE` は `204`（本体なし）**／**既に出ているアクセス トークンも通らなくなる**／**2 回目は `401`**／**同じ利用者が登録し直せる** |
| **`RT-307.12`** | **`registration_access_token` 以外では叩けない**（無し・偽・**段階 1 の専用 scope の AT**・**別の登録のトークン**・**知らない `client_id`** — **すべて `401`**） |
| **`RT-307.13`** | **`PUT` の誤りは `400`**（`client_id` 無し / 不一致・`redirect_uris` 無し・`client_secret` 不一致・専用 scope の自己付与）／**どの誤りでも登録は変わらない** |

**使い捨ての利用者 2 人は、段階 1 と同じ**（`WithDcrAsync`）。

> **2 つ目の登録が要るケース**（`RT-307.12` の (6)「別の登録のトークンでは触れない」）**は、
> 消してから作り直して得ている。** **段階 5-a で 2 件を同時に持てるようになった**が、
> **ケースはそのままにしてある**（**測っている観点は「別の登録のトークンでは触れない」**で、
> **2 件の作り方は関係しない**）。

> **`RT-307.12` の (5)「知らない `client_id`」は `401` であって `404` ではない**
> （RFC 7592 §2.1 〜 §2.3 の MUST）。
> **撃ち分けると「在るが触れない」ことが、外から分かってしまう。**

**歯抜け（実測 2026/10/18。どれも `RT-307` 単独の 26 件で測った）。**

| 壊すもの | 実測 |
|---|---|
| `ClientRegistrationProvider.Authorize` の**トークンの照合を、常に通るようにする** | **`RT-307.12` だけが落ちる**（core / netfx の 2 件）。**26 件 / 成功 24 / 失敗 2** |
| `ClientRegistrationProvider.Update` の **`client_id` の一致確認を外す** | **`RT-307.13` だけ**（2 件）。**26 件 / 成功 24 / 失敗 2** |
| **`Helper.HasClient` を、常に真にする**（= **段階 2 で直す前の振る舞い**） | **`RT-307.11` だけ**（2 件）。**26 件 / 成功 24 / 失敗 2** |

> **「`DELETE` で `Users.ClientID` を空にしない」という歯抜けも測ったが、1 件も落ちなかった**
> （26 件 / 成功 26）。**理由は、段階 1 の `Register` が「宙に浮いた `client_id`」を許容すること**で、
> **`!string.IsNullOrEmpty(user.ClientID) && DataProvider.Get(user.ClientID) != null`**
> という条件なので、**行が消えていれば、`Users.ClientID` が残っていても登録し直せる。**
> **その後、空にしてはならないことが分かった**（下の「踏んだこと」）ので、
> **段階 2 の実装は空にしなかった。**
> **段階 5-a-1 で `Users.ClientID` を列ごと落としたので、この歯抜けは作れなくなった。**

> **最後の 1 行が、段階 2 でいちばん大事な確認である。**
> **以前は「クライアントがまだ在るか」の確認が効いていなかった**
> （`Helper.GetClientSecret` は**未登録でも空文字を返す**ので、`!= null` が常に真だった）。
> **`DELETE` を入れると、ここが正面から当たる** —
> **払い下げたクライアントのアクセス トークンが、期限（既定 360 分）まで通ってしまう。**

**測っていないもの。**

| | |
|---|---|
| **管理 API のレート制限**（`register_mgmt` のバケツ） | **口の表に入れただけ**で、**`429` を測っていない**（#305 の `RT-305.*` は `/token` の口で測っている。**通しを重くすると `RT-305.5` の間欠が増える**） |
| **`2000` 文字いっぱいのメタデータ** | **段階 1 と同じく、測っていない**（DDL が通ることと、短い値が動くことまで） |

**実測（2026/10/19）。**

| | 結果 |
|---|---|
| クリーン ビルド | **net48 / net10.0 とも エラー 0 / 警告 0** |
| `RT-307.*`（単独。`mem`） | **26 件 / 成功 26 / 失敗 0 / Skip 0**（13 ケース × core / netfx） |
| `mem`（既定の通し） | **661 件 / 成功 654 / 失敗 1 / Skip 6**（原本 **342 件**。**Skip は従来の 6 件のまま**）。**失敗の 1 件は `RT-305.1`（netfx）**で、**単独では通る**（下の注） |
| `sql`（SQL Server） | **26 件 / 成功 26 / 失敗 0** |
| `ora`（Oracle） | **26 件 / 成功 26 / 失敗 0** |
| `npg`（PostgreSQL） | **13 件 / 成功 13 / 失敗 0 / Skip 13**（netfx は PostgreSQL を使えない。従来どおり） |

> **`mem` の通しで `RT-305.1`（netfx）が 1 件落ちた。**
> **単独では 4 件すべて通る**（実測）ので、**間欠である。**
> **`RT-305.1` は「ポーリングが速すぎたら `slow_down`」を測る**もので、
> **要求の間隔に依る** — **通しが重いと、間隔が開いて `authorization_pending` になる**
> （**実測はまさにそれだった**）。
> **段階 1 の `RT-305.5` と同じ性質**である（#305 の窓・間隔に依るテスト）。

> **3 方言は、新しい DDL（`RegistrationAccessToken` の 1 列）が流れた状態で測っている。**
> **`mem` の通しでは `Create_UserStore.sql` が流れない**ので、**列の追加は何も確かめられない。**
> **`oracle` と `postgres` はコンテナを作り直した**（`init` は新しいコンテナでしか流れない）。
> **`docker compose rm` には必ずサービス名を付けること**（#306 で踏んだ）。

> **`RT-307.9` 〜 `.13` は、列が無ければ通らない** —
> **登録の時点でハッシュを保存できず、`GET` が `401` になる。**
> **方言ごとに通ったことが、そのまま「列が在る」ことの確認になっている。**

###### 踏んだこと : DDL を変えたら `store\0_CopyInitSql.ps1` を回す

**3 方言の通しが、1 回目は全件落ちた**（実測 : `sql` と `ora` は 26 件すべて、`npg` は core の 13 件すべて）。
**症状は「ログイン画面が HTTP 500」**で、**サイトのログに
`column "registrationaccesstoken" does not exist`** が出ていた。

| | |
|---|---|
| **DDL の原本** | `root\files\resource\MultiPurposeAuthSite\Sql\{sqlserver,oracle,pstgrs}` |
| **コンテナが読むもの** | `store\{sqlserver,oracle,postgres}\init`（**複写。`.gitignore` 済み**） |
| **複写するもの** | **`store\0_CopyInitSql.ps1`**（**`1_DockerComposeUp.bat` は起動の前に必ず呼ぶ**が、**`test.ps1` 経由の起動は呼ばない**） |

> **`sqlserver` は毎回 init を流し直す**ので、**古い複写のまま DB を作り直す** —
> **「作り直したのに古い」**という形で出る。
> **`oracle` と `postgres` は、新しいコンテナのときだけ init が流れる**ので、
> **複写とコンテナの作り直しの両方**が要る。
>
> **同じ踏み方は #245 の段階 3 でもあった**（`0_CopyInitSql.ps1` の説明に書いてある）。
> **DDL を変えた回は、必ずこれを回すこと。**

###### 踏んだこと : `Users.ClientID` は空にできない（`mem` では出ない）

**複写を直して測り直したら、`sql` で `RT-307.11` と `RT-307.12` が落ちた**
（**26 件 / 成功 22 / 失敗 4**。**`DELETE` が `204` ではなく `500`**）。

| | |
|---|---|
| 何をしていたか | **`DELETE` で `Users.ClientID` を空にしていた**（「登録し直せるように」） |
| なぜ駄目か | **`Users.ClientID` は NOT NULL で、一意索引（`ClientIDIndex`）が張られている**。**`Saml2OAuth2Data.ClientID` から `Users.ClientID` への外部キー**も在る |
| 既存の作り | **管理画面の `RemoveSaml2OAuth2Data` も、同じ理由で空にしていない**（**「一意制約エラーになるので」というコメントが残っていた**） |
| 直し | **空にしない。** **同意だけ落とす。** **登録し直せるのは、段階 1 の `Register` が「登録の行が無ければ通す」から** |

> **`mem` のストアには制約が無いので、`mem` の通しでは出ない。**
> **`mem` で 26 件すべて通っていても、DB ストアでは落ちる**という形である。
> **`Users` と `Saml2OAuth2Data` を跨いで書く変更は、必ず方言でも測ること。**
>
> **段階 5-a-1 で、この制約ごと落とした**（**所有者は `Saml2OAuth2Data.OwnerUserId` へ移した**）。
> **踏んだ記録として残す** — **教訓（跨ぐ変更は方言でも測る）は、そのまま効いている。**

##### クライアント認証の方法（`RT-307.14` 〜 `.17`。#307 の段階 3）

**`token_endpoint_auth_method` を動的登録から設定できるようにした分**を測る。
**検証する側は実装済み**（`private_key_jwt` は #239 / #129 の段階 2、`tls_client_auth` は #226）で、
**動的登録だけが断っていた。**

| | 測ること |
|---|---|
| **`RT-307.14`** | **`private_key_jwt` ＋ `jwks` で登録でき、その鍵の `client_assertion` で `/token` が通る**／**応答が方法と `jwks` を返す**／**`client_secret` も返る**（一律発行）／**その秘密では通らない** |
| **`RT-307.15`** | **`tls_client_auth` ＋ DN で登録でき、その証明書で `/token` が通る**／**Subject が違う証明書では通らない**（**既定は core だけ**） |
| **`RT-307.16`** | **登録の時点で断る 6 つ**（`private_key_jwt` に鍵なし・`tls_client_auth` に DN なし・知らない方法・`jwks` に RSA 2 本・`jwks_uri`・`device_code` × `private_key_jwt`） |
| **`RT-307.17`** | **`PUT` で方法を省くと秘密ベースに戻る**／**`jwks` は持ち越される**（**省いても消さない**）／**戻った後は秘密で交換できる** |

**使い捨ての利用者 2 人は、段階 1・2 と同じ**（`WithDcrAsync`）。

> **`RT-307.15` は、既定では net10.0 版だけを測る**（`MtlsTests` と同じ前提）。
> **net48 版（IIS Express）はテスト用 CA の手当てが要る**ので、
> **`-NetFxMtls` を付けたときだけケースを作る**（**Skip にもしない**。TESTING.md 5 節）。
> **前提の判定は `MtlsTests.SkipIfNoMtls` を共用する**（同じことを 2 か所に書かないため）。

###### 既存のテストに及んだ影響（**同じ事情が、配備にも及ぶ**）

**「登録された方法でなければ通さない」**ようにしたので、
**1 つのクライアントが「秘密でも鍵でも通る」ことはできなくなった。**

| | |
|---|---|
| **`TestClient`** | **秘密で認証する**（ほぼ全てのケースがそう使う）。**方法は明示しない** |
| **`TestClient_24`（新規）** | **`TestClient` を写し、`token_endpoint_auth_method` を `private_key_jwt` にした種データ。** **`RT-239.1` 〜 `.4` / `RT-129.1` を、こちらへ向けた** |
| **`TestClient2`** | **構成ファイルに `token_endpoint_auth_method": "private_key_jwt"` を明記した**（fapi2。`RT-238.*` / `RT-239.5`） |
| **`TestClient2_2` / `TestClient2_3`** | **`tls_client_auth` を明記**（`FA-6.*`。**DN を登録しただけでは通らない**） |
| **`TestClient_8`** | **`private_key_jwt` を明記**（`RT-262.1`） |

> **`RT-239.1` 〜 `.3` は、以前は「交換は `client_secret`、更新や失効は `client_assertion`」と
> 混ぜていた。** **仕様（RFC 7591 §2）の `token_endpoint_auth_method` は 1 つ**であり、
> **混ぜられたのは、この実装が方法を見ていなかったから**である。
> **いまは、交換も `client_assertion` で行う**（`TokenByClientAssertionAsync`）。

> **`EX-7.*`（JWT Bearer の認可グラント）は影響を受けない** —
> **`GrantJwtBearerTokenCredentials` が自前で署名を検証する経路**で、
> **クライアント認証（`ClientAuthentication`）を通らない。**
> **SAML2 の `AuthnRequest` の署名検証と、Request Object（JAR）の検証も同じ**で、
> **登録された鍵を別の用途で使っている**ため、方法の判定は効かない。

**歯抜け（実測 2026/10/19）。**

| 壊すもの | 実測 |
|---|---|
| **`CmnEndpoints.AllowsAuthMethod` を常に true にする**（= 段階 3 より前の振る舞い） | **`RT-307.14` だけが落ちる**（core / netfx の 2 件）。**33 件 / 成功 31 / 失敗 2** |
| `ClientRegistrationProvider.Validate` の**材料の確認を外す**（鍵・DN が無くても登録させる） | **`RT-307.16` だけ**（2 件）。**33 件 / 成功 31 / 失敗 2** |
| `ParseJwks` の**同じ `kty` が 2 本の判定を外す**（先頭を採る） | **`RT-307.16` だけ**（2 件。**「RSA が 2 本」が通ってしまう**）。**33 件 / 成功 31 / 失敗 2** |

**測っていないもの。**

| | |
|---|---|
| **net48 版の `tls_client_auth`** | **テスト用 CA の手当てが要る**（`-NetFxMtls`）。**既定の通しでは、ケースを作らない** |
| **`jwks` に EC 1 本だけを登録した場合** | **`RT-307.14` は RSA で測っている**（`ParseJwks` は両方を同じ道で入れる）。**ES256 の `client_assertion` は `RT-129.1` が測る**（種データ側の登録） |
| **`client_secret_basic` と `client_secret_post` の撃ち分け** | **区別しない**（この層はどちらで来たかを知らない）。**仕様の値としては受けるが、振る舞いは同じ** |
| **デバイス フロー × 鍵だけのクライアント** | **登録では断る**（`RT-307.16` の (6)）が、**構成ファイルや画面から作った「鍵だけ」の登録**（秘密も DN も無い）**が、デバイス フローで断られること自体は測っていない** |

**実測（2026/10/19）。**

| | 結果 |
|---|---|
| クリーン ビルド | **net48 / net10.0 とも エラー 0 / 警告 0** |
| `RT-307.*`（単独。`mem`） | **33 件 / 成功 33 / 失敗 0**（**17 ケース × 2 − 1**。**`RT-307.15` は netfx のケースを作らない**） |
| `mem`（既定の通し） | **675 件 / 成功 669 / 失敗 0 / Skip 6**（原本 **346 件**。**Skip は従来の 6 件のまま**） |
| `sql`（SQL Server） | **33 件 / 成功 33 / 失敗 0** |
| `ora`（Oracle） | **33 件 / 成功 33 / 失敗 0** |
| `npg`（PostgreSQL） | **17 件 / 成功 17 / 失敗 0 ＋ Skip 16**（netfx は PostgreSQL を使えない。従来どおり） |

> **3 方言は、`mem` の通しと同じ版で取り直してある**（**最後の直しの後**）。
> **1 回目（直す前）と同じ値だった** — **`RT-307.*` のコードは、その直しで
> 1 行も変えていない**ため（直したのは `TestClients.cs` の種データ 1 件と、
> `RT-245.5` / `RT-129.3` の向き先だけ）。
>
> **1 回目の取り直しは、機械のメモリ不足で打ち切られた**（`sql` の途中）。
> **DB を 3 つ同時に起動しないこと**は `store\docker-compose.yml` の頭にも書いてあるが、
> **`mem` の通しの直後に方言を続けると、それだけでも足りなくなることがある** —
> **1 つずつ、間でサイトを止めて回すこと。**

> **DDL を 1 列足した**（`TokenEndpointAuthMethod`）ので、**3 方言でも測る。**
> **`store\0_CopyInitSql.ps1` を回すこと**（下の「踏んだこと」と同じ理由）。

##### `software_statement`（`RT-307.18` 〜 `.21`。#307 の段階 4）

**署名付きの主張を受けるようにした分**を測る。
**「署名が正しいこと」と「信頼していること」と「主張が本文に勝つこと」は別の話**なので、分けて測る。

| | 測ること |
|---|---|
| **`RT-307.18`** | **statement で登録でき、主張した値が本文（plain JSON）に勝つ**／**statement だけ・本文だけの項目も使われる**／**`software_statement` は応答に出ない**／**主張された折り返し先で実際に認可コードが取れ、本文に書いた方では取れない** |
| **`RT-307.19`** | **壊れた statement は `400` ＋ `invalid_software_statement`**（JWT でない・**署名が合わない**・`iss` 無し・`exp` 切れ・**`aud` が別の AS**） |
| **`RT-307.20`** | **知らない発行者は `400` ＋ `unapproved_software_statement`**（**署名が通る鍵で作っても**、`iss` が信頼一覧に無ければ受けない） |
| **`RT-307.21`** | **`PUT` でも statement が効く**／**壊れた statement の `PUT` は `400` で登録は変わらない**／**省いた `PUT` は本文が通る**（全置換） |

**使い捨ての利用者 2 人は、段階 1 〜 3 と同じ**（`WithDcrAsync`）。

###### 署名鍵は、配備の `SpRp_RsaPfxFilePath` を使う

**statement を署名する側（ベンダ）の鍵を、テストが持つ必要がある。**
**新しい鍵は作らず、既に在る対を使う。**

| | |
|---|---|
| **テストが署名する鍵** | **`SpRp_RsaPfxFilePath`**（`SHA256RSA_Client.pfx`）。`JwsSigner.SignRS256` |
| **サイトが検証する鍵** | **その対の `.cer`**（`SHA256RSA_Client.cer`）を、**発行者の `cer_file_path` として渡す** |
| **期待する `iss`** | **`https://vendor.opentouryo.com`**（`test.ps1` の `$script:SoftwareStatementIssuer`） |

**渡し方は `EnableDynamicClientRegistration` と同じ**（**雛形の既定は空**で、**`test.ps1` が環境変数で渡す**）。

```
net10.0 : appSettings__SoftwareStatementIssuers__e2e_vendor__issuer  ほか（節として読む）
net48   : SoftwareStatementIssuers（1 本の JSON 文字列）
```

> **`test.ps1` は、テスト側へ しるし を渡す** — **`MPAS_SOFTWARE_STATEMENT_ISS`。**
> **渡っていなければ、`RT-307.18` 〜 `.21` は Skip する**（`MtlsTests.SkipIfNoMtls` と同じ作法）。
> **`-Launch` を付けないで回したときや、コンテナを相手にしたときは、この 8 件が Skip になる。**
>
> **しるしの値を `iss` に使う**（テスト側で別に持たない）。
> **2 か所に書くと、設定を替えたときに食い違う。**

###### `RequireSoftwareStatement` は、ケースを分けずに実測した

**通しは false で回す**（**true にすると、statement を添えないケースが全部落ちる**）。
**ケースを足す代わりに、環境変数で true にして `RT-307` を 1 回回した**
（**設定ファイルを触らずに済む** — **`test.ps1` が立てる環境変数は子プロセスへ継がれる**）。

| | |
|---|---|
| **通し（false）** | **添えれば効き、添えなくても登録できる** |
| **true の 1 回** | **statement を添えないケースが落ちる**（実測は下の表）。**添えるケースは通る** |

> **`RT-307.21` が落ちるのが、いちばん大事な確認である。**
> **その (4)「statement を省いた `PUT` は本文が通る」が `400` になる** ＝
> **閉じたかった穴が、実際に閉じている。**
>
> **`PUT` に効かせたのは、そのため**である。
> **statement を保管していない**ので、**`PUT` で省かれたら「主張されていた値」を思い出せない。**

###### 既存のテストで、期待が変わったもの

| | |
|---|---|
| **`RT-307.4` の (5)** | **壊れた statement（`eyJ.eyJ.sig`）の `error`** が、**発行者を設定した配備では `invalid_software_statement`**（**設定していなければ従来どおり `unapproved_software_statement`**）。**どちらでも `400` で、登録は作られない** |

**ケースの側で、配備を見て期待を切り替えている**（`SoftwareStatementIssuer()` が空かどうか）。
**段階 3 のときのような「向き先の付け替え」は要らなかった** —
**statement は、既存のクライアントの振る舞いを変えないため**である。

**歯抜け（実測 2026/10/20）。**

| 壊すもの | 実測 |
|---|---|
| **`SoftwareStatementProvider.Merge` の優先順位を逆にする**（本文が在れば上書きしない） | **`RT-307.18` と `RT-307.21` が落ちる**（各 core / netfx の 2 件）。**41 件 / 成功 37 / 失敗 4** |
| **署名の検証を飛ばす**（`jws.Verify` の結果を見ない） | **`RT-307.19` と `RT-307.21` が落ちる**（4 件）。**41 件 / 成功 37 / 失敗 4** — **`.21` も落ちるのは、その (3)「壊れた statement の `PUT` は `400`」も 署名の検証に依っているため** |
| **発行者の照合をしない**（`SoftwareStatementIssuers.Find` が、どの `iss` でも 1 件目を返す） | **`RT-307.20` だけ**（2 件）。**41 件 / 成功 39 / 失敗 2** |

**測っていないもの。**

| | |
|---|---|
| **`ES256` で署名した statement** | **`alg` の照合は実装しているが、測っているのは `RS256` だけ**（`SigningKeys.CreateJwsFromCer` が alg → class を 1 か所で持つので、**鍵の種類が変わるだけ**） |
| **発行者の鍵の入れ替え**（新旧を並べて試す） | **出来ない**（**`Find` は一致する最初の行だけを返す**）。**段階 5 以降**（CONFIGURATION.md の「気をつける所」） |
| **`.cer` が読めないときの振る舞い** | **`unapproved_software_statement` に倒す**ことは実装しているが、**E2E では測っていない**（**設定を壊して回す形になる**） |
| **発行者ごとに許す範囲を絞ること** | **実装していない**（**いまは「信じるか、信じないか」の 2 択**）。段階 5 以降 |

**実測（2026/10/20）。**

| | 結果 |
|---|---|
| クリーン ビルド | **net48 / net10.0 とも エラー 0 / 警告 0** |
| `RT-307.*`（単独。`mem`） | **41 件 / 成功 41 / 失敗 0**（**21 ケース × 2 − 1**。**`RT-307.15` は netfx のケースを作らない**） |
| **`RequireSoftwareStatement` を true にした配備** | **41 件 / 成功 16 / 失敗 25**（**statement を添えないケースが落ちる**。**`RT-307.18` 〜 `.20` は通る**。**`RT-307.21` も落ちる** — **その (4)「省いた `PUT` は本文が通る」が `400` になるため** ＝ **閉じたかった穴が閉じている**） |
| `mem`（既定の通し） | **683 件 / 成功 677 / 失敗 0 / Skip 6**（原本 **350 件**。**Skip は従来の 6 件のまま**） |
| `sql`（SQL Server） | **41 件 / 成功 41 / 失敗 0** |

> **通しで取り違えは出なかった**（**段階 3 では、ここで 2 件出た** — 1 クライアント 1 方法の帰結）。
> **段階 4 は、既存のクライアントの振る舞いを変えていない** —
> **`software_statement` を添えない要求の道は、1 行も変わらない。**
> **増えたのは 8 件**（675 → 683）で、**Skip は従来の 6 件のまま。**
>
> **1 回目の通しは、機械のメモリ不足で打ち切られた**（テスト実行の途中）。
> **回すときは 1 つずつ、間でサイトを止めること**（段階 3 でも踏んだ）。
> **`mem` の通しの直後に方言を続けると、それだけで足りなくなることがある。**

> **方言は `sql` だけでよい。** **この段階は DDL を変えていない**（**列を 1 つも足していない**）ので、
> **`ora` / `npg` を取り直す理由が無い** — **`RT-307.18` 〜 `.21` が通る DB の道は、
> `DataProvider.Create` / `Update` / `Get` で、段階 1 〜 3 のケースと同じ列**である。
> **`sql` を測るのは、制約が在る側で、登録の作成・更新・削除が通ることを見るため**である
> （段階 2 でそこを踏んだ。**当時の制約は `Users.ClientID` の一意索引と外部キー**で、
> **段階 5-a-1 でそれごと落とした**）。
##### 1 利用者 n クライアント（`RT-307.3` の書き換え。#307 の段階 5-a）

**所有者の置き場所を移した分**を測る。**ケースは増やさず、`RT-307.3` の意味を変えた。**

| | 測ること |
|---|---|
| **`RT-307.3`** | **2 件目も `201`**／**`client_id` / `client_secret` / `registration_access_token` が 1 件目と違う**／**どちらでも認可コードが取れる**（それぞれの折り返し先で）／**1 件目を `DELETE` しても、2 件目は `GET` で読めて認可コードも取れる** |

**段階 1 では「2 件目は `403` ＋ `access_denied`」を測っていた。**
**あれは仕様の要求ではなく、器の都合だった**ので、**ケースごと向きを変えた。**

| | いま |
|---|---|
| **所有者** | **`Saml2OAuth2Data.OwnerUserId`**（`Users.Id` を指す。行ごと） |
| **落としたもの** | **`Users.ClientID`**（列ごと）／**その一意索引**／**旧い外部キー**／**`ApplicationUser.ClientID`** |
| **上限** | **無い**（設定キーも増やしていない） |

###### 種データの利用者が要らなくなった

**以前は、E2E の種データ（#264）のクライアント 1 件につき、利用者 1 人を作っていた** —
**外部キー（`Saml2OAuth2Data.ClientID` → `Users.ClientID`）を満たすためだけ**である。
**張り替えたので、その利用者はもう作らない**（**`OwnerUserId` は空**）。

> **`ClientName` は、従来どおり入る**（**ラベル**）。
> **`Helper.GetClientName` が「登録が在るか」の判定と、`client_credentials` の `sub` に使う**ため、
> **消してはならない。**

###### 管理画面は、まだ 1 件だけを扱う（段階 5-a-1 の時点）

**`DataProvider.GetFirstByOwner` で「所有者の先頭 1 件」を出していた。**
**この画面の UI テスト（`RT-277.1` / `RT-277.2` / `RT-297.1`）と、画面から登録するテスト**
（`ManageClientRegistration.RegisterWithSecretAsync`）**の振る舞いは変わらなかった。**

> **`RT-257.*` はこの画面ではない**（**サインアップと、利用者・ロール管理の画面**。#257）。
> **ここを取り違えて書いていたので、直した。**

> **どれが先頭かは決めていなかった**（`ORDER BY` を書いていない）。
> **`mem` は辞書の順、DB は索引の都合**である。
>
> **段階 5-a-2 で `client_id` の昇順に決めた** — **一覧の行が毎回入れ替わらないように**で、
> **E2E が「2 件目」を指せる**ようにもなった。

**歯抜け（実測 2026/10/20）。**

| 壊すもの | 実測 |
|---|---|
| **`Register` が `OwnerUserId` を書かないようにする** | **`RT-307.3` だけが落ちる**（core / netfx の 2 件。**(6) の「2 件目も、もう読めない」が `200`**）。**41 件 / 成功 39 / 失敗 2** |
| **`GetByOwner` が所有者で絞らないようにする**（全件返す） | **1 件も落ちない**（**41 件 / 成功 41**）。**`RT-307` 群では守られていない**（下の「測っていないもの」） |
| **`GetFirstByOwner` が常に null を返すようにする** | **41 件すべて落ちる**（成功 0）。**管理画面の経路が前提に入っているため**で、**狙いを絞れていない** |

> **`Register` の歯抜けが、足したケースの値打ちを示している。**
> **(6) を足す前は、この歯抜けで 1 件も落ちなかった** —
> **つまり「所有者を書いていること」は、どのケースでも守られていなかった。**
> **歯抜けを用意していて気付いた**ので、**(6) を足してから測り直した。**

**測っていないもの。**

| | |
|---|---|
| **既存データの移行**（`ALTER` ＋ `UPDATE` ＋ FK の張り替え ＋ 列の削除） | **E2E は毎回作り直す**（`Create_UserStore.sql`）ので、**移行の手順は測っていない。** **文書に 3 方言ぶん書いた**（`CONFIGURATION.md`） |
| **n 件を持つ利用者が、管理画面で保存したとき** | **画面が扱う 1 件に寄る**（**段階 5-a-1 の割り切り**）。**段階 5-a-2 で一覧にする** |
| **所有者の居ない登録**（`OwnerUserId` が空）**を、管理画面から触ること** | **出来ない**（**所有者で引くので、画面には出ない**）。**種データと構成ファイルのクライアントが、その立場** |
| **何件まで作れるか** | **上限を設けていない**ので、**件数の限界は測っていない**（**レート制限は #305 の `RT-305.*` が測る**） |
| **`GetByOwner` が所有者で絞っていること** | **`RT-307` 群では守られていない**（歯抜け b が 1 件も落ちない）。**絞りが効くのは管理画面の経路**で、**それを見るのは この画面の UI テスト**（`RT-277.*`。**`RT-257.*` ではない** — あれはサインアップと利用者・ロール管理である）。**段階 5-a-1 の時点では、どのケースも落ちなかった** — **段階 5-a-2 の `RT-277.9` が、一覧の件数で捕まえる**（下の節） |
| **所有者が n 件持つときの、管理画面の見え方** | **先頭 1 件を出すだけ**（段階 5-a-1 の割り切り）。**「どれが出るか」は決めていない**ので、**測れる形になっていない** |

**実測（2026/10/20）。**

| | 結果 |
|---|---|
| クリーン ビルド | **net48 / net10.0 とも エラー 0 / 警告 0** |
| `RT-307.*`（単独。`mem`） | **41 件 / 成功 41 / 失敗 0**（**21 ケース × 2 − 1**。**`RT-307.15` は netfx のケースを作らない**） |
| `mem`（既定の通し） | **683 件 / 成功 677 / 失敗 0 / Skip 6**（原本 **350 件**。**Skip は従来の 6 件のまま**） |
| `sql`（SQL Server） | **41 件 / 成功 41 / 失敗 0** |
| `ora`（Oracle） | **41 件 / 成功 41 / 失敗 0** |
| `npg`（PostgreSQL） | **21 件 / 成功 21 / 失敗 0 ＋ Skip 20**（netfx は PostgreSQL を使えない。従来どおり） |

> **DDL を変えたので 3 方言とも測る**（**列 1 つ ＋ 一意索引 ＋ 外部キーの張り替え ＋ 列の削除**）。
> **`store\0_CopyInitSql.ps1` を回すこと**（段階 1・3 と同じ理由）。
>
> **`Users` と `Saml2OAuth2Data` を跨いだ変更**なので、**`mem` では出ない失敗が在り得る** —
> **段階 2 でそこを踏んだ**（`Users.ClientID` を空にして `sql` で `DELETE` が `500`）。
> **今回は、その制約ごと落としている。**
>
> **回すときは 1 つずつ、間でサイトを止めること**（段階 3・4 で踏んだメモリ不足）。
##### クライアントの鍵を `jwks_uri` から引く（`RT-309.*`。#309 の段階 1）

| | 測ること |
|---|---|
| **`RT-309.1`** | **動的登録で `jwks_uri` を登録でき、その URL に置いた鍵の `client_assertion` で `/token` が通る**（**応答に `jwks_uri` が返り、`jwks` は返らない**）／**`jwks` との併記は `400`**／**読めない URL は `400`** |
| **`RT-309.2`** | **画面から登録した `jwks_uri`**（**取りに行っていない**）**は、1 回目のクライアント認証で断られ、背景で補充された後は通る** |
| **`RT-309.3`** | **同じ URL の中身を入れ替えると、`PUT` で読み直して新しい鍵（EC / ES256）で通り、古い鍵（RSA）では通らなくなる** |
| **`RT-309.4`** | **`software_statement` の中だけで主張された `jwks_uri`** でも登録でき、**1 回目のクライアント認証から通る**（**段階 2**。段階 1 では `400` だった） |

###### 相手の `jwks_uri` は、静的配信のコンテナで用意する

**`jwks_uri` が指す先は、本来クライアント（RP）が公開する。**
**E2E のクライアントは `HttpClient` のコードで、HTTP サーバを持たない** —
**配るだけのものを 1 つ置いた**（`store/docker-compose.yml` の `jwks`。**44305**）。

| | |
|---|---|
| **中身を書くのはテスト** | **ホストの `store/jwks` に `.json` を置く**（**同じテストの中で消す**。`.json` は `.gitignore`） |
| **URL はケースごとに分ける** | **キャッシュはプロセスの中で URL ごと**なので、**同じ URL では「空の状態」を測れない** |
| **既存の `/jwkcerts` は使わない** | **あれは `JwkSet_Upstream.json` を配っており、`RT-140.*` / `CN-5.*` も見ている共有のファイル**である（**書き替える測りを入れると、戻し忘れが ID 連携を壊す**） |
| **`sendfile off`** | **bind mount したファイルを書き替えると、古い中身を返すことがある**ので、落としてある（`store/jwks-nginx.conf`） |
| **平文の http** | **実装は `https` を要求するが、ループバックだけは許している**ので、**証明書を用意していない** |

> **コンテナが上がっていなければ Skip する**（`Infrastructure/JwksUri.SkipIfNotAvailableAsync`）。
> **`store\1_DockerComposeUp.bat` は、これも一緒に起動する。**

###### 測るのは `/revoke`（`RT-309.2` / `.3`）

**クライアント認証だけを通る口**なので、**鍵の出どころだけを見られる。**
**RFC 7009 §2.1 は「トークン エンドポイントと同じクライアント認証」を求めており**、
**知らないトークンは成功**（`200`。§2.2）なので、**合否がクライアント認証だけで決まる。**

###### 踏んだこと : 使い捨ての利用者は `Admin` で作る

**クライアント登録の画面（`/Manage/AddSaml2OAuth2Data`）は、
`SystemAdmin` か `Admin` でなければ開かない**（`ManageController`）。
**`User` で作ると、画面から登録できず「前提」で落ちる。**

**`GrantTypes` を絞ってもいけない** — **画面が `ResponseTypes` との噛み合いを見る**ので、
**`password` だけを登録しようとすると、登録そのものが通らない。**

###### 起動のときの温めは、E2E では測れない（目視の手順。#309 の段階 2）

**サイトの起動は `test.ps1` が握っており、テストから再起動できない**
（**プロセスを殺すと、xUnit が並列に回している他のケースを壊す**）。
**ログで確かめる。**

| | |
|---|---|
| **出る場所** | **net10.0 版は `C:\root\files\resource\Log\OPERATION.<日付>.log`**、**net48 版は `C:\root\files\resource\MultiPurposeAuthSite\Log\OPERATION.<日付>.log`**（**2 つのアプリで置き場が違う**） |
| **出る文字列** | `The jwks_uri warm-up read <n> of <m> JWK Sets.`（**0 件でも出る** ＝ **仕掛けが動いていることの印**） |

**設定ファイル側の経路は、環境変数 1 本で確かめられる**（**net10.0 版のみ**。
**net48 版の `OAuth2ClientsInformation` は 1 本の JSON 文字列**なので、1 件足せない）。

```powershell
# **相手の JWK Set を置く**（鍵が 1 本でも入っていること — 空の keys では「read 0」になる）
Copy-Item C:\root\files\resource\MultiPurposeAuthSite\JwkSet.json C:\MultiPurposeAuthSite\store\jwks\warm.json
$env:appSettings__OAuth2ClientsInformation__e2e309warm__jwks_uri = 'http://localhost:44305/warm.json'
cd root\programs\Tests
.\test.ps1 -Launch -NoNetFx -Filter "FullyQualifiedName~DiscoveryTests"
Remove-Item Env:\appSettings__OAuth2ClientsInformation__e2e309warm__jwks_uri
```

**実測（2026/10/21）。**

| 確かめたもの | 実測 |
|---|---|
| **net10.0 版の呼び出し**（`Startup.Configure`）＋ **設定ファイルの列挙** | **`The jwks_uri warm-up read 1 of 1 JWK Sets.`**（上の手順で） |
| **net48 版の呼び出し**（`Application_Start`） | **`read 0 of 0`**（**温める対象が無くても、呼ばれていることは分かる**） |
| **user store の列挙**（`sql`） | **`read 0 of 0`** ＋ **「読めなかった」のログが出ない** ＝ **SQL は通っている**（**`jwks_uri` を持つ行が無いので 0 件**） |
| **`ora` / `npg` の列挙** | **測っていない**（**同じコードで、列名の引用だけが方言ごと**。`DataProvider.ColumnList`） |

###### 歯抜け（実測 2026/10/21）

| 壊すもの | 実測 |
|---|---|
| **背景で補充しない**（`DiscoveryJwks.RefillInBackground` が何もしない） | **`RT-309.2` だけが落ちる**（core / netfx の 2 件。**1 回目に断られたまま、再試行しても通らない**）。**6 件 / 成功 4 / 失敗 2** |
| **登録のときに取りに行かない**（`ClientRegistrationProvider.WarmUpJwksUriAsync` が何もしない） | **`RT-309.1` と `.3` が落ちる**（4 件。**登録が `400`** ＝ **読めない扱いになる**）。**6 件 / 成功 2 / 失敗 4** |
| **`jwks` と `jwks_uri` の排他を見ない** | **`RT-309.1` だけが落ちる**（2 件。**併記が `400` にならず `201`**）。**6 件 / 成功 4 / 失敗 2** |
| **statement が主張した `jwks_uri` を温めない**（段階 1 の形に戻す） | **`RT-309.4` だけが落ちる**（2 件。**登録が `400`**）。**8 件 / 成功 6 / 失敗 2** |

> **3 つが別々のケースを落とす** — **「登録のときに取る」「背景で取る」「排他」が、
> それぞれ独立に効いている**ことの裏返しである。

**測っていないもの。**

| | |
|---|---|
| **何もせずに 1 分待つと追随すること** | **背景の取り直しの下限は 1 分**である。**E2E で 1 分待たない**ので、**`PUT` で読み直す形で測っている**（`RT-309.3`） |
| **起動のときの温め** | **E2E では測れない**（上の「目視の手順」で確かめた）。**`ora` / `npg` の列挙は測っていない** |
| **`https` の `jwks_uri`** | **ループバックの `http` で測っている**（**配信に証明書を用意していない**）。**`https` を要求する分岐は、読めない URL（`RT-309.1` の (5)）で通っている** |
| **`kid` が在るアサーション** | **`kid` を入れずに測っている**（**在る鍵を順に試す経路**）。**`kid` で引く分岐は、`RT-140.*` が ID 連携で通している** |

**実測（2026/10/21）。**

| | 結果 |
|---|---|
| クリーン ビルド | **net48 / net10.0 とも エラー 0 / 警告 0** |
| `RT-309.*`（単独。`mem`） | **8 件 / 成功 8 / 失敗 0**（4 ケース × 2。**段階 2 で `RT-309.4` を足した**） |
| `mem`（既定の通し） | **713 件 / 成功 705 / 失敗 0 / Skip 8**（原本 **365 件**。**`jwks` のコンテナを上げて回した**） |

> **方言は回していない** — **DDL は変わっていない**（**`JwksUri` 列は #307 の段階 1 から在る**）。

> **失敗 0 を取るのに 3 回かかった**（2026/10/21）。**どちらも既知の間欠である。**
>
> | 回 | 落ちたもの | 直し |
> |---|---|---|
> | 1 | **`CN-5.1` / `.2` / `.4` / `.5`** | **コンテナの溜まり**（上の「コンテナの `mem` ストアは、回を重ねると溜まる」）。**`docker compose restart upstream upstream2 downstream`** |
> | 2 | **`RT-305.5`（netfx）** | **窓 20 秒で 330 回叩き切るテスト**（上の「口ごとのレート制限」）。**単独では成功**（netfx 5 秒 / core 20 秒） |
> | 3 | **無し** | — |
>
> **1 日に何度も回した後は、この 2 つを先に疑うこと。** **どちらも変更の経路とは別**である
> （**`CN-5.*` は公開済みイメージのコンテナ同士**、**`RT-305.5` は時間に依る**）。

##### DPoP の縛りを前と後ろへ広げる（`RT-311.10`〜`.14`。#311 の段階 4）

| | 測ること | いつ回るか |
|---|---|---|
| **`RT-311.10`** | **認可要求の `dpop_jkt` で、`code` が鍵に縛られる**（§10） | いつでも |
| **`RT-311.11`** | **`refresh_token` も同じ鍵に縛られる**（§5）。**ローテーションした後も** | いつでも |
| **`RT-311.12`** | **`DPoP` スキームで来た要求には `WWW-Authenticate: DPoP` ＋ `algs`** で答える（§7.1） | いつでも |
| **`RT-311.13`** | **`/token` が `nonce` を要求する**（`use_dpop_nonce` ＋ `DPoP-Nonce`。§8） | **`-DPoPNonce`** |
| **`RT-311.14`** | **保護されたリソースが `nonce` を要求する**（§9）。**`/token` の nonce は通らない** | **`-DPoPNonce`** |

###### どれも「断った後、やり直せる」ことまで見る

**`RT-311.10`** は **断られた `code` が、正しい鍵でまだ引き換えられる**こと。
**`RT-311.11`** は **断られた `refresh_token` が、正しい鍵でまだ使える**こと
（**ローテーションの一族ごと失効させない**）。
**`RT-311.13`** は **断られた `code` が、貰った `nonce` で引き換えられる**こと。

**縛りが「利用者を閉じ出す仕掛け」になっていないことを、そこで押さえる。**

###### 歯抜け（実測 2026/10/22）

| 壊すもの | 実測 |
|---|---|
| **`code` の `dpop_jkt` を見ない** | **`RT-311.10` だけが落ちる**（**4 件 / 成功 2 / 失敗 2**） |
| **`refresh_token` の縛りを見ない** | **`RT-311.11` だけが落ちる**（**4 / 2 / 2**） |
| **チャレンジのスキームを見ない**（常に `Bearer`） | **`RT-311.12` が落ちる**（**2 / 0 / 2**） |
| **`nonce` を見ない** | **`RT-311.13` と `RT-311.14` が落ちる**（**4 / 0 / 4**。`-DPoPNonce`） |
| **ローテーションで縛りを引き継がない** | **`RT-311.11` の (7) だけが落ちる**（**4 / 2 / 2**。**下の測り漏れ**） |

> **5 つめは、最初 1 件も落ちなかった。**
> **預ける payload が、もともと `cnf.jkt` を持っている**ので、
> **書き直さなくても縛りは残る** — **効くのは「縛っていない → 縛る」の乗り換えだけ**だった。
> **そのケース（`RT-311.11` の (7)）を足してから、落ちることを確かめた。**

###### 測っていないこと

| | |
|---|---|
| **成功応答の `DPoP-Nonce`** | **載せていない**（RFC 9449 は SHOULD）。**窓が切れたときに 1 往復増える** |
| **`/register` の `use_dpop_nonce`** | **チャレンジのスキームと `DPoP-Nonce` は付く**が、**error は登録の側が決める**（`invalid_token`） |
| **`nonce` の窓の境目** | **5〜10 分の線そのものは測っていない**（**別の用途の値で断ることだけ**） |
| **インスタンスを増やした配備** | **`DPoPNonceSecret` を揃えれば効く**が、**複数インスタンスは測っていない** |
| **`dpop_jkt` を Request Object（JAR / PAR）で送る経路** | **読むようにしてある**が、**測っていない**（**クエリの経路で測っている**） |
| **デバイス / CIBA の `dpop_jkt`** | **その経路に `dpop_jkt` は無い**（認可要求がブラウザを通らない） |

###### 実測（2026/10/22）

| | 結果 |
|---|---|
| クリーン ビルド | **net48 / net10.0 とも エラー 0 / 警告 0** |
| `RT-311.*`（単独。`mem`） | **24 件 / 成功 24 / 失敗 0**（**段階 1〜4 の 12 ケース × 2 構成**。**nonce を除く**） |
| **`-DPoPNonce`**（`mem`） | **4 件 / 成功 4 / 失敗 0**（`RT-311.13` / `RT-311.14`） |
| `mem`（既定の通し） | **755 件 / 成功 747 / 失敗 0 / Skip 8**（原本 **386 件**。**1 回目で 失敗 0**） |
| **方言（`sql` / `ora` / `npg`）** | **下の節**（**DDL は変えていないが、預ける値が長くなった**） |

###### DDL は増えていないが、方言を回す

**`code` には `dpop_jkt`、`refresh_token` には `cnf.jkt` が入る** ＝ **預ける値が長くなった。**
**Oracle の `Value` は `NVARCHAR2(2000)` 固定**なので、**溢れないことを実機で見る。**

**「DDL が増えたら方言」ではなく、「DB に書く値が変わったら方言」である。**

##### DPoP の証明の使い回しを断る（`RT-311.8` / `RT-311.9`。#311 の段階 3）

| | 測ること |
|---|---|
| **`RT-311.8`** | **一度使った証明は、二度と通らない**（`/userinfo` と `/token` の両方）。**新しい `jti` なら通る。** **検証に通らなかった証明の `jti` は、焼かれない** |
| **`RT-311.9`** | **台帳は鍵ごと**である（**別の鍵が同じ `jti` を使っても、互いを塞がない**） |

###### `RT-311.8` の 6 手

| | 期待 |
|---|---|
| (1) 証明を添えて `/userinfo` | **200** |
| (2) **同じ証明をもう一度** | **401** |
| (3) 新しい `jti` の証明 | **200**（**断りは「使い回し」に対するもので、トークンも鍵も壊れていない**） |
| (4) **`/token` で、同じ証明を 2 回**（**コードは取り直す**） | **1 回目は 200**、**2 回目は `invalid_dpop_proof`（400）** |
| (5) 同じ `jti` で、まず壊れた証明（`htu` が別の口） | **401** |
| (6) **同じ `jti`** で、正しい証明 | **200**（**焼けるのは通った証明だけ**） |

> **(4) でコードを取り直している**のは、**コードの使い回しで断られては、何を測ったのか分からない**ため。
> **(5)(6) は「記録を検証の最後に置いた」ことを測っている** —
> **先に記録すると、壊した証明を投げるだけで相手の `jti` を奪える。**

###### `RT-311.9` は「作りの選択」を測っている

**`jti` だけを台帳の鍵にすると、`jti` の値はクライアントが決めるので、
先に使われた値は他の相手が使えなくなる。**
**EC と RSA の 2 本のトークンで、同じ `jti` を使い**、
**どちらも通ることと、同じ鍵でなら断られることを、並べて見る。**

###### 歯抜け（実測 2026/10/22）

| 壊すもの | 実測 |
|---|---|
| **記録しない**（`TryRecord` が常に true） | **`RT-311.8` と `RT-311.9` の両方が落ちる**（**4 件 / 成功 0 / 失敗 4**）。**`.9` の最後の手（同じ鍵なら断る）も、台帳を見ている** |
| **`jti` だけを台帳の鍵にする** | **`RT-311.9` だけが落ちる**（**4 件 / 成功 2 / 失敗 2**。**「鍵が違えば塞がらない」で 401 になる**） |
| **検証の前に記録する**（`htm` / `htu` / `iat` を見る前） | **`RT-311.8` の「焼けるのは通った証明だけ」だけが落ちる**（**4 件 / 成功 2 / 失敗 2**） |

> **3 つめの歯抜けは、警告が 1〜2 件出る**（`if (false)` の後ろが到達不能になる）。
> **歯抜けの間だけ**なので、そのまま測ってよい。

###### 測っていないこと

| | |
|---|---|
| **窓を過ぎた行が消えること** | **掃除は最初の記録で 1 回走る**（`DELETE` は 3 方言とも流れている）が、**「6 分前の行だけが消える」ことは測っていない**（**時刻を進める手立てが無い**） |
| **同じ `jti` が同時に 2 本来たとき** | **主キーに任せている**が、**競走そのものは測っていない** |
| **インスタンスを増やした配備** | **`mem` では効かない**（**別のプロセスには記録が見えない**）。**表に持てば効く**が、**複数インスタンスは測っていない** |
| **`DPoP-Nonce` / `dpop_jkt` / `refresh_token` の縛り** | **段階 4 で入った**（`RT-311.10`〜`.14`） |

###### 実測（2026/10/22）

| | 結果 |
|---|---|
| クリーン ビルド | **net48 / net10.0 とも エラー 0 / 警告 0** |
| `RT-311.*`（単独。`mem`） | **18 件 / 成功 18 / 失敗 0**（段階 1 の 4 ＋ 段階 2 の 3 ＋ 段階 3 の 2 ケース × 2 構成） |
| `mem`（既定の通し） | **749 件 / 成功 741 / 失敗 0 / Skip 8**（原本 **383 件**。**1 回目で 失敗 0**） |
| **方言（`sql`）** | **18 件 / 成功 18 / 失敗 0** |
| **方言（`ora`）** | **18 件 / 成功 18 / 失敗 0** |
| **方言（`npg`）** | **18 件 / 成功 9 / 失敗 0 / Skip 9**（**net48 は PostgreSQL を使えない**ので、その分は Skip） |

> **方言は回さなければならない**（**表が 1 つ増えている**）。
> **測るのは、新しい表に対する 3 つの口**である —
> **`INSERT`（初回）／ 一意制約の違反 → 存在確認（2 回目）／ `DELETE`（掃除）。**
> **掃除は最初の記録で走る**（前回の掃除の時刻の初期値が最小値）ので、**3 つとも通っている。**

> **パラメタの接頭辞を 1 か所に寄せた** — **Oracle だけ `:` である**。
> **`mem` と SQL Server では `@` のままでも動く**ので、**口ごとに書くと気付かずに残る。**

##### DPoP を保護されたリソースで照合する（`RT-311.5`〜`.7`。#311 の段階 2）

| | 測ること |
|---|---|
| **`RT-311.5`** | **縛ったトークンは、`Authorization: DPoP …` ＋ 証明（`ath` 付き）なら `/userinfo` で使える** |
| **`RT-311.6`** | **出し方を変えると断られる**（**6 通り**）。**最後に、正しい出し方なら また使える** |
| **`RT-311.7`** | **縛っていないトークンは、従来どおり `Bearer` で通る** |

###### `RT-311.6` の 6 通り

| 出し方 | 期待 |
|---|---|
| **`Bearer` で出す**（証明なし） | **401** |
| **`Bearer` で出すが、正しい証明を添える** | **401**（**スキームを見ている**） |
| **`DPoP` スキームだが、証明が無い** | **401** |
| **`ath` が、別のトークンの指紋** | **401** |
| **別の鍵（RSA）で署名した証明** | **401**（**署名は正しく、`cnf.jkt` と合わないだけ**） |
| **`htu` が別の口**（`/token` への証明） | **401** |

> **2 番目は、歯抜けで見つかった測り漏れ**である（下の「歯抜け」）。
> **証明を添えずに `Bearer` で出すのは、証明が無いから落ちる** —
> **スキームを見ているかどうかは、証明を添えて初めて分かる。**

###### 歯抜け（実測 2026/10/21）

| 壊すもの | 実測 |
|---|---|
| **照合しない**（`VerifyDPoPBinding` が常に true） | **`RT-311.6` が落ちる**（**6 件 / 成功 4 / 失敗 2**）。**`RT-311.5` と `RT-311.7` は通ったまま** |
| **`ath` を見ない** | **`RT-311.6` の「`ath` が別のトークン」だけが落ちる**（**6 件 / 成功 4 / 失敗 2**。**検証 3 で止まる**） |
| **スキームを見ない**（`Bearer` でも証明を受け取る） | **`RT-311.6` の「`Bearer` ＋ 正しい証明」だけが落ちる**（**6 件 / 成功 4 / 失敗 2**） |

> **3 つめは、最初は 1 件も落ちなかった** — **その出し方を測っていなかった**ためである。
> **ケースを足してから、落ちることを確かめた。**
> **歯抜けは「テストが何を見ていないか」を見つける道具**でもある。

###### 歯抜けを外したら、必ずビルドし直す

**`inj.py … off` はソースを戻すだけ**である。**戻した後にビルドしないと、
前のバイナリで測ることになる。**

**net48 は、ここで食い違う** — **`dotnet test` は net10.0 側を作り直すが、
IIS Express が配る net48 の出力は、前のビルドのまま**である。
**「core は通るのに netfx だけ落ちる」**という形で出る（**実際に 1 回踏んだ**）。

###### 測っていないこと

| | |
|---|---|
| **`WWW-Authenticate` のスキーム** | **段階 4 で `DPoP` にした**（`RT-311.12`） |
| **`/register` ／ CIBA ／ デバイス ／ 2FA の口** | **同じ判定を通している**が、**測っていない**（**`/userinfo` で測っている**） |
| **縛っていないトークンを `DPoP` スキームで出した場合** | **通る**（**実測 200**。仕様は明示していない）。**観測として記録し、判定にしていない** |
| **`jti` の使い回し** | **段階 3 で入った**（`RT-311.8` / `RT-311.9`） |

###### 実測（2026/10/21）

| | 結果 |
|---|---|
| クリーン ビルド | **net48 / net10.0 とも エラー 0 / 警告 0** |
| `RT-311.*`（単独。`mem`） | **14 件 / 成功 14 / 失敗 0**（段階 1 の 4 ケース ＋ 段階 2 の 3 ケース × 2 構成） |
| `mem`（既定の通し） | **745 件 / 成功 737 / 失敗 0 / Skip 8**（原本 **381 件**。**1 回目で 失敗 0**） |
| 方言（`sql` / `ora` / `npg`） | **回していない** — **DDL も列も増えていない** |

##### DPoP で鍵の持ち主に縛る（`RT-311.1`〜`.4`。#311 の段階 1）

| | 測ること |
|---|---|
| **`RT-311.1`** | **Discovery が `dpop_signing_alg_values_supported` を広告する**（**`ES256` / `RS256` が在り、`none` は無い**）。**mTLS の広告はそのまま** |
| **`RT-311.2`** | **認可コードの `/token` に証明を添えると、`token_type` が `DPoP` になり、`cnf.jkt` が鍵の指紋と一致する** |
| **`RT-311.3`** | **証明が無ければ `bearer`**（`cnf` も無い）。**`refresh_token` の経路でも縛れる** |
| **`RT-311.4`** | **壊した証明は `invalid_dpop_proof`（400）で断る**（**6 通り**）。**断った要求は `refresh_token` を消費していない** |

###### 証明はテスト側で組む

**実装のコードは使わない**（`JwsSigner.SignDPoP`）。
**ヘッダに公開鍵（`jwk`）を入れ、`typ` を `dpop+jwt`** にして、**テスト用クライアントの鍵で署名する**
（既定は **ES256**。`SpRp_EcdsaPfxFilePath`）。

**`cnf.jkt` の期待値も、テスト側で独立に計算する**（`JwsSigner.DPoPJkt`。RFC 7638）。
**DPoP の鍵は登録が要らない** — **その場の鍵で縛られる。**

###### `htu` は広告された値を使う

**サーバは設定から `htu` を作る**ので、**Discovery の `token_endpoint` と同じ値**である。
**テストはそれを `htu` に入れ、叩く先だけ `ToLocalUrl` で読み替える**
（**開発では待ち受けの URL が設定と違うことが在る**）。

###### 壊し方（`RT-311.4`。実測 2026/10/21）

| 壊し方 | 断る根拠 |
|---|---|
| **`typ` が `JWT`** | §4.2（**別の用途の JWT を受けない**） |
| **`htm` が違う**（GET） | §4.3 |
| **`htu` が別の口** | §4.3 |
| **`iat` が古い**（10 分前） | §4.3 |
| **`jti` が無い** | §4.2 |
| **署名が合わない** | §4.3 |

> **`jwk` に秘密鍵が混ざった証明は、測っていない** —
> **ヘッダを後から書き替えると署名が合わなくなり、「署名が合わない」と区別が付かない**ためである
> （**実装では見ている**）。

###### 歯抜け（実測 2026/10/21）

| 壊すもの | 実測 |
|---|---|
| **`cnf` に `jkt` を書かない** | **`RT-311.2` と `RT-311.3` の「`cnf.jkt` が一致する」だけが落ちる**（**8 件 / 成功 4 / 失敗 4**。**`token_type` は `DPoP` のまま** — **印だけ付いて縛れていない状態**） |
| **`htu` を見ない** | **`RT-311.4` の「`htu` が別の口」だけが落ちる**（**8 件 / 成功 6 / 失敗 2**） |
| **`token_type` を切り替えない** | **`RT-311.2` と `RT-311.3` の `token_type` だけが落ちる**（**8 件 / 成功 4 / 失敗 4**。**`cnf.jkt` は入ったまま** — **クライアントが縛られたことに気付けない状態**） |

###### 測っていないこと

| | |
|---|---|
| **保護されたリソースでの照合** | **段階 2 で入った**（`RT-311.5`〜`.7`） |
| **`jti` の使い回し** | **段階 3 で入った**（`RT-311.8` / `RT-311.9`） |
| **`DPoP-Nonce` / `dpop_jkt` / `refresh_token` の縛り** | **段階 4 で入った**（`RT-311.10`〜`.14`） |
| **`iat` の窓の境目** | **5 分（過去）/ 1 分（未来）の線そのものは測っていない**（**10 分前で落ちることだけ**） |
| **device / CIBA の経路** | **証明は受けるようにしたが、測っていない**（**縛る必要が薄い経路**である） |

###### 実測（2026/10/21）

| | 結果 |
|---|---|
| クリーン ビルド | **net48 / net10.0 とも エラー 0 / 警告 0** |
| `RT-311.*`（単独。`mem`） | **8 件 / 成功 8 / 失敗 0**（4 ケース × 2 構成） |
| `mem`（既定の通し） | **739 件 / 成功 731 / 失敗 0 / Skip 8**（原本 **378 件**。**1 回目で 失敗 0**） |
| 方言（`sql` / `ora` / `npg`） | **回していない** — **DDL も列も増えていない**（**トークンの中身と応答だけの変更**） |

##### ブラウザ経由でログアウトを伝える（`RT-310.7`〜`.9`。#310 の段階 3）

| | 測ること |
|---|---|
| **`RT-310.7`** | **Discovery が `frontchannel_logout_supported` と `frontchannel_logout_session_supported` を広告する**。**`check_session_iframe` は出ていない**（Session Management は見送り） |
| **`RT-310.8`** | **`/end_session` が `iframe` の画面を返す**（**302 ではなく 200**）。**URL に `iss` と `sid` が付く**。**その URL を叩くと RP に届く**。**登録が無い RP の `iframe` は無い**。**画面の後は、登録された戻り先へ `state` 付きで進む** |
| **`RT-310.9`** | **`/Account/LogOff` でも画面が出る**。**登録が在る RP が 1 つも無ければ、画面は出ない**（**302 のまま**） |

###### E2E はブラウザの代わりをする

**`HttpClient` は `iframe` を開かない。**
**テストが画面から `src` を取り出して、自分で叩く。**
**叩かれたことは受信箱で見る**（`/Account/FrontChannelLogoutBox`）。

| 口 | |
|---|---|
| `GET /Account/FrontChannelLogoutClient` | **叩かれたことを覚える**（`iss` と `sid`） |
| `GET /Account/FrontChannelLogoutBox` | **覚えているものを返す**（`?clear=true` で空にする） |

> **どちらも `IsLockedDownTestEndpoints` で閉じる。** **閉じている配備では Skip する。**

###### 画面が出る条件に気を付ける

**登録が在る RP が 1 つでも居れば、応答が 302 から 200 に変わる。**
**だから、Back-Channel の測り（`RT-310.5` / `.6`。302 を見ている）とは
別のクライアントを使っている。**

| クライアント | 登録 | ログアウトの応答 |
|---|---|---|
| **`TestClient_26`** | `backchannel_logout_uri` | **302**（従来どおり） |
| **`TestClient_28`** | `frontchannel_logout_uri` | **200**（`iframe` の画面） |

###### 歯抜け（実測 2026/10/21）

| 壊すもの | 実測 |
|---|---|
| **`iframe` を 1 つも出さない** | **`RT-310.8` と `RT-310.9` が落ちる**（**6 件 / 成功 2 / 失敗 4**。**302 が返る**）。**`RT-310.7`（広告）は通ったまま** |
| **`sid` を付けない**（`iss` だけ） | **`RT-310.8` と `RT-310.9` の「sid が id_token と同じ」が落ちる**（**6 件 / 成功 2 / 失敗 4**） |
| **登録を見ずに、全ての相手を `iframe` に入れる** | **`RT-310.8` の「iframe の数」が 2 になり、`RT-310.9` の「登録が無ければ画面が出ない」も落ちる**（**6 件 / 成功 2 / 失敗 4**） |

###### 測っていないこと

| | |
|---|---|
| **本物の `iframe`** | **ブラウザで開いていない**（**テストが URL を叩いている**）。**`display:none` の `iframe` が実際に要求を出すこと自体は、ブラウザの振る舞い**である |
| **進むまでの待ち** | **`meta refresh` の 2 秒は測っていない**（**画面の HTML だけを見ている**） |
| **再認証の経路の画面** | **`prompt=login` / `max_age` / 別のアカウントでログイン**でも同じ口を呼んでいるが、**測っていない**（**登録が在る RP が居るときだけ画面が出る**） |
| **届いたかどうか** | **仕様上、OP には分からない**（`iframe` の中は見えない）。**Back-Channel と補い合う** |

###### 実測（2026/10/21）

| | 結果 |
|---|---|
| クリーン ビルド | **net48 / net10.0 とも エラー 0 / 警告 0** |
| `RT-310.*` ＋ `RT-232.*`（単独。`mem`） | **32 件 / 成功 32 / 失敗 0** |
| `mem`（既定の通し） | **731 件 / 成功 723 / 失敗 0 / Skip 8**（原本 **374 件**。**1 回目で 失敗 0**） |
| `sql`（SQL Server） | **44 件 / 成功 44 / 失敗 0** |
| `ora`（Oracle） | **44 件 / 成功 44 / 失敗 0** |
| `npg`（PostgreSQL） | **44 件 / 成功 22 / 失敗 0 ＋ Skip 22**（netfx は PostgreSQL を使えない。従来どおり） |

> **DDL を変えたので 3 方言とも測る**（**`Saml2OAuth2Data` に列がもう 1 つ**）。
> **`store\0_CopyInitSql.ps1` を回し、コンテナを作り直すこと。**
>
> **`RT-232.*` も一緒に回す** — **「Front-Channel は広告しない」を見ていた検証**を、
> **広告するようになったことに合わせて直した**ためである（#232 の測りの更新）。

##### ログアウトを RP へ伝える（`RT-310.4`〜`.6`。#310 の段階 2）

| | 測ること |
|---|---|
| **`RT-310.4`** | **Discovery が `backchannel_logout_supported` と `backchannel_logout_session_supported` を広告する**（**`frontchannel_logout_supported` は段階 3 で出た** — `RT-310.7`） |
| **`RT-310.5`** | **`/end_session` でサインアウトすると、`backchannel_logout_uri` を登録した RP に `logout_token` が POST される**（**中身も見る**）。**登録が無い RP には届かない** |
| **`RT-310.6`** | **同意画面を出しただけ・拒否された RP には伝えない**（**段階 2 の冒頭で直した**） |

###### 受け口は、このサイト自身である

**Back-Channel Logout は「OP が RP を叩く」**ので、**RP の側に口が無いと測れない。**
**E2E のクライアントは HTTP サーバを持たない**ので（#309 で `jwks_uri` の足場を
別のコンテナにしたのと同じ事情）、**このサイトが自分の RP も兼ねる**
（`test_self_code` と同じ考え方）。

| 口 | |
|---|---|
| `POST /Account/BackChannelLogoutClient` | **受け取って覚える**（プロセス内。20 件まで） |
| `GET /Account/BackChannelLogoutBox` | **覚えているものを返す**（`?clear=true` で空にする） |

> **どちらも `IsLockedDownTestEndpoints` で閉じる。** **閉じている配備では Skip する。**
> **測る前に受信箱を空にする**（前のケースの通知が混ざらないように）。

###### 通知は背景で送られるので、待つ

**要求の経路では待たない**（net48 では同期の要求スレッドで待つと詰まる。#309 の起票）。
**サインアウトの応答が返った後に届く**ので、**届くまで待つ**（最大 15 秒）。

> **netfx 版では、1 回目の送信に 10 秒を超えることが在った**（実測）。
> **`HttpClient` の初回の接続**（TLS・プロキシの判定）が乗るためと見ている。

###### logout_token の何を見るか

| | |
|---|---|
| **`aud`** | **登録した RP の `client_id`** |
| **`sid`** | **その RP の `id_token` と同じ値**（**違えば、RP はどのセッションか分からない**） |
| **`sub` / `jti` / `iss`** | **在ること** |
| **`events`** | **`http://schemas.openid.net/event/backchannel-logout` が在ること** |
| **`nonce`** | **無いこと**（**入っていると `id_token` と見分けが付かず、RP でサインインに使われる恐れが在る**） |
| **ヘッダ** | **`typ` が `logout+jwt`**、**`kid` が在る** |

> **署名の検証はしていない。** **鍵は `id_token` と同じ**（`kid` も同じ引き方）なので、
> **`/jwkcerts` で検証できることは `RT-302.*` が押さえている。**

###### 歯抜け（実測 2026/10/21）

| 壊すもの | 実測 |
|---|---|
| **伝えない**（`NotifyBySession` で何もしない） | **`RT-310.5` と `RT-310.6` が落ちる**（**6 件 / 成功 2 / 失敗 4**）。**`RT-310.4`（広告）は通ったまま** — **広告と実装が食い違っていても、広告だけでは分からない** |
| **`logout_token` に `nonce` を入れる**（MUST NOT） | **`RT-310.5` の「nonce は入っていない」だけが落ちる**（**6 件 / 成功 4 / 失敗 2**） |
| **台帳への書き込みを、認可の分岐の手前に戻す**（段階 1 の形） | **`RT-310.6` だけが落ちる**（**6 件 / 成功 4 / 失敗 2**。**実測値まで出る** : `届いた（トークンを受けていない相手に伝えている）`） |
| **消してから伝える**（`ClearOpSession` の順序を逆にする） | **`RT-310.5` と `RT-310.6` が落ちる**（**6 件 / 成功 2 / 失敗 4**。**届いた数が 0**）。**「消す前に読む」が効いていることの裏返し**である |

###### 測っていないこと

| | |
|---|---|
| **再送** | **しない**（仕様も求めていない）。**届かなかった RP がどうなるかは測っていない** |
| **応答しない RP** | **1 件 10 秒で諦める**（**背景なので、ログアウトの応答は待たされない**）。**その待ちは測っていない** |
| **`op_session` が無いときの送り返し** | **`op_session_retry` の印で 1 回だけ送り返す**（#310 の段階 2 の冒頭）。**同時に 2 本来る競合そのものは測っていない** |
| **Front-Channel Logout** | **段階 3。** **広告していないことは `RT-310.4` で見ている** |

###### 実測（2026/10/21）

| | 結果 |
|---|---|
| クリーン ビルド | **net48 / net10.0 とも エラー 0 / 警告 0** |
| `RT-310.*`（単独。`mem`） | **12 件 / 成功 12 / 失敗 0**（段階 1 の 3 ケース ＋ 段階 2 の 3 ケース × 2 構成） |
| `mem`（既定の通し） | **725 件 / 成功 717 / 失敗 0 / Skip 8**（原本 **371 件**。**1 回目で 失敗 0**） |
| `sql`（SQL Server） | **38 件 / 成功 38 / 失敗 0** |
| `ora`（Oracle） | **38 件 / 成功 38 / 失敗 0** |
| `npg`（PostgreSQL） | **38 件 / 成功 19 / 失敗 0 ＋ Skip 19**（netfx は PostgreSQL を使えない。従来どおり） |

> **DDL を変えたので 3 方言とも測る**（**`Saml2OAuth2Data` に列が 1 つ増えた**）。
> **`store\0_CopyInitSql.ps1` を回し、コンテナを作り直すこと。**
>
> **流したのは `BackChannelLogoutTests` ＋ `SessionIdTests` ＋ 登録の画面**
> （`ManageSaml2OAuth2DataTests`）**＋ 利用者の削除**（`ManageGdprTests` / `UsersAdminTests`）。
> **増えた列は `DataProvider` の INSERT / SELECT / UPDATE に入る**ので、
> **DDL が揃っていなければ、クライアント登録の書き込みが全部落ちる**
> （**種データの投入で落ちるため、サイトが上がらない**）。
>
> **回すときは 1 つずつ、間でサイトを止めること。**

##### `sid`（OP のセッションの識別子）を `id_token` に出す（`RT-310.*`。#310 の段階 1）

| | 測ること |
|---|---|
| **`RT-310.1`** | **`id_token` に `sid` が出る**。**同じセッション・同じ RP なら 2 回目も同じ値**（**台帳から引けている**）。**`refresh_token` で取り直しても同じ** |
| **`RT-310.2`** | **同じセッションでも、RP ごとに別の値**（**`pairwise` の `sub` を分けた意味を消さない**） |
| **`RT-310.3`** | **サインアウトして入り直すと、同じ RP でも変わる**（**セッションを識別している**） |

###### 値そのものは見ない

**`sid` は guid** で、**意味を持たない。** **測るのは「同じか、違うか」だけ**である
（**報告にも値を出さない** — **どの RP に何を名乗ったかは、配備の情報**である）。

###### 台帳（`SessionClient`）の確かめ方

| | |
|---|---|
| **引けていること** | **`RT-310.1` の (2)** が、それである（**引けなければ 2 回目が別の値になる**） |
| **RP ごとに行が在ること** | **`RT-310.2`**（**行ごとに別の `sid`**） |
| **消していること** | **E2E では見えない** — **新しいセッションでは、どの行も引かれない**ため。**SQL が通ることは、方言の通しで確かめる**（**段階 2 では、消す順序が測れる** — **消してから伝えると `RT-310.5` が落ちる**。歯抜けで実測した） |
| **DDL** | **`SessionClient` 表が増えている**ので、**方言の通しが要る**（`dialects.ps1`） |

###### 歯抜け（実測 2026/10/21）

| 壊すもの | 実測 |
|---|---|
| **台帳から引かず、毎回新しい `sid` を作る** | **`RT-310.1` だけが落ちる**（core / netfx の 2 件。**2 回目が別の値になる**）。**6 件 / 成功 4 / 失敗 2** |
| **RP ごとに分けず、セッションの識別子をそのまま `sid` にする** | **`RT-310.2` だけが落ちる**（2 件。**2 つの RP に同じ値が出る**）。**6 件 / 成功 4 / 失敗 2** |
| **サインアウトで台帳を消さない**（Cookie だけ落とす） | **どのケースも落ちない**（**6 件 / 成功 6**）。**上の「消していること」の裏返し**である — **新しいセッションでは、残った行が引かれない**ので、**外からは区別できない** |

###### 測っていないこと

| | |
|---|---|
| **掃除** | **10 分間隔で、`AuthCookieExpiresFromHours` ＋ 1 日より古い行を消す**（`CONFIGURATION.md`）。**E2E で 1 日待たない** |
| **Front-Channel / Back-Channel Logout** | **Back-Channel は段階 2**（`RT-310.4`〜`.6`）、**Front-Channel は段階 3**（`RT-310.7`〜`.9`）**で入った**。**`RT-232.1` の「広告しない」を見ていた検証は、広告するようになったことに合わせて直した** |
| **`sid` が入らない経路** | `grant_type=password` / `client_credentials` / CIBA / Device（**ブラウザのセッションを経ていない**）。**クレームを付けないことは、実装では決めてあるが測っていない** |

###### 実測（2026/10/21）

| | 結果 |
|---|---|
| クリーン ビルド | **net48 / net10.0 とも エラー 0 / 警告 0** |
| `RT-310.*`（単独。`mem`） | **6 件 / 成功 6 / 失敗 0**（3 ケース × 2） |
| `mem`（既定の通し） | **719 件 / 成功 711 / 失敗 0 / Skip 8**（原本 **368 件**。**1 回目で 失敗 0**） |
| `sql`（SQL Server） | **20 件 / 成功 20 / 失敗 0** |
| `ora`（Oracle） | **20 件 / 成功 20 / 失敗 0** |
| `npg`（PostgreSQL） | **20 件 / 成功 10 / 失敗 0 ＋ Skip 10**（netfx は PostgreSQL を使えない。従来どおり） |

> **DDL を変えたので 3 方言とも測る**（**表 1 つ ＋ 一意索引 1 つ ＋ 索引 1 つ ＋ 外部キー 1 つ**）。
> **`store\0_CopyInitSql.ps1` を回し、コンテナを作り直すこと**（**新しい DDL で初期化される**）。
>
> **流したのは `SessionIdTests` ＋ 利用者の削除**（`ManageGdprTests` / `UsersAdminTests`）。
> **新しい表は `Users.Id` への外部キー（`ON DELETE CASCADE`）を持つ** ＝ **「跨いで書く変更」**なので、
> **削除の経路も方言で測る**（上の「`Users` と `Saml2OAuth2Data` を跨ぐ変更は…」と同じ理由）。
>
> **回すときは 1 つずつ、間でサイトを止めること**（#307 の段階 3・4 で踏んだメモリ不足）。

##### 発行者の台帳を DB ＋ 画面で持つ（`RT-308.*`。#308）

| | 測ること |
|---|---|
| **`RT-308.1`** | **画面から足して・直して・消せる**（一覧に出る／直した表示名と上限が出る／消えると一覧から消える） |
| **`RT-308.2`** | **DB に PEM を貼った発行者の statement で、登録が通る**（**`CerFilePath` は空** ＝ **本文だけで検証**）／**台帳から消すと、その場で `unapproved_software_statement` に変わる** |
| **`RT-308.3`** | **設定ファイルに在る鍵は、画面から足せない**（**同じ鍵なら設定が勝つ**）／**設定の行は、この画面に出ない** |

**鍵（`IssuerKey`）は対象ごとに分ける**（`e2e_rt308_core` / `…_netfx`）—
**DB ストアでは 2 つのサイトが 1 つの DB を共有する**ので、**同じ鍵だと奪い合う**（#260 と同じ事情）。

**署名する鍵と、貼る証明書は、構成ファイルに在る対を使う**
（**`RsaPfxFilePath` ↔ `SpRp_RsaCerFilePath`**。どちらも `SHA256RSA_Server`）。
**`SpRp_RsaPfxFilePath`（Client.pfx）とは対になっていない**ので、取り違えないこと。

###### 歯抜け（実測 2026/10/21）

| 壊すもの | 実測 |
|---|---|
| **DB を読まない**（`Co.SoftwareStatementIssuers.List()` が設定だけを返す） | **`RT-308.2` が落ちる**（core / netfx の 2 件。**登録が `201` ではなく `400`**）。**6 件 / 成功 4 / 失敗 2** |
| **PEM を解析しない**（貼られた本文を 1 本の Base64 として扱う） | **`RT-308.2` が落ちる**（2 件。**同じ手順**）。**6 件 / 成功 4 / 失敗 2** |
| **設定の鍵との重複を見ない**（`IsInSetting` が常に false。両アプリ） | **`RT-308.3` が落ちる**（2 件。**再表示されず `302` で足せてしまう**）。**6 件 / 成功 4 / 失敗 2** |

> **上の 2 つは、同じケースの同じ手順で落ちる** —
> **`RT-308.2` が「DB の読み」と「PEM の解析」の両方を通っている**ことの裏返しである。

###### 踏んだこと : テストが後片付けをしていなかった

**歯抜け（重複を見ない）を入れたら、設定と同じ鍵の行が実際に作られた。**
**`RT-308.3` はそれを消していなかった。**

| | |
|---|---|
| なぜ気付きにくいか | **`mem` では消える**（サイトを落とせば消える）。**DB ストアでだけ残る** |
| 直し | **`finally` で消す**（**作ったテストが、同じテストの中で消す**） |

**測っていないもの。**

| | |
|---|---|
| **`CerBody` に Base64（DER）を貼る形** | **PEM で測っている**（**解析は同じ 1 か所**だが、**Base64 の側は未測定**） |
| **本文とパスを混ぜたとき**（入れ替えの途中） | **実装は「本文 → パス」の順**だが、**E2E では測っていない** |
| **`CerBody` が壊れているとき** | **その鍵を飛ばして次を試す**ことは実装したが、**測っていない** |
| **画面の認可**（`SystemAdmin` でなければ開かない） | **`RT-257.9` が `UsersAdmin` で測っている**のと同じ門番だが、**この画面では測っていない** |

**実測（2026/10/21）。**

| | 結果 |
|---|---|
| クリーン ビルド | **net48 / net10.0 とも エラー 0 / 警告 0** |
| `RT-308.*`（単独。`mem`） | **6 件 / 成功 6 / 失敗 0**（3 ケース × 2） |
| `mem`（既定の通し） | **705 件 / 成功 697 / 失敗 0 / Skip 8**（原本 **361 件**） |
| `sql`（SQL Server） | **57 件 / 成功 55 / 失敗 0 / Skip 2** |
| `ora`（Oracle） | **57 件 / 成功 55 / 失敗 0 / Skip 2** |
| `npg`（PostgreSQL） | **57 件 / 成功 29 / 失敗 0 / Skip 28**（netfx は PostgreSQL を使えない。従来どおり） |

> **方言は `RT-307.*` ＋ `RT-308.*` を流した** — **表を足した影響は、
> `software_statement` の既存の経路にも出得る**ためである。

> **表を新設したので、3 方言とも DB を作り直して測る**（`store\0_CopyInitSql.ps1` → コンテナを作り直し）。
> **回すときは 1 つずつ、間でサイトを止めること**（#307 で踏んだメモリ不足）。
> **回し終えた方言のコンテナも止めること**（上の「表を足したら」の囲みと同じ）。

##### 発行者ごとの上限と、鍵の入れ替え（`RT-307.25` / `.26`。#307 の段階 6）

| | 測ること |
|---|---|
| **`RT-307.25`** | **範囲内の `scope` は通る**／**範囲外を主張すると `unapproved_software_statement`**／**本文（plain JSON）に書いても同じく断る**／**`PUT`（RFC 7592）でも効く** |
| **`RT-307.26`** | **1 本目の鍵で署名した statement は通る**／**2 本目の鍵でも通る**（**入れ替えの間**）／**どちらでもない鍵は `invalid_software_statement`** |

**`test.ps1` が渡すもの**（**サイトへ渡した値と、同じ値をテストへ渡す**）。

| | 値 |
|---|---|
| **上限** | **`allowed_scope` = `openid email`** ／ **`allowed_grant_types` = `authorization_code refresh_token urn:ietf:params:oauth:grant-type:device_code`** |
| **証明書 2 本** | **`SHA256RSA_Client.cer`**（`SpRp_RsaPfxFilePath` の対）＋ **`SHA256RSA_Server.cer`**（`RsaPfxFilePath` の対） |
| しるし | `MPAS_SOFTWARE_STATEMENT_ALLOWED_SCOPE` ／ `MPAS_SOFTWARE_STATEMENT_ROLLOVER`（**無ければ Skip**） |

> **上限は、既存のケースが登録する範囲までに絞ってある** —
> **`RT-307.*` が登録するのは `openid` と `openid email` だけ**（実測で確かめた）。
> **広く取ると「範囲の外」に当たる scope が無くなり、`RT-307.25` が Skip になる**（実測で踏んだ）。

###### 踏んだこと : 鍵は「配備側に配られているもの」から選ぶ

**最初 `SHA256RSAClientCert.cer` を 2 本目に選んだが、2 本目の鍵で署名した statement が通らなかった。**

| | |
|---|---|
| 何が起きていたか | **その `.cer` は、リポジトリには在るが `C:/root/files/resource/X509` に配られていない** |
| なぜ気付きにくいか | **`.pfx` は配られている**ので、**テスト側の署名は成功する**。**サイト側だけが検証できない** |
| 直し | **配備側に在る `SHA256RSA_Server.cer`（`RsaPfxFilePath` の対）に替えた** |

> **サイトが読むのは配備側**である。**リポジトリに在ることは、配られていることを意味しない。**

###### 踏んだこと : `test.ps1` の行継続

**行末が文字列のまま、次の行を `+` で始めると、PowerShell は構文エラーになる**
（**テストの起動ごと失敗する**）。**行末に `+` かバッククォートを置くこと。**

> **`.ps1` は、変更したら実行すること**（`CODING.md` 5 節）。**読んでも分からない。**

###### 歯抜け（実測 2026/10/20）

| 壊すもの | 実測 |
|---|---|
| **発行者の上限を見ない**（`allowed_scope` を常に空として扱う） | **`RT-307.25` の (2) で落ちる**（core / netfx の 2 件。**範囲外の主張が `201`**）。**51 件 / 成功 47 / 失敗 2 / Skip 2** |
| **鍵を 1 本目しか試さない** | **`RT-307.26` の (2) で落ちる**（2 件。**2 本目の鍵で署名した statement が `400`**）。**51 件 / 成功 47 / 失敗 2 / Skip 2** |
| **本文（plain JSON）由来の値を見ない**（statement のクレームだけ見る） | **`RT-307.25` の (3) で落ちる**（2 件。**本文に書けば通ってしまう**）。**51 件 / 成功 47 / 失敗 2 / Skip 2** |

> **上の 2 本は、同じケースの別の手順で落ちている** —
> **`RT-307.25` が「statement 由来」と「本文由来」の両方を見ていること**の裏返しである。

**測っていないもの。**

| | |
|---|---|
| **`allowed_grant_types` の範囲外** | **実装は `scope` と同じ 1 か所**（`IsWithin`）だが、**測ったのは `scope` だけ** |
| **鍵が 3 本以上のとき** | **2 本で測っている**（**順に試す作り**なので、本数で振る舞いは変わらない） |
| **読めない証明書が混ざったとき** | **他の鍵を試す**ことは実装したが、**E2E では測っていない**（**配備側に在る鍵だけを渡している**） |
| **管理画面からの書き替えの監査ログ** | **ログに残すことは実装した**が、**E2E からサイトのログを読む仕掛けが無い**ので測っていない |

**実測（2026/10/20）。**

| | 結果 |
|---|---|
| クリーン ビルド | **net48 / net10.0 とも エラー 0 / 警告 0** |
| `RT-307.*`（単独。`mem`） | **51 件 / 成功 49 / 失敗 0 / Skip 2**（**26 ケース × 2 − 1**。`RT-307.15` は netfx のケースを作らない。**Skip は `.23` / `.24` の netfx**） |
| `mem`（既定の通し） | **699 件 / 成功 691 / 失敗 0 / Skip 8**（原本 **358 件**） |
| `sql`（SQL Server） | **51 件 / 成功 49 / 失敗 0 / Skip 2** |

> **DDL は変えていない**（**列を 1 つも足していない**）ので、**`ora` / `npg` は取り直していない。**

##### `client_credentials` 経路（`RT-307.22` 〜 `.24`。#307 の段階 5-b）

**利用者のパスワードを使わずに登録する経路**を測る。

| | 測ること |
|---|---|
| **`RT-307.22`** | **画面で作ったクライアント**（`scope` 入り）**で `client_credentials` → 登録でき、所有者はそのクライアントの所有者**／**scope は専用 scope 1 本**／**所有者の利用者名を変えても切れない** |
| **`RT-307.23`** | **構成ファイルの `owner`（利用者名）から所有者が決まる**（**その人の管理画面の一覧に出る**） |
| **`RT-307.24`** | **所有者の決まらないクライアントでは `403` ＋ `access_denied`**（**トークン自体は取れる** — 止まるのは `/register` の側） |

###### `RT-307.23` / `.24` は net48 では Skip する

**構成ファイル発のクライアントを、`test.ps1` が net10.0 版にだけ渡している**ためである。

| | |
|---|---|
| **net10.0** | **設定を「節」として読む**ので、**クライアントを 1 件ずつ足せる**（`appSettings__OAuth2ClientsInformation__<id>__<属性>`） |
| **net48** | **1 本の JSON 文字列**なので、**足すと雛形の 7 件を全て置き換えてしまう** |

**`RT-307.15` と同じ作法**である（**片方だけのケースを作る**）。
**しるしは対象ごとに置く**（`MPAS_CORE_DCR_CC_*`）。
**process 全体に置くと、net48 のケースも「渡された」と見なして落ちる**（実測で踏んだ）。

###### `RT-307.22` は、わざと利用者名を変える

**これを挟まないと、新しい道を測れない**（**歯抜けで気付いた**）。

| | |
|---|---|
| なぜか | **登録の `ClientName` には所有者の利用者名が入る**（段階 5-a）。**`client_credentials` の `sub` は `ClientName`** なので、**`sub` から利用者が引けてしまう** — **「クライアントの所有者から引く」道を通らない** |
| 直し | **登録を作った後に、所有者の利用者名を変える。** **`ClientName` は古い名前のまま残る**（**ラベルだから**）ので、**`OwnerUserId` から引く道だけが残る** |
| おまけ | **「利用者名を変えても切れない」という段階 5-a-1 の主張**を、**正面から測ることになった** |

###### 歯抜け（実測 2026/10/20）

| 壊すもの | 実測 |
|---|---|
| **構成ファイルの `owner` を見ない**（常に空を返す） | **`RT-307.23` だけが落ちる**（core の 1 件。netfx は Skip）。**47 件 / 成功 44 / 失敗 1 / Skip 2** |
| **クライアントの所有者を引かない**（段階 5-a の振る舞いに戻す） | **`RT-307.22`（core / netfx の 2 件）と `RT-307.23`（1 件）が落ちる**。**47 件 / 成功 42 / 失敗 3 / Skip 2** |
| **断り方を `401` ＋ `invalid_token` に戻す** | **`RT-307.24` だけが落ちる**（1 件）。**47 件 / 成功 44 / 失敗 1 / Skip 2** |

> **`RT-307.22` は、最初この歯抜けで落ちなかった**（上の「わざと利用者名を変える」）。
> **歯抜けを 1 本ずつ入れていて気付いた**ので、**ケースを直してから測り直した。**

###### `EnableClientCredentialsGrantType` を false にして 1 本

**「グラントを閉じていても、専用 scope のトークンは出る」**ことを測った（**別に 1 本回す**）。

| | 実測（2026/10/20） |
|---|---|
| 通し全体 | **695 件 / 成功 660 / 失敗 27 / Skip 8** |
| **`RT-307.22` / `.23` / `.24`** | **すべて成功**（`.22` は core / netfx とも。`.23` / `.24` は core。netfx は Skip） |

> **失敗は、すべて `client_credentials` を他の目的で使っているケース**である
> （`TC-5.*` / `RT-198.1` / `RT-198.3` / `RT-237.*` / `RT-196.*` / `RT-129.1` / `RT-245.5` /
> `RT-262.1` / `FA-6.3`）。**グラントを閉じたのだから、落ちるのが正しい。**
>
> **この 1 本は「細い道が通ること」を見るための測定**で、**通しの合否としては採らない**
> （**雛形の既定は `true`**）。

**測っていないもの。**

| | |
|---|---|
| **`owner` の利用者が居ない場合** | **実装は `403` に倒す**（**`GetOwnerUserId` が空を返す**）が、**E2E では測っていない**（**`RT-307.24` は「`owner` を書いていない」側**で測っている） |
| **ROPC を閉じた配備** | **`EnableResourceOwnerPasswordCredentialsGrantType=false` では、`RT-307.*` の大半が Skip になる**（**前提の口が無い**）ので、**その形では回していない** |
| **net48 の構成ファイル発のクライアント** | **渡す仕掛けが無い**（上の表）。**実装は同じ 1 か所**（`Helper.GetOwnerUserId`）である |

**実測（2026/10/20）。**

| | 結果 |
|---|---|
| クリーン ビルド | **net48 / net10.0 とも エラー 0 / 警告 0** |
| `RT-307.*`（単独。`mem`） | **47 件 / 成功 45 / 失敗 0 / Skip 2**（**24 ケース × 2 − 1**。`RT-307.15` は netfx のケースを作らない。**Skip は `.23` / `.24` の netfx**） |
| `mem`（既定の通し） | **695 件 / 成功 687 / 失敗 0 / Skip 8**（原本 **356 件**。**Skip は従来の 6 件 ＋ `.23` / `.24` の netfx 2 件**） |
| `sql`（SQL Server） | **47 件 / 成功 45 / 失敗 0 / Skip 2** |

> **DDL は変えていない**（**列を 1 つも足していない**）ので、**`ora` / `npg` は取り直していない。**

##### 管理画面の一覧（`RT-277.9` 〜 `.11`。#307 の段階 5-a-2）

**画面から n 件を扱えるようにした分**を測る。

| | 測ること |
|---|---|
| **`RT-277.9`** | **画面から 2 件登録でき、一覧に 2 件とも出る**／**並びは `client_id` の昇順**／**2 件目を指して編集でき、1 件目は変わらない**／**編集では `client_id` を作り直すボタンが出ない** |
| **`RT-277.10`** | **自分の物でない `client_id` では、編集画面が開かない**（**種データのクライアント** ＝ 所有者が居ない行で測る）／**在りもしない `client_id` でも同じように断る**／**削除も通らず、その行は残る** |
| **`RT-277.11`** | **一覧から 1 件だけ消せる**（**残りは残る**）／**消した行は、もう開けない** |

**`RT-277.*` は共用のテスト利用者で測る**（**利用者はターゲットごとに分かれている**。#260）。
**同じクラスのケースは順に走る**ので、**互いに登録を奪い合わない** —
**別のクラスの `RT-305.4` や `RT-277.8` は、使い捨ての利用者に移してある**（#305 の段階 3）。

###### 画面の形（段階 5-a-1 からの差）

| | 段階 5-a-1 | **段階 5-a-2** |
|---|---|---|
| `/Manage/Index` | **「追加 / 変更 ＋ 削除」を出し分ける** | **件数 ＋ 一覧への導線 1 本**（**削除は一覧の行から**） |
| 一覧 | **無い** | **`/Manage/Saml2OAuth2DataList`**（`ConsentGrants` と同じ流儀） |
| 編集 | **所有者の先頭 1 件を黙って出す** | **`?clientId=…` で指す**（**所有者で照合** — 他人の行は `Error` 画面） |
| 保存 | **`client_id` が違えば、古い 1 件を消して作る** | **自分の持ち物なら更新、無ければ作成**（**古い行は消さない**） |
| 削除 | **引数なし。先頭 1 件を消す** | **行から `clientId` を渡す**（**空では何も消さない**） |

> **`client_secret` は一覧に出さない。**
> **行の VM（`Saml2OAuth2DataRowViewModel`）が、その値を持っていない** —
> **出し忘れでは防げない**ので、**器ごと分けてある**（`registration_access_token` も同じ）。

###### 歯抜け（実測 2026/10/20）

| 壊すもの | 実測 |
|---|---|
| **`GetByOwnerAndClientID` が所有者を照合しない**（誰の登録でも返す） | **`RT-277.10` だけが落ちる**（core / netfx の 2 件）。**12 件 / 成功 10 / 失敗 2** |
| **`GetByOwner` が所有者で絞らない**（全件返す） | **12 件 / 成功 4 / 失敗 8**（`RT-277.1` / `.9` / `.10` / `.11` / `RT-297.1`）。**捕まえるが、狙いは絞れていない** — **他人の行が何件混ざるかは回ごとに変わる**ので、**落ちる組み合わせも変わる** |
| **削除が `clientId` を見ない**（先頭 1 件を消す ＝ 段階 5-a-1 の振る舞い） | **`RT-277.11` だけが落ちる**（2 件）。**12 件 / 成功 10 / 失敗 2** |

> **この 3 本が、ケースの穴を 2 つ見つけた。** **どちらも、直す前は 1 件も落ちなかった。**
>
> | 穴 | 直し |
> |---|---|
> | **`RT-277.10` が「種データのクライアント」で測っていた** | **あれは構成ファイル発で、`Saml2OAuth2Data` に行が無い** — **照合しなくても null になる。** **「他人の行」は、本当に行が在る物でなければ測れない** → **使い捨ての利用者に、本物の登録を作らせた** |
> | **`RT-277.11` が「登録した順の 1 件目」を消していた** | **一覧の並びは `client_id` の昇順**なので、**たまたま一致すると、先頭を消す歯抜けと食い違わない** → **一覧の 2 行目を消す**ようにした |

###### 踏んだこと : ケースの番号が衝突すると、原本から押し出される

**足したケースに `RT-277.3` 〜 `.5` を付けたが、その番号は既に使われていた**
（**WebAuthn の資格情報の削除・利用者名の変更・パスワードの変更**）。

| | |
|---|---|
| **何が起きたか** | **原本は id で畳む**ので、**新しいケースが既存の 3 件を押し出した**（**原本から 3 件消えた**） |
| **なぜ気付きにくいか** | **テストは 689 件すべて通る。** **押し出された 3 件も走っている** — **原本にだけ出てこない** |
| **気付いた手がかり** | **「原本を作り直しました（350 件）」が増えていなかった**（**3 件足したのに同じ件数**）。**`git diff` で消えた見出しが見えた** |
| 直し | **`RT-277.9` 〜 `.11` に付け替えた**（**`.1` 〜 `.8` は埋まっていた**） |

> **番号は、ファイルをまたいで 1 つの空間である。**
> **`RT-277.*` は 5 つのファイルに散っている**（この画面・GDPR・属性・WebAuthn ×2）。
> **足す前に `grep -o "RT-277\.[0-9]*"` で空き番を見ること。**
>
> **件数が増えることを確かめるのが、いちばん安い検算**である。

**測っていないもの。**

| | |
|---|---|
| **ページング・並び替え・検索** | **実装していない**（**上限を設けていない**ので、**件数が増えたときの見え方は測れない**） |
| **自分と他人が、同時に n 件持つときの一覧** | **`RT-277.10` は「他人の 1 件が混ざらないこと」まで**（**使い捨ての利用者に本物の登録を作らせて見る**）。**両方が複数持つ形では測っていない** |
| **`client_secret` の作り直し**（編集中に押す） | **ボタンは出したまま**だが、**押した後の往復は測っていない**（`RT-297.1` は新規の経路で測る） |

**実測（2026/10/20）。**

| | 結果 |
|---|---|
| クリーン ビルド | **net48 / net10.0 とも エラー 0 / 警告 0** |
| `RT-277.*` ＋ `RT-297.1`（単独。`mem`） | **12 件 / 成功 12 / 失敗 0**（**6 ケース × 2**） |
| `mem`（既定の通し） | **689 件 / 成功 683 / 失敗 0 / Skip 6**（原本 **353 件**。**Skip は従来の 6 件のまま**） |
| `sql`（SQL Server） | **12 件 / 成功 12 / 失敗 0** |

> **DDL は変えていない**（**列を 1 つも足していない**）ので、**`ora` / `npg` は取り直していない。**
> **`sql` を回すのは、画面の作成・更新・削除が制約の在る側でも通ることを見るため**である。

##### クライアントあたり複数 `redirect_uri`（`RT-306.*`。#306）

| | 測ること |
|---|---|
| **`RT-306.1`** | **2 件登録して、どちらの `redirect_uri` でも認可コードが取れる**／**折り返し先が、指定したほうになる** |
| **`RT-306.2`** | **登録に無い `redirect_uri` は通らない**／**登録値の接頭辞も通らない**（前方一致にしていない） |
| **`RT-306.3`** | **2 件登録のとき、`redirect_uri` の省略は通らない** |

**使い捨ての利用者で測る**（`UsersAdmin` で作って消す。**ロールは `Admin`**）。
**当時はクライアント登録が 1 人 1 件**だったので、
**共用の利用者で登録すると、`RT-277.1` や `RT-305.4` と登録を奪い合った**（#305 の段階 2 で踏んだ）。

> **#307 の段階 5-a-1 で 1 人 n 件になったので、「奪い合って消える」形では起きない。**
> **それでも使い捨てのままにする** — **管理画面が扱うのは所有者の先頭 1 件**なので、
> **共用の利用者に登録を増やすと、画面を使うケースがどれを引くか決まらない。**

> **登録する値は `ManageClientRegistration.RegisterWithSecretAsync` の
> 「項目を差し込める」多重定義で入れる**（#306 で足した）。
> **画面から拾ったフォームの値を、「追加」の直前に置き換える**だけなので、
> **画面が出していない項目は差し込めない。**

> **「1 件登録なら省略できる」（下位互換）は、この一式では測らない。**
> **既存のケースの大半が、まさにその経路で回っている** —
> **`Flows.AuthorizeCodeAsync` は `redirect_uri` を既定で送らない。**
> **通しが失敗 0 であること自体が、その確認になっている。**

**歯抜け（実測 2026/10/18）。**

| 壊すもの | 期待する結果 |
|---|---|
| `CheckRedirectUri` の照合を **1 本目だけ**にする（= 以前の振る舞い） | **`RT-306.1` だけが落ちる**（core / netfx の 2 件。**2 本目の `redirect_uri` で `code` が返らない** / 実測 = 「返らない（`error` も無し）」）。**`RT-306.2` / `.3` は通ったまま**（6 件 / 成功 4 / 失敗 2） |

**実測（2026/10/18）。**

| | 結果 |
|---|---|
| `RT-306.*`（単独） | **6 件 / 成功 6 / 失敗 0**（3 ケース × core / netfx） |
| `mem`（既定の通し） | **642 件 / 成功 636 / 失敗 0 / Skip 6**（原本 **329 件**。**Skip は従来の 6 件のまま**） |
| `sql`（SQL Server） | **6 件 / 成功 6 / 失敗 0** |
| `ora`（Oracle） | **6 件 / 成功 6 / 失敗 0** |
| `npg`（PostgreSQL） | **6 件 / 成功 3 / 失敗 0 / Skip 3**（netfx は PostgreSQL を使えない。従来どおり） |

> **3 方言は、新しい DDL が流れた状態で測っている。**
> **列の幅を広げた変更なので、`mem` の通しだけでは何も確かめられない** —
> **`mem` では `Create_UserStore.sql` が流れない。**
>
> **`oracle` と `postgres` は、コンテナを作り直さないと `init` が流れない**（再起動では流れない）。
> **`0_CopyInitSql.ps1` で新しい DDL を置いてから、コンテナを消して回した。**
> **`docker compose rm` には必ずサービス名を付けること** —
> **付けないと、止めてある IdP の 3 コンテナまで消える**（実測で踏んだ）。

##### 断りを送信元ごとにし、`/token` のパスワードも数える（`RT-305.7` / `RT-305.8`。#305 の段階 4）

| | 測ること |
|---|---|
| **`RT-305.7`** | **クライアント認証の断りが、失敗を重ねた送信元だけに効く** — **別の送信元は、同じ `client_id` でも通る**／**待てば元の送信元も通る** |
| **`RT-305.8`** | **`/token` の `grant_type=password` を上限まで間違えると、正しいパスワードでも `access_denied`**／**待てば `access_token` が出る** |

**`RT-305.7` は、`X-Forwarded-For` で送信元を名乗って測る。**
**E2E は 1 台のホストから回る**ので、**送信元を変える手が他に無い。**

| | |
|---|---|
| **net10.0 版だけ** | **net48 版は転送ヘッダを戻さない**（`Request.UserHostAddress` そのまま） |
| **既定の通しでは Skip** | **通しは `UseForwardedHeaders` を off で回る**ので、**どの回も送信元が 127.0.0.1 になり、鍵が分かれない** |

**`RT-305.7` は単独で回して測る。**

```powershell
$env:UseForwardedHeaders = 'on'
$env:ForwardedHeadersKnownProxies = '127.0.0.1,::1'

.\2_RunAllTests.ps1 -Launch -Filter "FullyQualifiedName~RT30507"

Remove-Item Env:UseForwardedHeaders
Remove-Item Env:ForwardedHeadersKnownProxies
```

> **この単独の回しに `-UpdateTestCases` を付けないこと。**
> **原本が、この 1 件だけに置き換わる**（`RT-305.6` と同じ事情）。
> **`RT-305.7` は `TESTCASES.md`（原本）に載らない** — **通しでは Skip される**ため。

> **値は `on` である。** **`true` では効かない**
> （`Config.UseForwardedHeaders` が `on` と比べている。`CONFIGURATION.md` 7 節）。
> **実測で踏んだ** : **`true` を渡して、ミドルウェアがそもそも入らず、
> 転送ヘッダが無視されて `RT-305.7` の (4) が 401 になった**。
> **「黙って何も起きない」形で落ちる**ので、気付きにくい。
>
> **`::1` も挙げておくこと。**
> **`localhost` は IPv6 ループバックに解決され得る**ので、
> **サイトから見た接続元が `127.0.0.1` ではないことがある** —
> **前段として信用していないアドレスからの `X-Forwarded-For` は、黙って無視される。**

> **`ForwardedHeadersKnownProxies` を省くと、この測定自体は通ってしまう**が、
> **それは「クライアントが送信元を詐称できる」状態**である。
> **本番では必ず指定すること**（`CONFIGURATION.md`）。

**`RT-305.8` は、使い捨ての利用者で測る**（`UsersAdmin` で作って消す）。
**クライアント認証は、どの回も正しい秘密で通す** —
**測るのは利用者のパスワードの数え**であって、`client:` の数えではない。

> **`test.ps1` が `MaxFailedAccessAttemptsBeforeLockout=20` / `DefaultAccountLockoutTimeSpanFromSeconds=5` を渡して回る。**
> **上限を高くしてあるのは、`TC-4.2` が共用のテスト利用者で意図的にパスワードを間違える**ためである
> （**雛形の 5 回では、そこで枠を使ってしまう**）。**本番の既定は 5 回 / 300 秒。**

> **`AuthFailureWindowSeconds=60` も渡している**（段階 4）。
> **これは「数えた分の寿命」**で、**上限まで叩くのに掛かる時間より長くないと、
> 数が積まれる前に忘れてしまう** — **`RT-305.3` / `.4` / `.7` が断りに届かなくなる。**
> **断る長さ（5 秒）とは別の設定**である。

**歯抜け（実測 2026/10/17）。**

| 壊すもの | 結果 |
|---|---|
| `AuthFailureProvider.ClientKey` から **送信元を外す**（= 段階 2 の鍵に戻す） | **`RT-305.7` の 1 件だけが落ちた**（core。「別の送信元は HTTP 200 / 実測 = 401」）。**同時に回した `RT-305.3` / `RT-305.4` / `RT-305.8` の 6 件は通ったまま** |
| ROPC で **パスワードの失敗を数えない**ようにする（`IncrementAccessFailedCount` を呼ばない。= 段階 3 までの振る舞い） | **`RT-305.8` の 2 件だけが落ちた**（「正しいパスワードでもトークンが出ない / 実測 = **出てしまった（断りが効いていない）**」）。**`RT-305.3` / `RT-305.4` / `RT-305.7` の 5 件は通ったまま** |

> **1 件目を戻したことも、2 件目の回で確かめている**（`RT-305.7` が成功に戻った）。

**実測（2026/10/17）。**

| | 結果 |
|---|---|
| `mem`（既定の通し） | **636 件 / 成功 630 / 失敗 0 / Skip 6**（原本 **326 件**。**Skip は従来の 2 件 ＋ `RT-305.6` の 2 件 ＋ `RT-305.7` の 2 件**） |
| **`RT-305.7`**（単独。転送ヘッダを取り込む） | **core 成功 / netfx Skip**。**20 回失敗した送信元は正しい秘密でも断られ、別の送信元は同じ `client_id` で 200** |
| **`RT-305.8`**（通しに含まれる） | **core・netfx とも成功** |
| `sql`（SQL Server） | **10 件 / 成功 9 / 失敗 0 / Skip 1**（`RT-305.3` / `.4` / `.7` / `.8` ＋ `RT-277.1`。**`RT-305.7` の netfx だけ Skip**） |

> **`RT-305.8` が `sql` で通ることには意味がある** —
> **この経路は `Users` 表に書く**（`AccessFailedCount` / `LockoutEndDateUtc` を `CmnUserStore.Update` で）。
> **`mem` では辞書なので、書き込みの方言は測れない。**

**掃除の `DELETE` は 3 方言とも測った**（実測 2026/10/17）。

**そのままでは測れない。** **`PruneInterval` が 100 で、しかも `PruneExpired` は例外を握る**ので、
**方言の誤りがあっても「黙って掃除されないだけ」になる**
（**ph2 で npg の `INSERT` に別名を書いて落ちたのと同じ型の誤り**が、今度は静かに通ってしまう）。

**`PruneInterval` を 1 にし、`catch` で投げ直すようにして**測った（計測後に戻した）。

| ストア | 結果 |
|---|---|
| `sql`（SQL Server） | **8 件 / 成功 7 / 失敗 0 / Skip 1** |
| `ora`（Oracle） | **8 件 / 成功 7 / 失敗 0 / Skip 1** |
| `npg`（PostgreSQL） | **8 件 / 成功 4 / 失敗 0 / Skip 4**（netfx は従来どおり起動しない） |

> **段階 4 で表も列も増えていない。** **増えたのは、この `DELETE` 1 本だけ**である
> （鍵の文字列は長くなるが、`nvarchar(256)` に収まる）。

##### 口ごとのレート制限（`RT-305.5` / `RT-305.6`。#305 の段階 3）

| | 測ること |
|---|---|
| **`RT-305.5`** | **`client_id` ごとの上限を超えると `429` ＋ `Retry-After`**／**別の口は止まらない**／**窓が変わればまた通る** |
| **`RT-305.6`** | **送信元ごとの上限を超えると `429` ＋ `Retry-After`**（`/jwkcerts` の読み出し） |

**`RT-305.5` は、使い捨ての「利用者」を作って、その利用者でクライアントを登録して測る。**
**窓の中で叩き切る必要がある**ので、**10 本ずつ並べて叩く**（窓が変わると回数は 0 に戻る）。

> **使い捨てのクライアント登録だけでは足りなかった**（実測）。
> **管理画面が扱うのは、その利用者の 1 件**（`/Manage/AddSaml2OAuth2Data`）なので、
> **共用のテスト利用者で登録すると、同じ `client_id` を他のケースと分け合う**
> （**当時は DB 側も 1 人 1 件だった**。#307 の段階 5-a-1 で**画面だけがこの形**になった）。
>
> | 実測 | 何が落ちたか |
> |---|---|
> | `RT-305.5` を共用の利用者で登録 | **`RT-305.5` の復帰**（窓が変わればまた通る）**だけが落ちた** — **連打の枠を `RT-305.4` と食い合っていた** |
> | `RT-305.5` だけ使い捨ての利用者にした | **今度は `RT-277.1`（登録の 3 回押し）と `RT-305.4` が落ちた** — **この 2 つが共用の利用者の登録を奪い合っていた**（**`RT-305.5` が偶然その間に挟まって隠れていた**） |
>
> **`RT-305.4` も使い捨ての利用者にした**（`UsersAdmin` で作って消す。**ロールは `Admin`** —
> **この画面は `SystemAdmin` か `Admin` でなければ開かない**）。
> **共用の利用者の登録を触るのは `RT-277.1` だけになった。**
>
> **「使い捨て」は、クライアントではなく利用者の単位で要る。**

> **通しの設定は `RateLimitPerClientPermits=300` / `RateLimitWindowSeconds=20`**（`test.ps1`）。
> **低くすると通しが壊れる** — **共用のクライアントで、多数のケースが同じ口を叩く。**
> **本番の既定は 120 回 / 60 秒**（雛形）。

**`RT-305.6` は、既定の通しでは Skip する。**

> **送信元ごとの上限は、通しでは 0（制限しない）にしてある。**
> **通しの全ケースが `127.0.0.1` を共有する**ので、**有効にすると無関係なケースが `429` を受ける**
> （**実測** : `RateLimitPerIpPermits=50` で `RT-305.5` と一緒に回すと、
> **`RT-305.5` の 300 回超の連打が `/revoke` の送信元の枠を使い切り、`RT-305.4` が `429` になった**）。
>
> **だから単独で回して測る**（`test.ps1` は、**先に入っている値だけは尊重する**）。
>
> ```powershell
> $env:RateLimitPerIpPermits = '50'
> .\2_RunAllTests.ps1 -Launch -Filter "FullyQualifiedName~RT30506"
> Remove-Item Env:RateLimitPerIpPermits
> ```
>
> **実測**（2026/10/16。**core・netfx とも成功**）： **51 回目で `429`**（上限 50 回 / 20 秒）、
> **`Retry-After` は窓の残り秒数。**
>
> **`RT-305.6` は `TESTCASES.md`（原本）に載らない。**
> **原本は通しの結果から作る**ので、**通しで Skip するケースは入らない**（`RT-188` と同じ事情）。
> **この単独の回しに `-UpdateTestCases` を付けないこと**（付けると、その 2 件だけの原本に置き換わる）。

**歯抜け（実測 2026/10/16）。**

| 壊すもの | 期待する結果 |
|---|---|
| `RateLimitProvider.Check` が **常に null**（= 通す）を返すようにする（従来の振る舞い） | **`RT-305.5` の 2 件だけが落ちる**（「上限 300 ＋ 30 回まで叩いても `429` にならなかった」）。**同時に回した `RT-305.1` 〜 `RT-305.4` の 8 件は通ったまま** |
| 同じ状態で `RT-305.6` を単独で回す（上限 50 回） | **`RT-305.6` の 2 件が落ちる**（「80 回叩いても `429` にならなかった」） |

> **net48 版は、`2_RunAllTests.ps1` ではビルドされない**（`test.ps1` が建てるのは net10.0 版だけ）。
> **歯抜けを両方で測るには、`1_BuildAll.ps1` を回してから流すこと。**
> **これを忘れると、net48 版だけ古い振る舞いのまま測ってしまう**（実測で踏んだ）。

**通しの実測（2026/10/16）。**

| | 結果 |
|---|---|
| `mem`（既定の通し） | **632 件 / 成功 628 / 失敗 0 / Skip 4**（原本 325 件。**Skip は従来の 2 件 ＋ `RT-305.6` の 2 件**） |
| `sql`（SQL Server） | **8 / 8**（`RT-305.3` 〜 `RT-305.5` ＋ `RT-277.1`。**使い捨ての利用者を作って消す経路**を DB ストアでも確かめた） |

> **`ora` / `npg` は回していない。**
> **段階 3 はプロセスの中だけで数える**（表も SQL も増えていない）ため、
> **ストアによる差が出る余地が無い。**
> **一緒に直した `RT-305.4`（段階 2）は利用者の作成・削除を通る**ので、**`sql` で確かめた。**

##### 認証の失敗を数える（`RT-305.3` / `RT-305.4`。#305 の段階 2）

| | 測ること |
|---|---|
| **`RT-305.3`** | **`user_code` を上限まで間違えると、正しい `user_code` でも通らない**／**待てば通る** |
| **`RT-305.4`** | **クライアント認証を上限まで失敗すると、正しい秘密でも `invalid_client`**／**待てば 200**（**鍵は段階 4 で「クライアント ＋ 送信元」になった**。**このケースは 1 つの送信元から測るので、振る舞いは変わらない**） |

**どちらも使い捨ての利用者で測る**（`UsersAdmin` で作って消す）。
**`RT-305.4` は、その利用者でクライアントを 1 件登録する**（`/Manage/AddSaml2OAuth2Data`。**ロールは `Admin`**）。
**共用のテスト利用者やクライアントを断ると、並行して走る他のテストが落ちる**
（**「使い捨て」は、クライアントではなく利用者の単位で要る**。#305 の段階 3 の節）。
**管理画面が扱うのは、その利用者の 1 件**なので、**共用の利用者に登録を増やしても解けない**
（**#307 の段階 5-a-1 より前は、DB 側も 1 人 1 件だった**）。

> **上限は高くしてある**（`test.ps1` が **`AuthFailureMaxAttempts=20`** / `AuthFailureLockoutSeconds=5`）。
> **低くすると通しが壊れた**（実測）：
> **負の経路のケースが、共用のクライアントで意図的にクライアント認証を失敗させる**ので、
> **3 回では本筋のケースが 401 になった**（`RT-196.3` / `RT-196.4` / `EX-3.5` ほか **5 件**）。
> **本番の既定は 5 回 / 300 秒**（雛形）。

**歯抜け（実測 2026/10/16）。**

| 壊すもの | 期待する結果 |
|---|---|
| `AuthFailureProvider.IsLockedOut` が **常に false** を返すようにする（= 従来の振る舞い） | **`RT-305.3` / `RT-305.4` の 4 件だけが落ちる**（「正しい資格情報でも通らない」が崩れる）。**同時に回した Device / CIBA / ポーリングの 19 件は通ったまま** |

**ストアは 4 通りとも測った**（実測 2026/10/16。**表を足したので DB は作り直し**）。

| ストア | 結果 |
|---|---|
| `mem`（既定の通し） | **通し 628 / 失敗 0 / Skip 2** |
| `sql`（SQL Server） | **20 / 20**（`RT-305.*` ＋ 失効の一式） |
| `ora`（Oracle） | **8 / 8** |
| `npg`（PostgreSQL） | **4 / 4**（netfx は従来どおり Skip） |

> **PostgreSQL で 1 度落ちた**（実測）。
> **`INSERT` の列に別名を書いていた**ためである
> （`"failurekey" AS "FailureKey"` は **SELECT でしか書けない**）。
> **SELECT 用と INSERT 用を分けた**（`IdFederationUpstreamProvider` と同じ形）。
> **`sql` / `ora` では別名を使わないので、この誤りは出なかった** —
> **4 ストアを回す意味がここに出た。**

##### ポーリングの間隔（`RT-305.*`。#305 の段階 1）

**既定の通しは「`slow_down` 有効」で回る**（雛形の `EnablePollingSlowDown` が `true`、
`interval` は 5 秒）。

| | 測ること |
|---|---|
| **`RT-305.1`** | **Device** : 1 回目は `authorization_pending`／**続けて叩くと `slow_down`**／**`interval` ＋ 1 秒待つと `authorization_pending` に戻る**（= 要求を消していない） |
| **`RT-305.2`** | **CIBA** : 同じ 3 段（**認証デバイスの登録が前提**なので、`EX-8.*` と同じ段取りを踏む） |

> **`PollingSlowDownTests` は、CIBA 系と同じ collection に入れてある。**
> **`Users.DeviceToken` は 1 つの列**なので、**並行して書くと互いの宛先を壊す**
> （実測 : **`RT-233.1` が「別の宛先」で落ちた**）。
> **`[Collection(CibaTests.DeviceCollection)]` を付けて直列化した。**

**歯抜け（実測 2026/10/16）。**

| 壊すもの | 期待する結果 |
|---|---|
| `PollingThrottle.TooFast` が **常に false** を返すようにする（= 従来の振る舞い） | **`RT-305.1` / `RT-305.2` の 4 件だけが落ちる**（「`slow_down` を返す / 実測 = `authorization_pending`」）。**同時に回した Device / CIBA の 23 件は通ったまま** |

**ストアは 4 通りとも測った**（実測 2026/10/16。**列を足したので DB は作り直し**）。

| ストア | 結果 |
|---|---|
| `mem`（既定の通し） | **通し 624 / 失敗 0 / Skip 2** |
| `sql`（SQL Server） | **49 / 49**（`RT-305.*` ＋ Device / CIBA の一式） |
| `ora`（Oracle） | **27 / 27** |
| `npg`（PostgreSQL） | **13 / 13**（netfx は従来どおり Skip） |

> **SQL Server は、再起動では DDL が流れないことがある**（実測）。
> **`UserStore` が出来ていなければ、初期化スクリプトを手で叩く。**
>
> ```powershell
> docker exec store-sqlserver-1 bash /init/0_start-up.sh
> ```

##### `/jwkcerts` のキャッシュ（`RT-303.*`。#303）

**既定の通しは「キャッシュ有効」で回る**（`test.ps1` が **`JwkSetCacheMaxAgeSeconds=300`** を渡す）。

| | 測ること |
|---|---|
| **`RT-303.1`** | **`ETag` が付く**／**`Cache-Control` が設定どおり**（正なら `public, max-age=`、0 なら `no-store`）／**`If-None-Match` に `304`**（本文なし）／**2 回取っても中身と `ETag` が同じ** |
| **`RT-303.2`** | **鍵の入れ替えに追随する** — **`JwkSet.json` を触ると、次の要求で `ETag` と本文が変わる** |

> **`RT-303.2` は、`JwkSet.json` の末尾に空白を 1 つ足して戻す。**
> **鍵は変えない**ので、**並行して走る他のテストのトークン検証を壊さない。**
> **`finally` で必ず戻す**（落ちた回でも、鍵の配布を壊さない）。
> **構成の絶対パスにファイルが無い配備では Skip する。**

> **期待値は環境変数を先に見る**（`test.ps1` は環境変数で渡し、**環境変数が構成ファイルより強い**）。
> **構成ファイルだけを見ると、通しの実際の設定と食い違う**（実測で踏んだ）。

**歯抜け（実測 2026/10/16）。**

| 壊すもの | 期待する結果 |
|---|---|
| `JwkSetDocument.StampOf` が **更新時刻と長さを見ない**ようにする（覚えたまま返す） | **`RT-303.2` だけが落ちる**（core / netfx とも。「`ETag` が変わる（読み直した）/ 実測 = **変わらない（覚えたまま）**」）。**`RT-303.1` は通ったまま** — **ヘッダと `304` は、覚え方に関係なく成り立つ** |

##### 発行するトークンのヘッダ（`RT-302.1`。#302 の段階 1）

**`jku` は出さない**（`ANALYSIS-IdP.md` の D-10。経緯は
[`CONFIGURATION.md`](CONFIGURATION.md) 「署名鍵」の節）。

| 見るもの | |
|---|---|
| **`jku` が無い** | access_token / id_token / **JARM の `response`** の 3 つ |
| **`kid` が在る** | 同上（**鍵を引く手掛かりはこちら**） |
| **`typ` が種類どおり** | **access_token は `at+jwt`**（RFC 9068 §2.1）、**id_token と JARM は `JWT`**（#302 の段階 2） |

> **`jku` は、他のテストでは代わりにならない。**
> **検証は `kid` で引いている**ので、**`jku` を消しても付けても、他のケースは通る**
> （**だからこのケースが要る**）。
> **`typ` は逆で、噛み合っていないと通し全体が落ちる**（下の歯抜け）。

**歯抜け（実測）。**

| 壊すもの | 期待する結果 |
|---|---|
| `CmnAccessToken.SelectJwsForSigning` に **`jku` を戻す**（2026/10/15） | **`RT-302.1` だけが落ちる**（core / netfx とも。**実測値まで出る** : `在る（https://localhost:44300/jwkcerts）`）。**同時に回した `EX-6.*` / `TC-*` の 18 件は通ったまま** |
| **出す側だけ `typ` を `JWT` に戻す**（受ける側は `at+jwt` を期待したまま。2026/10/16） | **75 件が落ちる**（`/userinfo` が `invalid_token`、`/introspect` が `active=false`、CIBA の端末登録が 401 …）。**access_token を使う経路が全部**落ちる ＝ **出す側と受ける側が噛み合っていることの証拠** |

**受ける側が期待する `typ`。**

| 検証する口 | 期待 | |
|---|---|---|
| `CmnAccessToken.VerifyAccessToken` | **`at+jwt`** | `/userinfo`・リソース サーバ・`/introspect`・`/revoke` が通る道 |
| `CmnAccessToken.VerifySignature` | `JWT` | **`id_token_hint`**（RP-Initiated Logout）。**access_token を渡されたら落ちる** |

> **Open棟梁 の既定（引数なしの `Verify`）は `typ` を照合しない**（Open棟梁 #611 の決め事）。
> **期待値は呼ぶ側が決める** — **ライブラリは、来た JWT が access_token か id_token かを知り得ない。**

> **配備のとき、発行済みの access_token は検証に通らなくなる**（`typ` が `JWT` のため）。
> **有効期限が切れるまでの間だけ**で、**`refresh_token` で取り直せば新しい `typ` になる**
> （`refresh_token` は JWS ではなく `RefreshTokenProvider` が持つ）。
> **コンテナ（`store/`）は公開済みのイメージで動く**ので、**作り直すまでは `JWT` のまま**である
> （**上流・下流とも自分で出して自分で検証する**ので、混在していても通る）。

##### 書き込みの失敗を握らなくした（#300）

**user store の層は、例外を握って正常に戻っていた**（`catch` → `SQLTRACE` に書く → 何事も無く戻る）。
**書き込みでそれをやると `IdentityResult` は成功**になり、**画面はリダイレクトし、データは変わらない。**
**書き込みの 16 か所だけ、投げ直すようにした**（読み取りは従来どおり握る）。

**これで、隠れていた不具合が 1 件出た。**

| | |
|---|---|
| どこ | `CmnUserStore.AddClaim` の **PostgreSQL の `INSERT`** |
| 何が | **列を 5 つ挙げて値を 4 つ渡していた**（`id` は `serial` なので挙げてはいけない） |
| DB の答え | **`42601: INSERT has more target columns than expressions`**（**構文の誤りなので、1 度も成功し得ない**） |
| 影響 | **PostgreSQL では、利用者のクレームが 1 件も保存されていなかった**（ID 連携が運ぶメアド・利用者名の属性を含む） |
| いま | **直した。** `userclaims` は **2 件**入っている（ID 連携の通しの後。実測） |

**握るのを止めたから出た**ことが、**両方の向きで測れている**（実測 2026/10/15。`npg` の通し）。

| 実装 | `INSERT` の誤り | 結果 |
|---|---|---|
| **握る**（従来） | **在る** | **322 / 失敗 0**（**緑。クレームは保存されていない**） |
| **投げ直す**（#300） | **在る** | **6 件が落ちる**（`RT-140.4` / `.5`、`SA-6.1` / `.2` / `.4` / `.6`。**ID 連携の経路**） |
| **投げ直す**（#300） | **直した** | **322 / 失敗 0**（**緑。クレームが保存される**） |

**4 ストアで測った**（実測 2026/10/15）。

| ストア | 通し |
|---|---|
| `mem` | **612 / 失敗 0 / Skip 2** |
| `sql`（SQL Server） | **612 / 失敗 0 / Skip 2** |
| `ora`（Oracle） | **612 / 失敗 0 / Skip 2** |
| `npg`（PostgreSQL） | **322 / 失敗 0 / Skip 292**（netfx は従来どおり Skip） |

> **読み取りを握るのは、そのままにした。**
> **「居ない」と区別が付かない**のは確かだが、**Skip や「居ない」で成り立っている経路**
> （種データの作成など）が在り、**1 件ずつ意味を決める必要がある。**

> **`StopUserStoreException` は、以前から投げ直していた**
> （`Logging.MySQLLogForEx` の中。**STS 専用の配備で user store を止める**ための例外）。
> **今回入れた `throw;` は、その後ろに置いてある。**

##### コンテナの `mem` ストアは、回を重ねると溜まる

**実測（2026/10/15）** : **1 日に通しを 8 回ほど回した後、`CN-5.4` / `CN-5.5` が落ちた**
（**2 つ目の上流との連携で、下流がサインインさせない**）。
**`docker compose restart upstream upstream2 downstream` で元に戻った**（23 / 23）。

> **コンテナは公開済みのイメージで動く**ので、**手元の修正とは無関係**である
> （**それが切り分けになる** — **コンテナだけが落ちるなら、まず溜まりを疑う**）。

##### GDPR の消去は、行ごと消す（`RT-277.8`。#299）

**消去（`POST /Manage/DeleteGdprPersonalData`）は、利用者の行ごと消す**
（`UserManager.DeleteAsync`。**#299 でそう改めた**）。
**子の行は外部キー（`ON DELETE CASCADE`）が落とす** — `UserRoles` / `UserLogins` /
`UserClaims` / `TotpTokens` / `FIDO2Data` / `ConsentGrant` / `SubjectIdentifier` /
**`Saml2OAuth2Data`（その利用者が登録したクライアント）**。

> **#307 の段階 5-a-1 で、この cascade の経路が変わった** —
> **`Saml2OAuth2Data.ClientID` → `Users.ClientID` から、`OwnerUserId` → `Users.Id` へ**である。
> **1 人が n 件持てるようになったので、n 件とも落ちる**（`RT-307.3` の (6) が測る）。

> **以前は属性を潰す実装だった**（利用者名・メアドを利用者 id で塗り潰す）。
> **潰す対象の `Users.UserName` / `Users.ClientID` は、どちらも外部キーの参照先**であり、
> **`ON UPDATE` の指定は 3 方言とも 1 本も無い**（= NO ACTION）。
>
> **実測（SQL Server。トランザクションを張って試し、ロールバックした）。**
>
> | 試した `UPDATE` | 結果 |
> |---|---|
> | `UPDATE Users SET UserName = Id`（WebAuthn の資格情報を持つ利用者） | **`FK.FIDO2Data.Users_UserName` で弾かれる** |
> | `UPDATE Users SET ClientID = Id`（クライアントを登録した利用者） | **`FK.Saml2OAuth2Data.Users_ClientID` で弾かれる**（**この列は段階 5-a-1 で落とした**） |
>
> **例外は握られる**（`CmnUserStore.Update`。[#300](https://github.com/OpenTouryoProject/MultiPurposeAuthSite/issues/300)）ので、
> **画面は成功に見えて、1 列も消えていなかった。**
> **`ON UPDATE CASCADE` で逃げる道も無い**（**Oracle に `ON UPDATE` 節が無い**）。
>
> **Oracle では、資格情報も登録も無い利用者でさえ消去が落ちていた**
> （`LockoutEndDateUtc` に `DateTime.MaxValue` を入れていて `ORA-01841`）。
> **これも #299 で直した**（`null` ＝ この製品の既定値）。

**`RT-277.8` は、消される側に 3 つ持たせてから消す。**

| 持たせるもの | なぜ |
|---|---|
| 属性データ（`UnstructuredData`） | **潰す対象**だった値 |
| **クライアント登録**（`/Manage/AddSaml2OAuth2Data`） | **以前はこれが在ると消去が FK で弾かれた**。**ロールは `Admin`**（この画面は `SystemAdmin` か `Admin` でなければ開かない） |
| ロール（`Admin`） | **`UserRoles` も cascade で落ちる**ことの確認 |

**見るのは 3 つ**（**別々のことを見ている**）。

| | |
|---|---|
| **サインインできない** | **行が無くても、属性が潰れていても成り立つ**（以前の実装では `EmailConfirmed = false` が効いていた。実測） |
| **一覧に元の利用者名・メアドが出ない** | 潰す実装でも成り立つ |
| **一覧に利用者 id も出ない** | **行ごと消えたときだけ**成り立つ（**潰す実装では、id の名前で残っていた**） |

**ストアは 4 通りとも測った**（実測 2026/10/14）。

| ストア | 結果 |
|---|---|
| `mem`（既定の通し） | **通し 612 / 失敗 0 / Skip 2** |
| `sql`（SQL Server） | **通し 612 / 失敗 0 / Skip 2** |
| `ora`（Oracle） | **`RT-277.*` ＋ WebAuthn の削除 ＋ クライアント登録で 11 / 11**（netfx 1 件は Skip） |
| `npg`（PostgreSQL） | **2 / 2**（netfx は Skip） |

> **`mem` ストアには外部キーが無い。**
> **`CmnUserStore.Delete` が消すのは、利用者・ロールの対応・`sub` の対応表だけ**なので、
> **WebAuthn の資格情報は画面の側で消している**（`FIDO.DataProvider.DeleteByUser`）。
> **同意の記録とクライアント登録は、`mem` では残る**（**プロセスを畳めば消える**ストアである）。
> **DB ストアでは cascade が全部落とす。**

##### 連携キーの幅（`UserLogins`。#292）

**上流が n 件になったので、`LoginProvider` / `ProviderKey` を 512 / 256 に広げた**
（経緯と `ALTER` は [`CONFIGURATION.md`](CONFIGURATION.md) 7 節）。

**E2E では測れない。** **長い `iss` / entityID を名乗る上流が、この仕掛けに無い**ためである
（コンテナの上流は `mem` ストアなので、表の幅を通らない）。
**代わりに、3 方言の境界を実機で測った**（実測 2026/10/14）。

| 方言 | 512 / 256 | 513 文字 |
|---|---|---|
| SQL Server | **入る** | **弾かれる**（「文字列またはバイナリ データは切り捨てられます」） |
| Oracle | **入る** | **弾かれる**（`ORA-12899`） |
| PostgreSQL | **入る** | **弾かれる**（`value too long for type character varying(512)`） |

**測ったあとの行は消してある**（`Users` への FK が在るので、既存の利用者の行に挿した）。

> **到達性の記憶を読み直していた**（テスト基盤。`TestEnv.IsReachable`）。
> **並行して走る別のテストが、再試行のために `null` に戻している**ことがあり、
> **`npg` の通しで netfx の 2 件が Skip にならず
> `Nullable object must have a value` で落ちていた**（実測）。**false を返すように直した。**

> **表を足したら、DB を作り直すこと。**
> **PostgreSQL と Oracle は、初期化スクリプトを「最初の 1 回」しか流さない** —
> **コンテナを起動し直しても、足した表は増えない**（実測）。
>
> ```powershell
> cd store
> .\0_CopyInitSql.ps1                      # repo の DDL を init に流し込む
> docker compose rm -sfv postgres oracle    # **作り直す**（sqlserver は毎回流れる）
> docker compose up -d postgres oracle
> ```
>
> **回し終えた方言のコンテナは止めること**（`docker compose stop <service>`）。
> **止めないと 3 つとも上がったまま残る** — **ポートは衝突しない**（1434 / 1522 / 5433）ので
> **気付かないまま、メモリだけを食う**（**#308 の 3 方言で踏んだ**）。
> **消さずに止めるだけでよい**（次に回すときに作り直す）。

> **製品コードで歯抜けを測るときは、先に `1_BuildAll.ps1` を回すこと。**
> **net48 版は IIS Express が「ビルド済みの出力」を配信する**ので、
> **ビルドせずに `test.ps1` を回すと、古い実装のまま通ってしまう**
> （実測 : `Co.IdFederationUpstreams` から DB の読み出しを外したとき、
> **core だけ落ち、netfx は通った**。`dotnet run` は起動時に作り直す）。

##### 2 つ目の上流コンテナ（`upstream2`。#292 の段階 1）

**上流が n 件になったことを測るために在る**（`CN-5.4` 〜 `CN-5.6`）。

| | 値 | なぜ |
|---|---|---|
| URL | **`https://localhost:44304`** | 口はポートで分ける |
| `IssuerId` | **`https://upstream2.ssoauth.opentouryo.com`** | **3 つの IdP が同じ `iss` を名乗らない**ようにする |
| 署名鍵 | **`SHA256RSA_Upstream2.*` ＋ `JwkSet_Upstream2.json`** | **上流 1 とも下流とも別の鍵**（`CN-1.5` が 3 つとも違うことを見る） |
| `CookieNamePrefix` | **`upstream2_`** | Cookie はポートで分かれない（RFC 6265 §8.5） |
| 鍵・ログの置き場 | `store/keys-upstream2` / `store/logs-upstream2` | 他と分ける（#279） |

**下流コンテナには、上流 2 件が登録してある**（`IdFederationUpstreams__upstream1*` / `__upstream2*`）。
**鍵とメタデータを引く宛先は、コンテナの中から届くもの**（`http://upstream2:8080/...`。#293 の段階 3）。
**ブラウザが行く先（`authorize` / SSO）は、ホストから届く URL**（`https://localhost:44304/...`）。

**鍵を作るとき**（`root/files/resource/X509` で実行する）。

```
GenRsaCertForUpstreamByOpenSSL.bat Upstream2
```

**その後、上流 2 用の JwkSet を作り直す**（`CommandLineTools/CreateJwkSetJson` を、
`SpRp_RsaCerFilePath` ＝ `SHA256RSA_Upstream2.cer` / `JwkSetFilePath` ＝ `JwkSet_Upstream2.json`
の設定で 1 回）。**`C:\root\files\resource` にも配置する**（コンテナはそこをマウントする）。

> **`.bat` は CRLF でなければならない**（`.gitattributes` の `*.bat text eol=crlf`）。
> **LF だと cmd が行を割り、`set` / `if` が働かない**（実測。#292 の段階 1 で直した）。
>
> **UTF-8 の日本語の `rem` 行は、CP932 のコンソールで「認識されていません」と出ることがある。**
> **既存の `GenClientCertByOpenSSL.bat` も同じ**（実測）。**鍵の生成そのものには影響しない。**

##### SAML2 の ID 連携も、コンテナ 2 つで測る（`CN-5.3`。#293 の段階 3）

**`CN-5.1` / `CN-5.2` は OIDC である。** **SAML2 の脚は `CN-5.3` で初めてコンテナを通る。**

**`SA-6.*` とは、測っている配備が違う。**

| | 下流 | 設定の出どころ |
|---|---|---|
| `SA-6.*` | **ホスト**（Kestrel / IIS Express） | `test.ps1` の環境変数 |
| **`CN-5.3`** | **コンテナ** | **compose の環境変数** |

> **鍵を引く宛先を間違えると、倒れ先しか測れない。**
> **`IdFederationSaml2MetadataUrl` / `IdFederationJwkSetUri` はサーバが呼ぶ**ので、
> **`https://localhost:44301` ではコンテナの中から届かない**（待ち受けは 8080 / 8081）。
>
> **実測（2026/10/13。直す前）** : 下流コンテナのログに
> `The SAML2 metadata could not be read. (empty response)` /
> `The discovery document could not be read. (empty response)`。
> **一巡は通っていたが、通っていたのは設定の `.cer`（倒れ先）である。**
>
> **直した後** : `The SAML2 metadata was read. (sso: found, signing certificates: 1)` /
> `The JWK Set was read from the configured URL.`
>
> **メタデータが書く SSO の口は、上流の公開 URL**（`https://localhost:44301/saml2request`。
> `OAuth2AuthorizationServerEndpointsRootURI` から作る）なので、
> **コンテナの中の宛先で引いても、ブラウザが行く先は正しい。**

**歯抜け（実測 2026/10/13。どちらも `CN-5.3` だけが落ち、`CN-5.1` / `CN-5.2` は通ったまま）。**

| 壊すもの | 落ちる所 |
|---|---|
| 上流に登録した `jwk_rsa_publickey`（下流コンテナの分）を**別の鍵に** | **`StatusCode` が `Requester`**（**上流が (2) を検証している**。#293 の段階 2） |
| **メタデータを届かない宛先に戻し、倒れ先の `.cer` を下流自身の証明書に** | **ACS がエラー画面**（**(3) は上流の鍵でなければ検証できない**。#293 の段階 1） |

> **`CN-5.1` / `CN-5.2` が通ったままなのが正しい。**
> **OIDC の (2) には署名が無く、(3) の鍵は `IdFederationJwkSetUri` から引いている。**

##### (2) の署名鍵を上流ごとに指定する（#292 の段階 4-a）

**`store/docker-compose.yml` の下流コンテナは、上流 2（SAML2）の行に
`signing_pfx_file_path` を書いてある**（**値は共通設定と同じ `*_Client.pfx`** だが、
**明示指定の経路を通すため**である）。

**歯抜け（実測 2026/10/14）。**

| 壊すもの | 期待する結果 |
|---|---|
| **上流 2 の `signing_pfx_file_path` を別の鍵に**（`*_Upstream.pfx`） | **`CN-5.5` だけが落ちる**（`StatusCode` が **`Requester`** ＝ **上流が登録鍵で (2) を検証して弾いた**）。**`CN-5.3`（上流 1。共通設定の鍵）と他の 4 件は通ったまま** |

> **「通った」だけでは、指定した鍵で署名したかが分からない。**
> **別の鍵を指すと落ちること**で、**行の値が効いていること**を確かめている。

##### 上流が n 件（`CN-5.4` 〜 `CN-5.6`。#292 の段階 1）

**下流コンテナに上流 2 件を登録し、2 つ目を指して連携する。**
**どちらへ行くかは、画面の導線が送る `IdpKey`**（空なら先頭の 1 件 ＝ 従来の押し方）。

| | 測ること |
|---|---|
| **`CN-5.4`** | **2 つ目の上流（鍵も `issuer` も違う OP）と OIDC で連携できる**。**「鍵の違う OP と連携できる」ことは、ここで初めて測れる**（#289 の完了コメントの限界） |
| **`CN-5.5`** | **同じことを SAML2 で**（`entityID` の照合も相手ごと） |
| **`CN-5.6`** | **上流が違っても、同じ（検証済みの）メアドなら同じ下流の利用者になる**（アカウント リンク。#140 の段階 1・3） |

> **`CN-5.6` は、上流ごとに別の `IdPClient`（別の Cookie の入れ物）で測る。**
> **1 つの入れ物で続けると、上流 1 のサインインが残り、
> 上流 2 の連携が失敗しても「同じ利用者」に見えてしまう**（**歯抜けで実測**。直した）。

**歯抜け**（実測 2026/10/13。**compose の `IdFederationUpstreams__upstream2__*` を壊す**）。

| 壊すもの | 期待する結果 |
|---|---|
| `issuer` を上流 1 の値に | **`CN-5.4` / `CN-5.6` が落ちる**（`id_token` の `iss` が合わず、サインインできない）。**`CN-5.5` は通ったまま**（SAML2 は別の行） |
| `client_id` を上流 1 の値に | **`CN-5.4` / `CN-5.6` が落ちる**（**上流 2 に未登録**なので `code` が返らない）。**`CN-5.5` は通ったまま** |
| `IdpKey` を送らない | **上流 1 へ行く**（既定の選び方。**`CN-5.1` がその経路**である） |

##### 目視の手順（実測 2026/10/08）

**両方を作り直した状態から 1 巡測った。**

| 手順 | 実測 |
|---|---|
| 1. 両方の Discovery | **`issuer` が違う**（`https://ssoauth.opentouryo.com` / `https://downstream.ssoauth.opentouryo.com`） |
| 2. 下流の `jwkcerts` | **鍵が 4 つ**（マウントした署名鍵まで読めている） |
| 3. 上流でサインイン | HTTP 302 |
| 4. 下流で「ID 連携でサインイン」 | 上流の `/authorize` へリダイレクト |
| 5. 1 回目 | **同意画面**（#280 と同じ。同意を 1 度整える）→ `code` |
| 6. 下流へ戻す | `/Manage/Index` が **HTTP 200**（サインインできた） |
| 7. 2 回目 | **同じ利用者**（`super_tanaka`）。連携キーが `(iss, sub)` であること |
| 8. Cookie | **上流・下流が並んだ**（下記） |

```
.upstream_MultiPurposeAuthSite        .downstream_MultiPurposeAuthSite
upstream_auth_time                    downstream_auth_time
upstream_MultiPurposeAuthSiteSession  downstream_MultiPurposeAuthSiteSession
```

**`token` / `userinfo` が `http://upstream:8080` で届いていることは、6 で分かる**
（届いていなければ `/Manage/Index` は 200 にならない）。

##### AntiForgery の Cookie も、名前が分かれる（✅ 修正済み。#282）

**#281 の時点では、AntiForgery だけが同じ名前であった**（`CookieNamePrefix` が掛かっていなかった）。
**片方がもう片方のトークンを上書きし、ログに復号失敗が残っていた。**

| | AntiForgery の Cookie 名 |
|---|---|
| #282 より前 | 上流 `.AspNetCore.Antiforgery.xxxxxxxxxxx` / 下流 `.AspNetCore.Antiforgery.xxxxxxxxxxx`（**同じ**） |
| #282 より後 | 上流 `.upstream_AspNetCore.Antiforgery.…` / 下流 `.downstream_AspNetCore.Antiforgery.…`（**分かれた**） |

**実測（2026/10/08。#282 の後）** : ID 連携を 2 巡させて、
**`The antiforgery token could not be decrypted.` が両方とも 0 件**（直す前は上流 5 件 / 下流 10 件）。

> **名前は DataProtection の識別子から導かれる**（net10.0 版。実測）。
> **#279 で `SetApplicationName` を入れたので、`DataProtectionKeyPath` を設定した配備同士は、
> パスが違っても同じ名前になる。** そのため、**接頭辞で分けるのが必須になった。**

#### 上流コンテナの自己テスト（#250）

**自己テストは「サーバが自分自身を WebAPI で呼ぶ」**（`client_credentials` など）。
**コンテナの中からは、外向けのホスト名・ポートに届かない。**

```
コンテナ内   localhost:8080  : OPEN      ← 待ち受け（HTTP）
コンテナ内   localhost:8081  : OPEN      ← 待ち受け（HTTPS）
コンテナ内   localhost:44301 : CLOSED    ← ホスト側の公開ポート。**届かない**
```

**`docker-compose.yml` が `OAuth2ContainerizatedAuthSvrEPRootURI` に
`http://localhost:8080` を与えている。** `Helper.GetContainerizatedAuthZServerUri` が、
`Helper` を通る WebAPI 呼び出しの宛先をこれに差し替える（**Windows でないときだけ働く**）。

> **HTTP のループバックにしてある。** HTTPS（8081）にすると、
> **コンテナの中でホストの開発用証明書を検証できず**、証明書を信頼させる手当てが要る。
> **自分自身への呼び出しなので、コンテナの外には出ない。**

**実測（`/Home/Saml2OAuth2Starters` のボタンを叩いた結果）。**

| ボタン | 結果 |
|---|---|
| `ClientCredentialsFlow` | **`access_token` が返る** |
| `ResourceOwnerPasswordCredentialsFlow` | **`access_token` が返る** |
| `JWTBearerTokenFlow` | **`access_token` が返る** |
| `DeviceAuthZGrant` | 応答画面（`DeviceAuthZResponse`）まで進む |
| `FAPI_CIBA_Profile` | `access_denied : The authentication device is not registered.`（**認証デバイスの登録が要る**。`RT-246.3` が Skip なのと同じ理由） |

**画面遷移を伴うもの**（認可エンドポイントへブラウザが飛ぶ Authorization Code / Implicit / Hybrid / PKCE、
および mTLS を使う FAPI2）は、**ここでは測っていない。**
**mTLS はクライアント証明書の持ち込みが要る**ので、コンテナでは動かない。

**起動できたかは、ディスカバリで確かめる。**

```powershell
Invoke-RestMethod https://localhost:44301/.well-known/openid-configuration
Invoke-RestMethod https://localhost:44301/jwkcerts   # 鍵が 4 つ出る（実測 2026/10/08）
```

**`jwkcerts` が返れば、マウントした署名鍵まで読めている。**

> **DataProtection の鍵の置き場（#251）も、ここで効いている。**
> `appSettings__DataProtectionKeyPath=/keys` を `store/keys` にマウントしてあるので、
> **コンテナを作り直してもサインインが切れない。**
>
> **実測** : サインインしてから `docker restart` / `docker compose rm -sf` + `up` を
> それぞれ 2 回。**4 回とも `/Manage/Index` は 200**（サインインは維持された）。
>
> **起動を待たずに叩くと、サインイン画面に飛ばされる。** 判定の前に
> `jwkcerts` が返るまで待つこと（決め打ちの `sleep` では足りないことがある）。

**ID フェデレーションの目視・E2E は、まだこれから**（5 節「ID フェデレーション」）。

### 4 つのストアの実測

**実測 2026/10/06**（#272 を全部入れた後。`prompt` の 4 値すべての E2E を含む）。
ビルドは net48 / net10.0 とも エラー 0 / 警告 0。

| ストア | 成功 | 失敗 | Skip | 備考 |
|---|---|---|---|---|
| `mem`（既定） | **510** | **0** | 1 | `RT-246.3` core（mTLS フックの副作用） |
| `sql` | **510** | **0** | 1 | 同上 |
| `ora` | **510** | **0** | 1 | 同上 |
| `npg` | **257** | **0** | 254 | **net48 版を起動しないぶんが Skip**（`Npgsql` が `#if NETCORE`。netfx 253）＋ 上記 1 件 |

> **同じ日の推移**（どれも 4 ストアとも失敗 0）。
>
> | 時点 | `mem` / `sql` / `ora` | `npg` | 増えたもの |
> |---|---|---|---|
> | #269 | 490 | 247 | — |
> | #270 | 492 | 248 | `RT-270.1`（core / netfx） |
> | #271 | 492 | 248 | （増えていない。E2E を足していない） |
> | #272 の段階 1 | **498** | **251** | `RT-272.1`〜`RT-272.3`（× 2 対象） |
> | #272 の段階 2 | **506** | **255** | `RT-272.4`〜`RT-272.7`（× 2 対象） |
> | #272 の `prompt` の残り | **510** | **257** | `RT-272.8` / `RT-272.9`（× 2 対象） |
>
> **段階 2 では、作り直した DB でだけ落ちるものが 1 件出た**（`sql` の `RT-188.4`）。
> **`prompt=none` を自分で送るテストが、先に走ったテストの同意に依存していた**ためで、
> **対象ごとに 1 度同意を通す**形に直した（上の「同意を記録するようになった」）。
>
> **`ora` で `RT-186.1` が 1 度落ちたが、再現しなかった**（下の「以前の実測」の揺れと同種と見ている）。

**DB ストアだけで出る失敗が 3 つ出た。** どれも直してある（下記）。

> **#260 を直したときの記録（2026/10/03）** : 4 ストアとも **474 / 0 / 3**
> （`npg` は 239 / 0 / 238）。**その後 #261〜#267 でケースが増え**、
> **#263 で `RT-245.4` の Skip が外れた**（C-10 を直したため）。

#### DB ストアだけで出た失敗（#266 で踏んだ）

**`mem` では出ない。** **種データがストアに書かれるようになって初めて出た**（#264）。

| | 症状 | 原因 | 直し方 |
|---|---|---|---|
| 1 | **`core` が 247 件 Skip**（`sql`） | **初回の種データ作成が重く**（クライアント登録 17 件）、並行して走ったクラスの**到達性プローブが 10 秒で時間切れ**。`_reachable = false` を掴むと、その対象が全部 Skip になる | **プローブを 3 回まで試す**（`TargetInfo.Probe`。間隔 5 秒） |
| 2 | **`npg` で 190 件失敗**（`GET /Account/Login` が HTTP 500） | **画面の選択肢（`Ddl*Items`）が登録 JSON に直列化されていた。** 登録 1 件が **3,108 文字**になり、**Oracle / PostgreSQL の `UnstructuredData`（2000 文字）に収まらない**（`22001`） | **`Ddl*Items` に `[JsonIgnore]`**（`ManageAddSaml2OAuth2DataViewModel`） |
| 3 | 2 を直しても、**長い登録はまだ入らない** | **`UnstructuredData` の型が 3 方言で揃っていない**（#269） | **Oracle は `NCLOB`、PostgreSQL は `text`**（下記） |

> **2 は、画面から登録するときにも起きていた**（E2E が画面登録を駆動していなかったので見えていなかった）。

#### `UnstructuredData` の型を 3 方言で揃えた（#269）

**揃っていなかった。** **SQL Server だけ上限が無く、Oracle と PostgreSQL は 2000 文字**だった。
**SQL Server で保存できる登録が、Oracle / PostgreSQL では保存できない**という形である。

| テーブル | SQL Server | Oracle | PostgreSQL |
|---|---|---|---|
| `Users` / `FIDO2Data` / `CibaData` | `nvarchar(max)` | **`NVARCHAR2(2000)` → `NCLOB`** | **`varchar(2000)` → `text`** |
| ~~`Saml2OAuth2Data`~~ | — | — | — | **#270 で列を落とした** |

**Oracle は単純に広げられない。** **`NVARCHAR2` は 2000 文字（4000 バイト）が上限**で、
**`MAX_STRING_SIZE = EXTENDED`**（データベース全体の設定。戻せない）か **`NCLOB`** しかない。
**配備側の設定に踏み込まない**ので `NCLOB` にした。

**クライアント登録は全項目が 1 つの JSON に入っていた**（`Saml2OAuth2Data.UnstructuredData`）ので、
**画面から入れられる範囲でも 2000 文字を超えた** —
`Const.MaxLengthOfUri`（**512**）の項目が 5 つ ＋ JWK 2 本（約 890 文字）。

> **そのクライアント登録は、#270 で専用列に切り出した。**
> **`Saml2OAuth2Data` に `UnstructuredData` 列はもう無い**（下の「専用列に切り出した」）。
> **列ごとに幅を決めたので、この節の問題はクライアント登録には起きない。**
> **残る 3 表（`Users` / `FIDO2Data` / `CibaData`）には引き続き効く**ので、#269 の型を揃えたことは無駄になっていない。

- **E2E** : **`RT-269.1`**（`web_origins` 24 件 ＋ 長い `redirect_uri` 2 つで
  **2000 文字を超える登録**を作り、**先頭と末尾のオリジンの両方で CORS が通る**ことを見る）
- **`mem` では幅の問題を測れない**（辞書なので上限が無い）。**効くのは `sql` / `ora` / `npg`**
- **既存のデータベースは作り直すのが早い**（`store/` は使い捨て）。
  **`ALTER` で広げるなら**、PostgreSQL は `ALTER TABLE ... ALTER COLUMN ... TYPE text`、
  **Oracle は `NVARCHAR2` から `NCLOB` へ直接変更できない**ので
  **列を足して移してから入れ替える**

#### 同意（consent）を記録するようになった（#272 の段階 2）

**これが E2E に一番広く響いた変更である。**

**記録が無いクライアントに `prompt=none` で認可を求めると `consent_required`** になる。
**`Flows.AuthorizeCodeAsync` は常に `prompt=none` を付けていた**ので、そのままでは通らない。

| 直したところ | |
|---|---|
| `Flows.AuthorizeCodeAsync` | **`prompt=none` を付けない**。代わりに**同意画面が出たら「許可」まで進める**（`AuthorizeAndGrantAsync`） |
| `TargetInfo.EnsureSeedData` | **対象ごとに 1 度だけ、構成ファイルのクライアントの同意を通す**（`EnsureConsentSeed`） |
| `Flows.EnsureConsentAsync` | **`prompt=none` を自分で送るテスト**が先に呼ぶ口 |
| `RT-247.1` | 観測点を「同意画面まで進む」から**「再びサインインへ送られない」**へ（記録が在ると同意画面を飛ばすため） |
| `HomeController`（自己テスト） | **OIDC のボタンの固定の `prompt=none` を外した**。付けたままだと**記録が無い配備で初回に必ず `consent_required`** になる |
| `AccountController`（**ID 連携**） | **このときは見落としていた。** **#287 で外した**（同じ理由。**利用者が押す導線で UI を禁じていた**） |
| `RT-247.1` の手順 4 | **URL の形だけを見る**（辿らない）。**辿ると再認証が起き、手順 5 が測れなくなる** |

> **順序で結果が変わるのが一番危い。**
> `prompt=none` を送るテストは **12 フイルに散っている**ので、
> **先に走ったテストが同意を通していたかどうかで合否が変わる**ことになる。
> **実際に、`mem` では通るのに作り直した `sql` で `RT-188.4` が落ちた。**
> そのため、**種データと同じところで 1 度だけ通す**形にしてある。

> **自己テスト画面も忘れない。**
> **`HomeController` の OIDC ボタンは `prompt=none` を固定で付けていた**ので、
> **同意を記録するようになった時点で、新しい配備では使えなくなっていた。**
> **E2E では見えなかった** — 上の種データが同意を通していたためである。
> **人が指摘して気付いた。**

**通すのは構成ファイルのクライアントだけである。**
**種データの `TestClient_19` は、「記録が無いこと」を測るために在る**ので、
**どのテストも「許可」を押してはならない**（押すと DB ストアで 2 回目から測れなくなる）。

- **E2E** : `RT-272.4`（記録が無ければ `consent_required`）/
  `RT-272.5`（`prompt=consent` は記録が在っても出す）/
  `RT-272.6`（**拒否** → `access_denied`。E-6）/
  `RT-272.7`（**管理画面からの取り消し**） /
  `RT-272.8`（**`prompt=login`**。再認証と、印で繰り返しにならないこと）/
  `RT-272.9`（**`prompt=select_account`**。同意画面と「別のアカウントでログイン」）
- **DDL 3 方言に `ConsentGrant` 表を足した。** **`store/` は作り直す**こと

##### 「認可の後は管理画面が 302 になる」は、調べたら誤りだった

**一度そう観測して、そのまま書いていた。** **後で測り直したら再現しなかった。**

**認可フローの前後で `/Manage/Index` を測った実測**（2026/10/06。net10.0）。

| 時点 | `/Manage/Index` | Cookie |
|---|---|---|
| サインイン直後 | **200** | `.AspNetCore.Identity.Application` ほか 4 件 |
| 認可の GET（同意画面）の後 | **200** | **同一** |
| 同意の POST（code 発行）の後 | **200** | **同一** |

**認可フローはセッションを壊していない。**
`RT-272.7` は**同じクライアントで通る**ので、別の `IdPClient` にする回避策も外した。

**当時の 302 の正体は、下の `FooterScriptsSection` の漏れであったと見ている**
（net48 は `customErrors` が例外を 302 に変えるため）。
**ただし、`/Manage/Index`（この画面とは関係がない）を 302 と観測した説明にはなっていない。**
**そこは分からないままである。**

**教訓は、「1 度の観測を原因と混同しない」こと。**
**回避策を入れる前に、切り分けの測定をすればよかった。**
今回は、**`/Manage/Index` も 302 だった**という 1 行の観測を根拠に、
**「認可フローがセッションを壊す」という説を置いてしまった。**

##### 画面を足したときは、`FooterScriptsSection` を忘れない

**共通の `_Layout.cshtml` が `RenderSection("FooterScriptsSection", required: true)` を持つ。**
**書かないと、画面を開いたときに落ちる。**

| 系統 | そのときの見え方 |
|---|---|
| net10.0 | **HTTP 500**（例外がそのまま返る） |
| net48 | **HTTP 302**（`customErrors` がエラー画面へ送る） |

**net48 の 302 は「未認証」と見分けがつかない。**
**認証を疑って時間を使った**が、原因は画面側だった。
**net10.0 側の 500 を先に見れば、すぐに分かる**（ログに例外の文面が出る）。

#### SAML2 の E2E を足した（#275 / #276）

**DDL は変えていないが、種データの `client_id` を変えたので `store/` は作り直す**こと。

**種データの `client_id` を変えたら、必ず作り直す。**
**古い `client_id` の登録が残り、テストが古い値を引く**（**種データは init SQL が入れる**）。

> **#307 の段階 5-a-1 より前は、もっと硬い形で落ちた** —
> **`Saml2OAuth2Data.ClientID` が `Users.ClientID` への外部キーを持っていた**ので、
> **古い id の利用者が残っていると、新しい id の登録を入れられなかった。**
>
> ```
> INSERT ステートメントが FOREIGN KEY 制約 "FK.Saml2OAuth2Data.Users_ClientID" と競合しています。
> ```
>
> **いまは外部キーが `OwnerUserId` → `Users.Id` に張り替わり、種データは所有者を持たない**ので、
> **この形では出ない。** **作り直す理由は上の 1 行に変わった。**

**種データは `CreateData`（`GET /Account/Login`）の中で作られる**ので、
**ここで落ちると `/Account/Login` そのものが落ちる。**

| 症状 | |
|---|---|
| **net10.0 版** | `GET /Account/Login` が **HTTP 500** |
| **net48 版** | **HTTP 302**（`customErrors` が例外をリダイレクトに変える） |
| **E2E** | **`__RequestVerificationToken` が取れず、サインインを要する全件が落ちる**（実測 416 / 543） |

**「ほぼ全件が落ちる」ときは、まず `/Account/Login` を 1 回叩くこと。**
**個々のテストを追っても何も分からない**（どれも同じ 1 行で落ちている）。

> **`client_id` の接頭辞の付け方に注意。**
> **`e2e0tcNN` の `NN` は `TestClient_NN` ではない。**
> `TestClient2_2` が `e2e0tc22`、`TestClient2_3` が `e2e0tc23`、
> `TestClient4_2` が `e2e0tc42`、`TestClient4_3` が `e2e0tc43` を使っている。
> **`TestClient_22` に `e2e0tc22` を取ろうとして衝突した**（#275）。
> **先に在る方が登録され、こちらは「登録されていない」ことになり、**
> **SAML の応答が返らないという形で出た。** SAML の分は `e2e0saNN` にしてある。

#### オンライン決済サービスを取り下げ、`Users.PaymentInformation` を落とした

**DDL が変わったので、`store/` は作り直すこと**
（`2_DockerComposeDown.bat` → `1_DockerComposeUp.bat`）。

| | |
|---|---|
| **落とした列** | `Users.PaymentInformation`（3 方言）。**支払元情報（Stripe / PAY.JP の顧客 ID）だった** |
| **種データ** | **`TestClient_15` の `redirect_uri_code` を、記号 `test_self_code_manage` から実 URL（`https://rtc10.example/cb`）に変えた** |

> **経緯は `programs/CommonLibrary/ANALYSIS.md` の 13 節。**
> **もともと SaaS 基盤にしたかった**ので決済を実装していたが、
> **認証基盤に注力する**ことにし、**維持の手間に見合わない**ため取り下げた。
> **管理画面の「トークンを取る」も同時に落とした**
> （**決済の WebAPI `/ChageToUser` を呼ぶためのもの**だった）。

**種データは「登録が無ければ入れる（在れば触らない）」**ので、
**登録値を変えたときは、作り直さないと古い値のままになる。**

> **実測（2026/10/09）** : `mem` と `sql` は 561/0/1 で通ったが、
> **`npg` だけ `RT-C10.1` が落ちた。**
> **DB を見ると `TestClient_15` の `redirect_uri_code` が
> `test_self_code_manage` のまま**だった（`sql` 側は新しい値が入っていた）。
> **コードの不具合ではなく、作り直していない `store/` の側である。**

**列が残っていても、アプリは動く**（`SELECT *` で読み、INSERT・UPDATE では触らない）。
**実測 : 列が在る `sql` の DB に対して 561/0/1 で通った。**
**使っている DB から落とすなら、手で `ALTER TABLE ... DROP COLUMN` する。**

#### WebAuthn を復活させ、`Users.FIDO2PublicKey` を落とした（#137）

**DDL が変わったので、`store/` は作り直すこと**
（`2_DockerComposeDown.bat` → `1_DockerComposeUp.bat`）。

| | |
|---|---|
| **落とした列** | `Users.FIDO2PublicKey`（3 方言）。**MsPass（Microsoft Passport）専用だった** |
| **表はそのまま** | `FIDO2Data`（`PublicKeyId` / `UserName` / `UnstructuredData`） |
| **入れ物の形が変わった** | `UnstructuredData` に入れる JSON は**自前の `StoredCredential`** になった（以前は `Fido2NetLib.Development.StoredCredential`。**`Development` 名前空間は 3.0 で消えた**） |

**古い行は読めない。** とはいえ、**測った時点で `FIDO2Data` は 0 行だった**
（`store/` の `sql`。#270 の調査）ので、**実際に読む行は存在しない。**

- **E2E** : `RT-137.1`（登録の要求）/ `RT-137.2`（認証の要求）/
  `RT-137.3`（壊れた入力を封筒に入れて 200 で返す）/ `RT-137.4`（challenge を使い回していない）
- **net48 版は退役した**ので、`RT-137.1` / `RT-137.2` の netfx 側は**「口が無いこと」を測る**

##### 登録と認証そのものは、この基盤では測れない

**`navigator.credentials` を呼ぶのはブラウザである。**
**attestation / assertion を作るには、仮想認証器（CDP の WebAuthn ドメイン）が要る。**
**E2E の大半は HttpClient だけなので、ここは測らないと決めてある。**
**描画は `Tests/WebUI`（`UI-n.n`）で測る**（#277 の段階 7）。

**測っているのは、要求を組み立てる段と、壊れた入力の扱いである。**
**「通った」の範囲を広く読まないこと。**

##### 歯が立つことの確かめ方（実施済み）

| 崩したところ | 結果 |
|---|---|
| `appsettings.json` の `FIDOServerMode` を `none` にした | **core の 4 件が落ちた**（netfx の 2 件は通る。そういうテストだから） |
| `CredentialGetOptions` を 1.x の `UserVerificationRequirement.Discouraged` 固定に戻した | **`RT-137.2`（core）だけが落ちた** |

**netfx 側の 2 件は「無いこと」を測っている**ので、
**歯を確かめるには退役させた画面を戻すことになる。それはやっていない。**

#### CORS の許可オリジンのキャッシュをやめた（#271）

**`GetCorsAllowedOrigins` は毎回作るようになった。**
**話題になるのは「要求ごとに DB を読むのか」だが、**
**引くのは `Origin` 付きの要求のときだけ**である。

| | |
|---|---|
| **引く口** | `MpasBrowserApi` ポリシーのみ（`/token` `/userinfo` `/SetDeviceToken` `/ciba_result` `/2fa_result`） |
| **公開情報の口** | **全開なので引かない**（`MpasPublicDocs`） |
| **通しの中で `Origin` を送る箇所** | **12**（すべて `CorsTests`） |

**通しの所要時間は、この変更の指標にならない。**
`sql` は**同じコードで 170 秒と 229 秒**を記録しており、
このセッションでは **131〜229 秒**の幅で変動した。
**1 要求あたりのコストは、下のように別で測る。**

##### 1 要求あたりのコスト（実測 2026/10/06）

**同じミドルウェアで A/B にする。**
**一覧を引くポリシー（`MpasBrowserApi`）と、引かないポリシー（`MpasPublicDocs`。全開）**に、
**同じプリフライト（`OPTIONS`）を 300 回ずつ**当てる。
**プリフライトなので、本体の処理は走らない。**

| `UserStoreType` | 引かない | 引く | **差** |
|---|---|---|---|
| `mem` | 0.22 ms（p50 0.20） | 0.29 ms（p50 0.28） | **＋0.07 ms** |
| `sql`（`store/` 1434、19 行） | 0.22 ms（p50 0.20） | **2.10 ms**（p50 2.05 / p95 2.80 / 最大 7.86） | **＋1.9 ms** |

**尺度の参考** : 同じ機械で `GET /.well-known/openid-configuration`（200。
Discovery の JSON を組む）が **平均 0.96 ms**（p95 1.26）。

**キャッシュが当たっていた頃のコストは、「引かない」の 0.2 ms 相当**である
（錠を取って `List` を返すだけ）。**DB ストアでは 1 要求あたり約 1.9 ms の上乗せ**になった。

| | |
|---|---|
| **払うのはクロスオリジンの要求だけ** | `Origin` が無ければ **CORS の評価そのものが走らない** |
| **SPA の 1 回の呼び出し** | **プリフライト ＋ 本体の 2 要求**なので、実質 **＋約 3.8 ms**（`sql`） |
| **測っていないこと** | **`/token` 自体のコストとの比**。署名と DB 書き込みを伴うので相対的には小さいはずだが、**数値は持っていない** |
| **条件** | **ローカルの Docker の SQL Server** での値。**DB が遠い配備では比例して増える** |

**重くなったときは `IDistributedCache`**（#256）。
**redis 往復 1 回に置き換わる**が、**net10.0 だけ**で、
`SessionStoreType` が `mem` なら効かない。

###### 測り方の記録（同じことをするなら）

**クライアント側の時間では測れない。**
PowerShell の `HttpClient` では **1 要求約 9 ms のオーバヘッド**が乗り、
**0.2〜2 ms の信号が埋もれる。**

**実際に一度しくじった。** PowerShell で測った「＋0.72 ms / ＋0.19 ms」は、
**要求がサーバに届いていなかった**（Kestrel のログに 4 行しか無かった）。
**数値が出ていても、当たっているとは限らない。**

```powershell
# サイトを単体で起動する（パスの前置きは付かないので、口は / 直下）
cd root\programs\MultiPurposeAuthSiteCore\MultiPurposeAuthSiteCore\bin\Debug\net10.0
$env:FxContainerization = 'ON'; $env:ASPNETCORE_URLS = 'https://localhost:44300'
Start-Process .\MultiPurposeAuthSite.exe -RedirectStandardOutput "$env:TEMP\mpas.out.log"

# 種データを作らせる（これが無いと登録が 0 件になる）
Invoke-WebRequest https://localhost:44300/Account/Login -SkipCertificateCheck

# curl で当てる（url = を並べると接続を使い回す）
curl.exe --config preflight.cfg

# 時間は Kestrel のログから読む
#   "Request finished HTTP/1.1 OPTIONS <url> - 204 - - 2.0510ms"
```

**`Access-Control-Allow-Origin` が返っていることを先に確かめること。**
**許可されていなくても 204 は返る**ので、状態コードだけでは分からない。

**E2E は足していない。**
**この変更で消える「最長 60 秒の窓」は、インスタンス 1 つでは見えない**
（サイトは 1 インスタンスずつしか立てない）。
**利用者の削除で消える側は 1 インスタンスでも見える**が、
**種データのクライアントを消すことになり、同じ通しの他のテストを壊す**。
**許可オリジンの計算そのものは `RT-265.1` / `RT-266.1` / `RT-269.1` が見ている。**

#### クライアント登録を専用列に切り出した（#270）

**`Saml2OAuth2Data` は `ClientID` ＋ `UnstructuredData`（JSON 1 列）だった。**
**17 列にした**（属性名と同じ列名。幅は `Const.MaxLengthOfUri` などに合わせてある）。

**測るときに注意が要るのは 1 列だけである。**

| | |
|---|---|
| **`RequirePkce` は、登録項目で唯一の `bool`** | **方言ごとに形が違う** — SQL Server `bit` / PostgreSQL `boolean` / **Oracle は `NUMBER(3)` の `-1`**（`Users` の bool 列と同じ流儀） |
| **そこが落ちても、画面とビルドは黙っている** | **「登録で PKCE を必須にしたつもりのクライアントが、PKCE 無しを受け入れる」**になる |
| **既存の `RT-221.1` では測れない** | `TestClient6` は**構成ファイル側**なので、`Helper` は user store を見に来ない |

- **E2E** : **`RT-270.1`**（**画面登録側**の `require_pkce`。種データ `TestClient_18`）
- **歯が立つことを確かめてある** : `mem` の複製と Oracle の書き込みを
  それぞれ `false` / `0` に崩して、**両方で落ちる**ことを見た
  （Oracle は**行を消してから回す**こと。種データは**登録が無いときだけ書く**ので、
  行が残っていると壊した書き込みが走らず、**通ってしまって測れない**）
- **幅の実測**（`sql` / `npg` / `ora` とも同じ） : 19 行。`WebOrigins` 最大 **503**、
  `JwkRsaPublickey` 最大 **586**、`RedirectUriSaml` 最大 **486**
  — **以前はこれを全部足して 1 列に入れていた**ので 2000 文字を超えていた

**以前の実測（2026/10/02）** : `sql` と `ora` は**毎回 1 件ほど落ちていた**
（`RT-230.3` / `RT-233.2` など。回すたびに変わる）。

#### 同じ行を 2 つのものが書くと、間欠で落ちる — **✅ 直した（#260）**

**原因は 3 つあった。どれも「同じ利用者の行を、2 つのものが書く」ことである。**

| | 誰と誰が | 直し方 |
|---|---|---|
| 1 | **net48 版と net10.0 版**（DB ストアでは 1 つの DB を共有する） | **テスト利用者をサイトごとに分けた**（`super_tanaka_core` / `_netfx`） |
| 2 | **CIBA の端末登録（`DeviceToken`）と、非構造化データ（`UnstructuredData`）** | **同じコレクションに入れた**（並行させない） |
| 3 | **`UsersAdmin` と `RolesAdmin`**（同じ管理者でサインインする） | 同上 |

**`mem` では 1 が起きない**（各サイトが自前のストアを持つ）。**2 と 3 は `mem` でも起こりうる。**

**1 の仕組み。** `test.ps1` が、サイトごとに接尾辞を渡す。

| 渡す先 | 環境変数 | 値 |
|---|---|---|
| サイト（種データの名前に付く） | `TestUserSuffix` | `_core` / `_netfx` |
| テスト（同じ値を見る） | `MPAS_CORE_TESTUSER_SUFFIX` / `MPAS_NETFX_TESTUSER_SUFFIX` | 同上 |

**製品の既定は空**（＝ `super_tanaka` / `tanaka`）。**接尾辞を与えるのは `test.ps1` だけ**である。

> **上流（ID フェデレーションの IdP）には渡さない。**
> 上流は `store/` のコンテナで**自分のストアを持つ**ので、分ける必要が無い。
> 渡すと「上流に居ない利用者」でサインインしようとして落ちる（`TestEnv.UpstreamUserName`）。

> **DB を作り直さなくてよい。**
> **初期化済みの DB でも、テスト利用者だけは「居なければ作る」**ようにした
> （`AccountController.CreateTestUsers`）。接尾辞を変えても追随する。

**2 と 3 は、xUnit のコレクションで直列化している。**
**同じコレクションのクラスは並行しない**という仕組みで、#224 から在るもの（`DeviceCollection`）を広げた。

| コレクション | 入っているクラス |
|---|---|
| 既定の利用者の行を書くテスト | `CibaTests` / `CibaRequestTests` / `CibaClientModeTests` / `UserClaimsTests` |
| 管理画面（管理者でサインインする） | `UsersAdminTests` / `RolesAdminTests` |

**実測での見分け方。**

| 症状 | 原因 |
|---|---|
| `RT-230.*` で、入れた `usd1` / `usd2` が**消える** | 端末登録が同じ行を書いた（2） |
| `RolesAdmin` / `UsersAdmin` の画面が **302**（サインイン画面へ） | もう片方の変更で**認証 Cookie が無効になった**（3。`SecurityStamp`） |

> **実行順への依存も 1 つ直した**（#260）。
> **サイトは `GET /Account/Login` と `GET /Account/Register` でしか種データを作らない。**
> `RT-210.1` は `/ros` と `/ciba_authz` しか叩かないので、
> **他のテストがサインインしていなければ、利用者が居なかった**（`unknown_user_id`）。
> **単独で回すと必ず落ちていた。** いまはテストの中で 1 回踏んでから進む。

#### net10.0 版が `ora` / `npg` でロールを付けられなかった — **✅ 直した（#257 で判明）**

**ASP.NET Core Identity は、ストアに「正規化した名前」（大文字）を渡す。**
**`CmnUserStore` の DBMS 分岐は、`Roles.Name`（生の名前）と突き合わせていた。**

| ストア | 以前 | 結果 |
|---|---|---|
| `mem` | **`NormalizedName`**（`#if NETCORE` で分けてあった） | 通っていた |
| `sql` | `Name` | **照合順序が大文字小文字を区別しないので、偶然通っていた** |
| `ora` / `npg` | `Name` | **一致せず、副問い合わせが NULL になり、挿入が失敗していた** |

```
ORA-01400: ("SCOTT"."UserRoles"."RoleId")にはNULLは挿入できません。
```

**直し方** : `AddToRole` / `RemoveFromRole` / `UpdateRoles` の 3 方言（9 文）で、
**`#if NETCORE` のときだけ `NormalizedName` 列と突き合わせる**
（`GetRoles` は**生の名前を返す**ので、そのまま）。

**なぜ見つけにくかったか。**

- **例外が握り潰される**（`catch { Logging.MySQLLogForEx(ex); }`）。
  **画面にもテストにも出ず、「ロールが付いていない」だけが残る**
- **種データの作成は 1 回しか走らない**（`IsDBMSInitialized`）。
  **最初に失敗すると、作り直すまで直らない**
- **net48 版（Identity 2.x）は正規化しない**ので、同じ DB でも**そちらの経路では付いていた**
- **`SystemAdmin` を要求する画面が無かった**（#257 の管理画面のテストが、初めてそこを踏んだ）
- **記録は `root/files/resource/Log/SQLTRACE.*.log`**（`MySQLLogForEx` の出力）

**実測（直した後）** : `npg` の `UserRoles` に **6 行**（管理者 3 ＋ `super_tanaka` 2 ＋ `tanaka` 1）が入り、
**管理画面の 9 ケースが Skip されなくなった**（`ora` も同じ）。

### 古いデータベースを使い回すと、列が足りない（#245 の段階 3 で踏んだ）

**DDL は更新されるが、既に作ってあるデータベースは更新されない。**
移行スクリプトは持っていないため、**使い回すなら DDL と突き合わせること。**

**実際に起きたこと。** `npg` と `ora` の `RefreshTokenDictionary` に、
**#188 で足した 2 列（`FamilyId` / `UsedDate`）が無かった。**
`sql` は作り直してあったので揃っていた。

> **列だけでなく、表が増えることもある。**
> **#151 の段階 2 で `SubjectIdentifier` を足した**（16 表 → **17 表**）。
> **`store/`（E2E）は `2_DockerComposeDown.bat` → `1_DockerComposeUp.bat` で作り直せば済む。**
> **手動確認の DB（LocalServicesOnDocker）は、自分で `Create_UserStore.sql` を流し直すこと。**
> 表が無いと、**サインイン（`sub` の記録）で落ちる。**

> **種データの「利用者名」も変わった**（#151 の段階 3。**実測 2026/10/02**）。
> **古い DB の利用者名はメアドのまま**である（当時は「利用者名＝メアド」だった）。
>
> | | 古い DB に入っている値 | いまの種データ |
> |---|---|---|
> | テスト利用者 | `super_tanaka@gmail.com` | **`super_tanaka`** |
> | 管理者 | `daisuke...@...`（メアド全体） | **メアドの `@` より前** |
>
> **`CreateData` は「初期化済みなら何もしない」**ので、**作り直さない限り直らない。**
> **症状は「サインインに失敗しました（HTTP 200）」が全件**に出る
> （実測 : `sql` で **339 件 失敗**）。**列が足りないときより分かりにくい。**
> **`store/` は作り直すこと**（`2_DockerComposeDown.bat` → `1_DockerComposeUp.bat`）。

- 症状は **HTTP 500 が 67 件**（`42703: column "familyid" ... does not exist`）。
  **トークンが出ないので、関係の無いケースまで巻き添えで落ちる**（85 件 失敗）
- **エラーはサイトのログに出る**（`programs\Tests\E2ETests\Result\MpasSite.out.log`）。
  E2E の失敗メッセージは「`前提: access_token が返ること`」までしか言わない

**突き合わせ方**（列の一覧を出して、DDL と比べる）。

```powershell
# PostgreSQL
docker exec -e PGPASSWORD=<pw> <container> psql -U postgres -d UserStore -tAc `
  "SELECT table_name || '.' || column_name FROM information_schema.columns WHERE table_schema='public'"

# Oracle（"..." で囲った大文字小文字混在の名前で作ってある）
select lower(table_name)||'.'||lower(column_name) from user_tab_columns;
```

**足りないだけなら、作り直さずに足せる。**

```sql
-- PostgreSQL（行が無ければ NOT NULL をそのまま足せる）
ALTER TABLE RefreshTokenDictionary
    ADD COLUMN FamilyId varchar(64) NOT NULL, ADD COLUMN UsedDate timestamp;

-- Oracle（行が在ると ORA-01758 になる。NULL 可で足す → 埋める → NOT NULL にする）
ALTER TABLE "RefreshTokenDictionary" ADD ("FamilyId" NVARCHAR2(64), "UsedDate" DATE);
UPDATE "RefreshTokenDictionary" SET "FamilyId" = SUBSTR("Key", 1, 64) WHERE "FamilyId" IS NULL;
COMMIT;
ALTER TABLE "RefreshTokenDictionary" MODIFY ("FamilyId" NOT NULL);
```

> **`Create_UserStore.sql` を流し直すのが正道である。** 上は**行を消さずに済ませる**手順で、
> **古い行が残ることを承知で使うもの**である（テスト用のストアなので、それで困らない）。

> **`mem` と違い、状態が残る。** 同じデータベースを使い回すと、前回のテスト ユーザや
> クライアント登録がそのまま残る。作り直したいときは、データベースを作り直す。

### セッションの置き場も、3 通りで測った（#256）

**`SessionStoreType` は `UserStoreType` と直交する。** 回し方は同じで、
**`appsettings.json` を書き換えてから net10.0 版を建て直す**（環境変数の口は作っていない）。

```powershell
# appsettings.json の SessionStoreType / SessionStoreConnectionString を書き換えてから
cd root
.\1_BuildAll.ps1 -Only net10.0 -SkipClean
.\2_RunAllTests.ps1 -Launch
```

**2026/10/06 の実測**（`UserStoreType` は `mem`）。

| `SessionStoreType` | 成功 | 失敗 | Skip | 置き場に入ったか |
|---|---|---|---|---|
| `mem`（既定。**キー無しも同じ経路**） | 490 | 0 | 1 | － |
| `redis` | 490 | 0 | 1 | **Redis のキーが 1 → 27 件に増えた**（`redis-cli dbsize`） |
| `sql` | 490 | 0 | 1 | **`dbo.SessionCache` に 26 行**（`SELECT COUNT(*)`） |

**「通った」だけでは足りない。** `mem` でも全部通るので、
**置き場に本当に書かれたかを、ストア側から数えて確かめる。**

**Skip 1 件は `core` の未修正項目**（6 節）で、この設定とは関係しない。

**接続文字列を空にすると、起動時に落ちることも確かめた**（`InvalidOperationException`）。
**歯が立つことの確認** — 空のまま起動を通してしまうと、
**画面が 500 を返すだけで理由が分からない**（`IDistributedCache` は遅延で落ちるため）。

**E2E に専用のテストは足していない。**
**どの置き場を使っているかは、外から叩いて区別できない**（同じ画面が同じように動く）。
**通し × 3 通り ＋ ストア側の件数**が、この変更の検証である
（`UserStoreType` の 4 ストアと同じ測り方）。

### テスト専用クライアントは、種データで作る（#264）

**E2E は、構成ファイルに無いクライアント登録を要る**（`TestClient_8` など）。
**サーバ側の種データが、テスト利用者の登録（`saml2OAuth2Data`）として作る。**

```
root/programs/CommonLibrary/Extensions/Sts/TestClients.cs   表（16 件）
    ↓  AccountController.CreateTestUsers（IsDebug ＋ TestUserPWD）
利用者 1 人 ＝ クライアント登録 1 件（client_name は利用者名そのもの）
```

| | |
|---|---|
| **構成ファイルに残すもの** | 自己テスト画面が名前で選ぶもの（`TestClient`〜`TestClient6`。`HomeController` に直書き）、`IdFederation`、サンプル RP |
| **種データで作るもの** | **E2E だけが使うもの**（16 件。`Tests/README.md`） |

- **`-Launch` は要らない。** **手で起動したサイトに対しても測れる**
- **`client_id` は固定値。** **`Sts.TestClients.Entries` と `Flows.KnownClients.SeededClientIds`
  を同じ値にしておくこと**（E2E は構成ファイルを読む作りで、user store は読めない）
- **件数の上限が無い。** user store は 1 件ずつ別の行になる

> **種データは `GET /Account/Login` でしか作られない**（`CreateData`。#210 で踏んだ）。
> **`TargetTestBase.Client` が 1 度だけ呼んで揃えている**（`TargetInfo.EnsureSeedData`）。
>
> **これを入れる前は、サインインしないテストが 401 で落ちた**（`RT-237.*`）。
> **環境変数で渡していた頃はプロセス開始から在った**ので、順番に依存しなかった。
> **寄せたことで「作られるまで無い」状態が生まれ、先に走るクラスに依存して間欠で落ちた。**
> **PowerShell 5.1 の通しで出た**（7 では、たまたま先にサインインするクラスが走って通っていた）。

#### 以前は環境変数で差し込んでいて、件数に上限があった（#262 で踏んだ）

**net48 版だけ、クライアント一覧を 1 本の環境変数で渡していた。**

```
net10.0 : appSettings__OAuth2ClientsInformation__<client_id>__<項目>   … 1 件ずつ足せる
net48   : OAuth2ClientsInformation                                      … 一覧ごと差し替える
```

**1 件増えるごとに約 1.3 KB 伸び**（写す元が JWK 2 本を持つため）、
**Windows の環境ブロックは変数すべてで 32,767 文字**までだった。

| 差し込み件数 | `OAuth2ClientsInformation` の長さ |
|---|---|
| 16 件（#262 の時点） | 約 26.2 KB |
| 17 件 | 約 27.5 KB（**他の変数と合わせて上限を超える**） |
| **0 件（#264 の後）** | **差し込まない**（構成ファイルの 7.4 KB だけ） |

**超えると、こう出た。** **同じ罠は他の環境変数でも起こりうる**ので、残しておく。

- **IIS Express は起動する**（ポートは開き、プロセスも残る）
- **が、全要求が HTTP 500 になる。** `/.well-known/openid-configuration` も 500
- **`Log` に例外が出ない。** `IisExpress.out.log` には `HTTP status 500.0` だけが並ぶ
- **`SmokeTests` が 12 件すべて落ちる**ので、「net48 版が起動していない」ようにしか見えない

**切り分けは、同じ `applicationhost.config` で手で起動すること。**
**手で起動すると 200 が返る**なら、原因はコードではなく**環境変数**である
（手での起動は `test.ps1` の環境変数を引き継がないため）。

```
& "$env:ProgramFiles\IIS Express\iisexpress.exe" /config:<生成された applicationhost.config> /site:MultiPurposeAuthSite
```

## 2. 構造

**3 層になっている。** OpenTouryo が `root/programs/*.ps1` から `CS/*.bat` を呼ぶのと同じ形。

```
root/2_RunAllTests.ps1          呼び出しと集計（TRX を読む）
  └ programs/Tests/test.ps1     どう起動して、どう流すか
      └ dotnet test → E2ETests  xUnit
```

分けてある理由。

- `test.ps1` は **`Tests` フォルダから直接叩ける入口**になる。1 件だけ流すときに使う
- `2_RunAllTests.ps1` は**集計だけ**を持つ。起動方法が変わっても、こちらは影響を受けない

## 3. テストは外から叩く

テストはアプリを **HTTP で外から叩く。** 実装側のクラス（`CmnEndpoints` / `Helper` など）を参照しない。

JWT のデコードも Request Object の署名も、テスト側で独立に実装している。
**同じコードで作って同じコードで読むと、型や値の誤りを検出できない**ためである。

このため、**サイトが動いていることが前提**になる。

**同梱の自己テスト（`/Home/Saml2OAuth2Starters`）とは役割が違う。**
自己テストは **Open棟梁 のクライアント ライブラリ**を使い、**人が目で確かめる**ための場で、
E2E は**自前の実装で外から叩き、合否を判定する。**
**E2E から自己テストを駆動してよい**（`IdPClient.StartSelfTestAsync`）。
Open棟梁 のクライアントを通る経路はそこしか無いので、**相互接続性の回帰だけは E2E が押さえる**
（`RT-197` / `RT-246`）。線引きの全文は
[`programs/MultiPurposeAuthSiteCore/ANALYSIS.md`](programs/MultiPurposeAuthSiteCore/ANALYSIS.md) 7 節。

## 4. 起動する URL を合わせる（重要）

**サイトは、構成ファイルに書かれた URL で待ち受けている必要がある。**

アプリ同梱の自己テスト（FAPI2 / CIBA / Device AuthZ）は、
サーバ自身が `OAuth2AuthorizationServerEndpointsRootURI` へ **HTTP で折り返す。**
叩き先と構成が食い違うと、その折り返しが接続不能になり **HTTP 500** になる。

**https で動かすこと。**
認証まわりの Cookie は `SameSite=None` で発行されるため、**http では保持されない。**
`max_age` を使うフロー（FAPI2）は `auth_time` Cookie を見るので、http だとエラー画面になる。

Visual Studio（IIS Express）で起動する分には、構成ファイルのままなので食い違わない。
`-Launch` は、**構成ファイルを書き換えずに、環境変数で上書きしてから**起動する。

```
OAuth2AuthorizationServerEndpointsRootURI
OAuth2ClientEndpointsRootURI
FcmOutboxDirectory
```

`FcmOutboxDirectory` は、プッシュ通知の送信箱（テスト用）。サイトは FCM に送らず、ここにファイルを書く。
テストは `MPAS_CORE_FCM_OUTBOX` / `MPAS_NETFX_FCM_OUTBOX` で場所を受け取り、認証デバイスの代わりに読む（CIBA の `EX-8`）。

Open棟梁 の `GetConfigParameter` は、`appSettings` の `FxContainerization` が `ON` のとき
**設定ファイルより環境変数を優先する**（net48 / net10.0 の両方）。
**キー名がそのまま環境変数名になる。** 接頭辞は付かない。

このため、**net48 版を `app.config` の URL に置く必要がない。**
別のポートへ寄せられるので、2 つのサイトを同時に立てても衝突しない。

> **環境変数は、子プロセスの起動時に写される。**
> 2 つのサイトへ別々の URL を渡せるのは、この性質による。
> 起動の直前に書き換えること。後から変えても、動いている側には効かない。

詳細は [`CONFIGURATION.md`](CONFIGURATION.md)。

## 5. 判定基準

### 識別子

テストには識別子が付いている。**原本と報告は、これで突き合わせる。**

| 接頭辞 | 対象 | 置き場所 |
|---|---|---|
| `SM-n` | 疎通（テスト基盤そのものの確認） | `Tests/SmokeTests.cs` |
| `TC-n.n` | 基本テストケース（OAuth 2.0 / OIDC の基本的な検証項目） | `Tests/Basic/` |
| `EX-n.n` | 拡張仕様（Revocation / Introspection / Device / Hybrid / response_mode / JWT Bearer / CIBA） | `Tests/Extended/` |
| `RT-<Issue>.n` | 個別 Issue の回帰（`RT-186.2` なら #186 の 2 番目） | `Tests/Issues/` |
| `RT-C<n>.n` | **公開の Issue を持たない項目**の回帰（`RT-C10.1` なら `ANALYSIS-IdP.md` の C-10） | `Tests/Issues/` |
| `FA-n.n` | FAPI（クライアント登録 ＝ `oauth2_oidc_mode` ごとに通る経路） | `Tests/Fapi/` |
| `21-n.n` | OAuth 2.1（許されない経路の抑止） | `Tests/OAuth21/` |
| `SA-n.n` | **SAML2**（Web Browser SSO。#275） | `Tests/Saml/` |
| `CN-n.n` | **コンテナ配備**（疎通と配備固有。#284） | `Tests/Container/` |
| `UI-n.n` | **ブラウザでしか測れないもの**（描画・JavaScript。#277 の段階 7） | `Tests/WebUI/` |

#### `UI-n.n`（ブラウザで測るもの）

| | |
|---|---|
| **ここに置くもの** | **ブラウザでしか測れないもの**。**描画**（見て分かるか）、**JavaScript が要る画面**、**ブラウザ側の Cookie の扱い** |
| **ここに置かないもの** | **HttpClient で測れるもの。** 分野別のフォルダに置く |
| 駆動 | Playwright for .NET（Chromium → Chrome → Edge の順に、入っているものを使う） |
| ブラウザが無いとき | **Skip**（`playwright.ps1 install chromium`、または Chrome / Edge を入れる） |
| 既定 | **走る。** **動かしたくなければ `-NoWebUI`** |

> **なぜ要るか。** **#277 の段階 6 の不具合**
> （Bootstrap 5 の `.form-control` が `appearance: none` を付け、**チェックの印が描かれなかった**）は、
> **HttpClient では原理的に見えない。** **値は正しく往復していた。**

**ブラウザには、クライアント証明書を渡している**（`Infrastructure/WebUi.cs`）。

**`test.ps1 -Launch` は、mTLS を測るために
`ClientCertificateMode.AllowCertificate` で net10.0 版を起動する**（`MtlsTestHook`。#226）。
**「無くても通す」設定だが、TLS では、サーバが証明書を要求する。**
**HttpClient は持っていなければ空で答えて先に進むが、
ブラウザは「どれを出すか」を人に選ばせる**ので、**画面の無い Chromium はそこで止まる。**

> **実測（2026/10/10）** : **`goto` が 30 秒で時間切れ**になり、**失敗した要求は 0 件**。
> **同じサイトに HttpClient では届いていた**（同じ通しの中の他のテストは全部通る）。
> **フックを読ませずに起動すると、同じ通しの中で 10 秒で通った**ので、**原因はこれだけである。**
> **その場で作った自己署名の証明書を渡して解決した**（**サーバは発行元を問わない**ので、
> **何かを認証しているわけではない**）。**実測 : 同じ通しの中で通る。**

> **`test.ps1` を続けて何度も回すと、net48 版（IIS Express）の起動が失敗することがある**
> （`net48 版が起動できませんでした（終了コード ）`。**実測 2026/10/14**）。
> **`iisexpress.exe` の残りを落として、少し間を置くと通る。**
> **同じ構成を手で起動すると落ちない**ので、**起動の間隔の問題**である。
>
> ```powershell
> Get-Process iisexpress -ErrorAction SilentlyContinue | Stop-Process -Force
> ```

> **それでも、まれに同じ時間切れが出る**（実測 2026/10/13。通し 1 回で `UI-1.1` が 30 秒で時間切れ）。
> **単体では 14 秒で通り、次の通しでも通った**（593 成功 / 失敗 0）。
> **続けて落ちるのでなければ、退行ではない** — **ただし「落ちたから退行ではない」とは読まないこと。**
> **単体で回し、通しをもう 1 度回して、2 回とも通ることを見てから先へ進む。**

### どのテストが、どのサイトとどのストアを使うか（#284）

**上流が常に `mem` であることと、下流が `-UserStoreType` で切り替わることが、
別々に書いてあって組み合わせとして読めなかった**ので、1 枚にした。

| 識別子 | サイト | ストア |
|---|---|---|
| `SM-n` | ホストの core / netfx | **`-UserStoreType`**（`mem` / `sql` / `ora` / `npg`） |
| `TC-n.n` | 同上 | 同上 |
| `EX-n.n` | 同上 | 同上 |
| `RT-<Issue>.n` / `RT-C<n>.n` | 同上 | 同上 |
| **`RT-140.n`**（ID 連携） | **ホストの core / netfx ＋ 上流コンテナ** | **下流 = `-UserStoreType` / 上流 = `mem` 固定**（**クロス ストア**） |
| `FA-n.n` | ホストの core / netfx | `-UserStoreType` |
| `21-n.n` | 同上 | 同上 |
| `SA-n.n` | 同上 | 同上 |
| **`SA-6.n`**（SAML2 の ID 連携） | **ホストの core / netfx ＋ 上流コンテナ** | **下流 = `-UserStoreType` / 上流 = `mem` 固定**（**クロス ストア**。`RT-140.n` と同じ） |
| `SA-7.n`（アサーションの属性） | ホストの core / netfx | `-UserStoreType`（**上流コンテナは要らない**。自己テストの口で測る） |

> **「この配備の値」は共通設定のまま**である（#290。`JwkSetUri` / `SpRp_*CerFilePath`）。
> **上流（相手）の値だけが `IdFederation*` のキー**に在る
> （`IdFederationJwkSetUri` / `IdFederationOidcDiscoveryUrl` / `IdFederationOidcCerFilePath` ほか）。
> **`test.ps1` が渡しているのも、その `IdFederation*` だけ**である。

> **`SA-6.*` の上流の値は、上流のメタデータから引いている**（#291。`test.ps1` が URL を渡している）。
> **設定の口（`…RequestEndpoint`）と鍵（`…CerFilePath`）は受け皿**である。
>
> **歯抜けの測り方**（実測 2026/10/13。`SA-6.*` の 8 件で測った）。
>
> | 壊すもの | 期待する結果 |
> |---|---|
> | **設定の口と鍵の両方**を壊す（メタデータは生かす） | **8/8 通る**（**メタデータが使われている**ことの確認） |
> | **メタデータの URL**を別の `entityID` のサイトに（下流コンテナ） | **8/8 通る**（照合で弾き、設定に倒れる。ログに `The SAML2 metadata entityID did not match the expected entityID.`） |
> | **メタデータの URL**を届かない口に | **8/8 通る**（ログに `The SAML2 metadata could not be read.`） |
> | **メタデータと鍵の両方**を壊す | **`SA-6.1` / `SA-6.2` / `SA-6.4` が落ちる**（`SA-6.3` は署名に依存しないので通る） |

> **Open棟梁 の複製を更新したら、コンテナも作り直すこと**（`1_BuildAll.ps1 -Libs Force` → `3_PublishUpstream.ps1` → `docker compose up -d --build`）。
> **実測（Open棟梁 #603 / #604 の取り込み。2026/10/12）** : **複製だけを更新して回すと 20 件が落ちた** — **`SigAlg` の扱い**（`SA-1.1` / `SA-1.3` / `RT-246.4` / `RT-246.7` / `SA-6.*`）と、**自己テストの `aud` の確認**（`RT-246.1` / `RT-246.6` / `RT-232.9`）である。
> **どちらも「確認するようになった」ことによる失敗**であり、緩む方向ではない。
| **`CN-n.n`** | **下流コンテナ ＋ 上流コンテナ** | **両方 `mem` 固定**（切り替えない） |
| **`UI-n.n`** | **ホストの core だけ**（net48 版には WebAuthn の口が無い。#137） | `-UserStoreType` |

**役割分担で言うと、こうなる。**

| | 測るもの |
|---|---|
| ホストの core / netfx（`mem` / `sql` / `ora` / `npg`） | **実装**（方言ごとの SQL を含む） |
| `RT-140.*` | **ID 連携の機能**（OIDC） ＋ **連携キーの永続**（クロス ストア） |
| **`SA-6.*`** | **ID 連携の機能**（**SAML2**。#286） |
| `SA-7.*` | **アサーションの属性**（#286 の段階 4。**メアド・利用者名・`email_verified`**） |
| **`CN-*`** | **配備の差**（コンテナ特有のもの） |

> **クロス ストアは、ただ通っているだけでない。**
> **実測（2026/10/08。`-UserStoreType sql`）** : `RT-140.2`〜`.7` が core / netfx ともに OK。
> 下流の `UserLogins` に **連携キー `(iss, sub)` の行が 2 件**入り、
> **2 回目はそれを引いて同じ利用者になる**（`RT-140.5`）。
> **`mem` では静的な辞書で済むところが、`sql` では方言ごとの SQL（`CmnUserStore`）を通る。**

> **段階に分けた Issue は、段階ごとに番号を伸ばす**。
> 例 : **#272 の段階 1** は `RT-272.1`〜`RT-272.3`で、
> **段階 2（同意の永続化）はその続き番号になる。**

報告書の一覧と詳細、原本は、この順（**SM → TC → EX → RT → FA → 21 → SA → CN**）に並ぶ。

**土台から順に並べる。**
SM が倒れていれば、TC の合否は読む意味がない。
サイトに届いていない・サインインできていない、という話であって、
**仕様に適合しているかどうか以前**だからである。
同じ理由で、拡張（EX）は基本（TC）の上に乗っている。
TC が倒れている状態の EX は、拡張の問題なのか土台の問題なのかを判断できない。RT も同じ。

先に出る群が倒れていたら、**後ろは読まずに原因を潰す。**

### 報告は 2 つに分かれている

**説明と結果を混ぜない。**

| | 場所 | いつ変わるか |
|---|---|---|
| **原本**（何を・何を根拠に確かめるのか） | `programs\Tests\TESTCASES.md` | **テストを変えたときだけ**。リポジトリに入れる |
| **報告**（その回に何が起きたか） | `Result\E2ETests.report.md` | 実行のたび。`.gitignore` 済み |

観点・根拠・手順は実行しても変わらないので、毎回刷り直さない。
報告は「検証・観測の期待と実測」だけを持ち、冒頭から原本へリンクする。

**妥当性を評価するときは、両方を渡すこと。**

原本はテストの記録から生成する。**テスト コードが一次情報**である。

**`Skip` にしているテストは実行されないので、記録が出ない。**
そのぶんは「保留中のテストケース」として、`Skip` の理由から別枠で載る。
このため **`Skip` の理由は「未修正」で始め、Issue 番号・実測日・実測結果を書く**

```powershell
.\2_RunAllTests.ps1 -Launch -UpdateTestCases
```

> **原本を作り直すときは、IdP の 3 コンテナも起こしておくこと**
> （`store\1_DockerComposeUp.bat`。**アプリを直したなら `docker compose up -d --build`**）。
> **止めたまま作り直すと、`CN-*` と `RT-140.4` 以降が原本から消える** —
> **通しで Skip されたケースは記録が出ないので、載らない**（上の `Skip` の話と同じ）。
>
> **実測 2026/10/18（#306）** : コンテナを止めたまま回して **原本が 302 件に縮んだ**
> （起こして回し直すと **329 件**。通しも **Skip 49 → 6**）。

### net48 版も同時に測る

**`-Launch` は 2 つのサイトを立てる。** **原本のケースを、両系統に同じだけ流す。**
実測 2026/10/06 : **491 件**（原本 248 件 × 2 − 片系統だけのもの）。**成功 490 / 失敗 0 / Skip 1**。**数は増え続けるので、ここに書いた値は目安である**（正確な数は実行結果と `TESTCASES.md` を見る）。

| 対象 | 待ち受け | 立て方 |
|---|---|---|
| net10.0 | `https://localhost:44300` | Kestrel（ビルド済みの `MultiPurposeAuthSite.exe`） |
| net48 | `https://localhost:44302` | IIS Express |

> **`dotnet run` は使わない。**
> アプリを子プロセスとして起動するため、親（`dotnet`）を止めてもアプリが残り、
> 次回の起動がポートを奪われる。ビルド済みの exe を直接起動すれば、
> 止めた時点で確実に終わる。

**報告書は 1 回の実行で上書きされる。**
別々に測ると、後から測った方しか残らない。**両方を残したいなら、同じ実行で測る。**

net48 版は ASP.NET なので Kestrel では動かない。`test.ps1` は IIS Express の雛形

```
%ProgramFiles%\IIS Express\config\templates\PersonalWebServer\applicationhost.config
```

を読み、サイト 1 つ分を書き換えて `Result\applicationhost.config` に出す。

- 物理パス : `programs\MultiPurposeAuthSite\MultiPurposeAuthSite`
- バインド : `https` の `*:44302:localhost`
- 44300〜44399 は IIS Express の開発用証明書が http.sys に登録済みなので、そのまま使える

**仮想ディレクトリは作らない。**
待ち受け URL は環境変数で構成へ反映されるので（4 節）、
`/MultiPurposeAuthSite` の下に置く必要がない。アプリはサイト直下に置く。

立てられないときは、**理由を出してその対象を Skip する。** 失敗にはしない。

| 状況 | 見るところ |
|---|---|
| `-NoNetFx` を付けた | 意図的に測らない |
| IIS Express が無い | `%ProgramFiles%\IIS Express\iisexpress.exe` |
| net48 版がビルドされていない | `1_BuildAll.ps1`（`bin\MultiPurposeAuthSite.dll`） |

> **`.vs` を消すと、Visual Studio 用の `applicationhost.config` は消える。**
> `1_DeleteDir.bat` の削除対象に `.vs` が入っているため。
> `test.ps1` が使うのは自前で作る方なので、こちらは影響を受けない。

### mTLS（`FA-6`）と、net48 版の `-NetFxMtls`

**mTLS（クライアント証明書）のテストは、既定では net10.0 版だけを測る**（#226）。
`-Launch` は、テスト専用のフック `programs/Tests/MtlsTestHook` を net10.0 版にだけ読ませ、
発行元を問わずにクライアント証明書を受け付けさせる（アプリのコードは変えない）。
証明書はテストがその場で作る自己署名のもので、証明書ストアには入れない。

**net48 版（IIS Express）は、準備だけを手動で行い、`-NetFxMtls` を付けて回す。**
IIS は信頼できない証明書を、アプリより前で **HTTP 403.16** として断る。
自己署名の証明書を通す設定は IIS に無いので、**テスト用 CA をコンピューターの信頼されたルートに入れる**（管理者権限）。
`-NetFxMtls` を付けなければ、net48 版のケースは作らない（Skip にもならない）。

> **実施済み（2026/09/23。Windows 11 / IIS Express 10）。**
> net48 版でも `FA-6` の 4 件が通った（`-NetFxMtls` 付きで 276 件 / 失敗 0 / Skip 0）。
>
> **測り直した（2026/09/29。#245 の段階 3）** : **414 成功 / 失敗 0 / Skip 4**
> （Skip は `RT-245.4` ×2 ＝ C-10 未修正、`RT-246.3` ×2 ＝ mTLS フックの副作用。core 2 / netfx 2）。
> **既定の通し（410 / 0 / 3）と比べて、`FA-6` の netfx が 5 件増え、`RT-246.3` の netfx が Skip に回った。**
> 手順は [`SetupNetFxMtls.ps1`](SetupNetFxMtls.ps1)（下記）。
>
> **管理者権限と後片付けが要るため、通しの一部にはしていない。**
> **`-NetFxMtls` を付けない限り、`FA-6` の net48 版は測られない**（net10.0 版は毎回測っている）。
> **失効の情報（CRL）を持たない証明書でも、IIS は通した。**
>
> **クライアント証明書を要求させるのは `/token` と `/userinfo` だけ**
> （`applicationhost.config` の `location path="MPAS48/token"` / `"MPAS48/userinfo"`）。
> `/token` は mTLS のクライアント認証、`/userinfo` は証明書に紐づくトークン（`cnf`）の照合に要る。
> **サイト全体に掛けない。** net48 版の FAPI2 の自己テスト（サーバが自分自身を HTTPS で呼ぶ）が
> 証明書を求められて止まり、`RT-197.1` が 60 秒で時間切れになる（実測で切り分けた）。
>
> なお、**5.1 で起動待ちが 90 秒で失敗する不具合**が、この手順で見つかって直っている（#226）。
> 証明書のネゴシエーションが入ると、サーバ証明書の検証がランスペースの無いスレッドで呼ばれるため、
> `ServerCertificateValidationCallback` が**スクリプト ブロックでは実行できない**。
> `test.ps1` は、コンパイルしたデリゲートを使う（`CODING.md` 5 節）。

**手順は [`SetupNetFxMtls.ps1`](SetupNetFxMtls.ps1) にある**（#245 の段階 3 でファイルにした）。
**シークレットは含まない。** 私有鍵は証明書ストアの中で生成され、スクリプトには現れない
（`Trust` が読む `.cer` は**公開部分だけ**）。

```powershell
cd root
.\SetupNetFxMtls.ps1 -Action Prepare   # 通常の PowerShell。CA ＋ クライアント証明書 2 枚を作る
.\SetupNetFxMtls.ps1 -Action Trust     # **管理者**。CA を信頼されたルートに入れる
.\2_RunAllTests.ps1 -Launch -NetFxMtls # 通常の PowerShell（証明書を作った利用者）
.\SetupNetFxMtls.ps1 -Action Cleanup   # **管理者**。必ず行う（信頼されたルートに残さない）

.\SetupNetFxMtls.ps1 -Action Check     # いま何が在るかを見る
```

**`Prepare` と `Trust` を分けてあるのは、証明書の入る先が違うからである。**
`TestCertificate.ForTarget` は、netfx のとき **`CurrentUser\My` を Subject で引く**。
**管理者の PowerShell が別アカウントなら、証明書は別の利用者のストアに入り、テストから見えない**
（症状は「証明書がありません」）。同じアカウントで昇格するなら、まとめて実行しても同じ結果になる。

- **`-UpdateTestCases` は付けない。** 原本に netfx の mTLS ケースが混ざる
- `Prepare` / `Check` は、**Subject が E2E の定数（`Flows.cs` / `MtlsTests.cs`）と一致することを確かめる。**
  綴りが違えば、その場で止まる
- 別アカウントで `Prepare` / `Trust` をするなら、**両方に同じ `-CerPath` を渡す**（`%TEMP%` が違う）

**期待する結果**（既定の通しは 410 成功 / 失敗 0 / Skip 3）。

| 変わるところ | 期待 |
|---|---|
| `FA-6.1`〜`FA-6.5` の **netfx** | **5 件増えて成功**（付けないと対象すら作られない） |
| `RT-246.3` の **netfx** | **成功 → Skip**（netfx もクライアント証明書を要求するため。既知の副作用） |
| 失敗 | **0 のまま** |

### ID フェデレーション（#140 / #250 の段階 5）

**E2E で駆動している**（`RT-140.4` 〜 `RT-140.7`）。**上流の IdP が要る。**

| | |
|---|---|
| `RT-140.4` | 連携でサインインできる（**PKCE(S256)** を付け、**`prompt` を付けない**ことも見る。#287） |
| `RT-140.5` | **二度目の連携でも同じ利用者**になる（連携キーが `(iss, sub)` であること） |
| `RT-140.6` | **上流が未サインインなら成立しない**（**上流がサインイン画面を出し、`code` は返らない**） |
| `RT-140.7` | 連携の認可応答にも **`iss`** が付く（#252 が実経路で効いていること） |

> **上流は、下流と別の RSA 鍵を使う**（#293 の段階 1）。
> **`store/docker-compose.yml` の upstream が `*_Upstream.pfx` / `.cer` と
> `JwkSet_Upstream.json` に向けている**（**EC の 3 本は共有**）。
>
> | | 公開している RSA の `kid`（実測 2026/10/13） |
> |---|---|
> | 上流（44301） | `ZB2dUcdK9F7wPQ38…` |
> | 下流（44303） | `W8YPrSZDTP6XB0VT…` |
>
> **鍵を作り直すときは `root/files/resource/X509/GenRsaCertForUpstreamByOpenSSL.bat`**、
> **その後に上流用の JwkSet を作り直す**（`CreateJwkSetJson` を上流の設定で 1 回）。
>
> **歯抜け（鍵が本当に分かれているか）** : **メタデータ / discovery を落とし、
> (3) の倒れ先を「下流自身の証明書」に向ける**と、
> **`RT-140.4` / `.5` と `SA-6.1` / `.2` / `.4` が落ちる**（**16 件中 10 件**。実測 2026/10/13）。
> **鍵が同じだった頃は、この取り違えが通っていた。**
>
> **上流は (2)（下流が送る `AuthnRequest`）の署名も検証する**（#293 の段階 2）。
> **`store/docker-compose.yml` の E2E クライアント 3 件に `jwk_rsa_publickey` を登録してある**
> （値は `*_Client.cer` の JWK）。
>
> **歯抜け（署名が検証されているか）** : **登録鍵を別の鍵に差し替える**と、
> **`SA-6.1` / `.2` / `.4` が落ち、`RT-140.*` は通ったまま**になる
> （**16 件中 6 件が失敗**。実測 2026/10/13）。
> **OIDC の (2) には署名が無い**ので、**SAML 側だけが落ちるのが正しい。**

##### 歯抜けのうち 2 つは、常設のケースにした（#293 の段階 4）

**歯抜けは、本来「人が壊して確かめる手順」である。**
**配備を壊さずに測れるものは、通しに入れた方がよい** — **手順は、やらなければ測られない。**

| | ケース | 何が落ちたら気付けるか |
|---|---|---|
| **(2) の署名の検証** | **`SA-6.5`** | **上流の `jwk_rsa_publickey` の登録**（外れると「鍵がない場合は、通す」に入る） |
| **脚ごとの鍵の分離** | **`CN-1.5`** | **上流コンテナの `RsaPfxFilePath` / `JwkSetFilePath` の上書き**（外れると上流と下流が同じ鍵になる） |

**`SA-6.5` は、配備を壊さない。**
**製品が署名した本物の `AuthnRequest` の、署名だけを 1 バイト反転して送る**
（`Saml2.ReplaceQueryValue`。**`SAMLRequest` と `SigAlg` は 1 文字も触らない**）。

**どちらも「落ちることを確かめてから」入れた**（**制御実験**。実測 2026/10/13）。

| 外したもの | 結果 |
|---|---|
| 上流の `jwk_rsa_publickey`（ホストの E2E クライアント 2 件） | **`SA-6.5` が core / netfx とも失敗**（`Requester` の所が **`Success`**） |
| 上流コンテナの `*_Upstream` への上書き 3 件 | **`CN-1.5` が失敗**（`kid が違う` の所が **同じ `W8YPrSZD…`**） |

> **落ちることを見ていないケースは、歯抜けの代わりにならない。**
> **「通っている」だけでは、測れていないのと区別が付かない。**

**手順のまま残すもの**（**配備を壊さないと測れない**）。

| | なぜ常設にしないか |
|---|---|
| **(3) の検証鍵の取り違え**（メタデータ / discovery を落とし、鍵を下流自身の証明書に） | **下流の設定を書き換える**ことになる（`test.ps1` / compose の環境変数）。**通しの中では替えられない** |
| **メタデータ / discovery の優先順**（設定の `.cer` だけを壊す、など） | 同上。**倒れ先に落ちて通る**ことを見る測り方なので、**合否では表せない** |

> **上流の `id_token` の検証鍵は、上流の discovery から引いている**（#289 の段階 2）。
> **discovery の URL も `test.ps1` が渡している**（`IdFederationOidcDiscoveryUrl`。
> **空なら `IdFederationAuthorizeEndpoint` の基底から組み立てる**）。
> **設定の `.cer`**（`IdFederationOidcCerFilePath`）**は受け皿**である。
>
> **歯抜けの測り方**（実測 2026/10/12）。
>
> | 壊すもの | 期待する結果 |
> |---|---|
> | **設定の `.cer` だけ**を別の証明書に | **通る**（**discovery が優先される**ことの確認） |
> | **discovery の宛先**を別の issuer のサイトに（下流コンテナ） | **通る**（`issuer` 不一致で弾き、`.cer` に倒れる。ログに `The discovery issuer did not match the expected issuer.`） |
> | **discovery の宛先**を届かない口に | **通る**（ログに `The discovery document could not be read.`） |
> | **両方**（discovery も `.cer` も壊す） | **`RT-140.4` / `RT-140.5` が落ちる**（**自分の JWK Set に落ちて通ってしまうことが無い**） |
> | **設定の discovery の URL だけ**を届かない口に（`.cer` も壊す） | **`RT-140.4` / `RT-140.5` が落ちる**（**設定が組み立てより先に見られている**ことの確認。ログに `The discovery document could not be read.`） |

**上流を先に建てておくこと。** 建っていなければ、**この 4 件（×2 ターゲット）だけが Skip される。**

```powershell
cd store
.\3_PublishUpstream.ps1
docker compose up -d upstream
```

> **建て忘れると、黙って Skip される。** 「全テスト OK」と出ても、**連携は測れていない。**
> **Skip の件数**（サマリに出る）と、**Skip の理由**で気付くこと。

> **上流は「作り直さないと古いまま」である。** ここが一番踏みやすい。
> **アプリを直したら、必ず `3_PublishUpstream.ps1` と `docker compose up -d --build upstream` を回す。**
>
> **実測（#250 の段階 5）** : `FormPost.cshtml` を直した（#252）あと、**上流を作り直さずに**
> `RT-140.7` を回して落ちた。**下流は新しく、上流だけが古い**という状態で、
> **「直したはずのものが直っていない」ように見える。**

#### 作り直すと、同意の記録が消える（#280）

**上流は `UserStoreType=mem`** なので、
**作り直すと同意の記録（#272 の段階 2）も消える**
（`Sts.ConsentProvider.ConsentGrants` は静的な辞書）。

**記録が無い上流では、同意画面で止まる**（**どこでも「許可」を押さないため**）。

> **`prompt=none` を外す前**（#287 より前）は、**`consent_required` で終わっていた**
> （OIDC Core §3.1.2.6。**IdP の側は仕様どおりである**）。

**実測（2026/10/08。作り直した直後の通し）** : **6 件が落ちた**
（`RT-140.4` / `.5` / `.7` × core / netfx）。症状は
`RT-140.4 code が返る / 期待=code あり 実測=**無し**` で、**退行に見える。**

**#280 で、テスト側が前提を整えるようにした**
（`IdFederationTests.EnsureUpstreamConsentAsync`）。

- **1 度だけ叩き、同意画面が出たら「許可」を押す**
- **記録が在れば同意画面は出ない**ので、何もしない（**余分な往復もしない**）
- **上流が未サインインならログイン画面が返る**ので、押さない
  （`RT-140.6` の意味は変わらない）

> **「許可が押せること」は測っていない。** 測るのは ID 連携の一巡である。
> **整えられなければ「`code` が返らない」として落ちる**ので、
> **前提の失敗が隠れることはない。**

**実測（#280 の後。同じく作り直した直後）** : `IdFederationTests` は **8 / 8 OK**。
上流のログでは **`consent_required` が 2 回**（core / netfx の 1 回目）出たあと、
**同意画面が 2 回描画され**、そのあと `code` が返っている。

**下流の同意（`RT-272` 系）とは別の話である。**
`TestClient_19` / `TestClient_20` は、**下流の「記録が無い状態」を測るために在る。**

**下流の設定は `test.ps1` が差し込む**（`Set-IdFederationEnv`）。

| 設定 | 値 |
|---|---|
| `OAuth2AndOidcClientID` / `Secret` | **ターゲットごとに別のクライアント**（`redirect_uri` は 1 件に 1 つのため） |
| `IdFederationRedirectEndpoint` | そのサイトの URL ＋ `/Account/IDFederationRedirectEndPoint` |
| **`IdFederationSaml2*`（4 本）** | **SAML2 の ID 連携**（#286 の段階 2）。上流の SSO の口・自分の ACS・期待する上流の Issuer・上流の署名証明書 |

**上流のエンドポイント（`IdFederation{Authorize,Token,UserInfo}Endpoint`）は上書きしない。**
**構成ファイルの値が、そのままサイトの向き先である。**
**テストはその値を読んで上流を探す**ので、上書きすると、両者がずれたときに気付けなくなる。

**上流側のクライアント登録は `store/docker-compose.yml` にある**（`IdFederationE2ECore` / `IdFederationE2ENetFx`）。
**雛形の `IdFederation` クライアントは手動確認（VS）用**で、`/MultiPurposeAuthSite` 付きのまま残してある。

**SAML2 の ID 連携は、同じクライアントに `redirect_uri_saml` を足して使う**（#286 の段階 2）。
**上流は `Issuer`（`http://` ＋ `client_id`）で SP を引く**ので、**OIDC と同じ登録で足りる。**
**返す先は登録値から解決する**ので、**下流の ACS を 1 文字違わず登録すること**（#263 と同じ照合）。

> **実測（2026/10/10。#286 の段階 2）** : **下流コンテナ ⇔ 上流コンテナで一巡した。**
> **2 度目も同じ利用者**（連携キー `(上流の EntityID, NameID)` で引けている）。
> **ログに `has signed in with a SAML2 ID federation` が出る。**

**上流は `preferred_username` も返す**（`docker-compose.yml` の `UserClaimsMapping`。#151 の段階 4）。
**`subject_types` の既定が `public` になり、`sub` は利用者 ID になった**ので、
**下流が新規に作る利用者名は、`preferred_username` から取る**
（無ければメアドの `@` より前。`CONFIGURATION.md`「ID 連携・外部ログインで作られる利用者名」）。

> **入れ忘れても連携は成立する**（鍵はメアドなので）。
> **変わるのは、新規に作られる利用者の名前だけ**である。

**#140 の段階 3 で、この経路をまとめて直した**
（連携キーを `(iss, sub)` へ／認可応答の `iss` を検証／PKCE(S256) を追加／
要求スコープを標準だけに／`Helper` のホスト書き換えを回避）。
**ビルドと通し（414 件）で「他を壊していないこと」までは確かめたが、
経路そのものは動かしていない。**

**上流のコンテナは #250 の段階 2〜3 で建った**（1 節「上流の IdP も `store/` で立てる」）。
**段階 4 で、下流の設定をそこへ向け、目視が net48 版・net10.0 版の両方で通った。**
**段階 5 で E2E に入れた**（`RT-140.4` 〜 `RT-140.7`。5 節「ID フェデレーション」）。
**上流を建て忘れると Skip される**ので、そこだけは人が見ること。

#### 目視の手順（#250 の段階 4）

1. **上流を建てる。**

   ```powershell
   cd store
   .\3_PublishUpstream.ps1
   docker compose up -d upstream
   ```

2. **上流でサインインしておく。** `https://localhost:44301/Account/Login`
   **先にセッションを作っておくと、確かめたい経路だけを通せる。**
   **無くても構わない**（**上流がサインイン画面を出す**。#287 で `prompt=none` を外した）。

3. **下流を VS から動かす**（net48 版 / net10.0 版のどちらでも）。
   **どちらも `https://localhost:44300/MultiPurposeAuthSite` で待ち受ける**ので、
   **上流に登録済みの `IdFederation` クライアントの `redirect_uri_code` と一致する。**

4. **下流の `/Account/Login` で「ID連携でサインイン」を押す。**

**向け先は雛形に入れてある**（`_appsettings.json` / `_app.config`）。**書き換えは要らない。**

> **Cookie の名前を、上流と下流で分けてある**（#250 の段階 4）。
> **Cookie のスコープにポートは入らない**（RFC 6265 §8.5）ので、
> `localhost:44300`（下流）と `localhost:44301`（上流）は **Cookie を共有する。**
> 名前が同じだと、次の 2 つが起きる（**どちらも実測した**）。
>
> | 同名の Cookie | 症状 |
> |---|---|
> | セッション（`MultiPurposeAuthSiteCoreSession`） | **上流のサインインが下流のセッションを消す** → `state` / `nonce` が読めず「エラー」画面 |
> | 認証（`.AspNetCore.Identity.Application`） | **後にサインインした側が相手を蹴り出す** → 連携は正常終了するのに**下流がサインイン状態にならない** |
>
> **`docker-compose.yml` が、上流に別名と接頭辞を与えている**（#250 の段階 4 / #255）。
> **雛形の既定は空＝従来どおり**なので、**1 サイトだけの配備には影響しない。**
>
> **接頭辞は、名前を決められるものすべてに掛かる**（実測）。
>
> ```
> .upstream_MultiPurposeAuthSite                     認証（サインイン）
> upstream_Identity.External                         外部ログイン・ID 連携の途中
> upstream_MultiPurposeAuthSiteSession               セッション
> upstream_auth_time / upstream_re_auth_at           max_age の判定
> .upstream_AspNetCore.Mvc.CookieTempDataProvider    画面のメッセージ
> ```
>
> **先頭が `.` のものは、その後ろに接頭辞が入る**（`.` は host-only を表す慣習なので潰さない）。
>
> **サインインの Cookie だけでは足りない。** **外部ログイン（`Identity.External`）は
> ID フェデレーションの途中で使う**ので、ここが混ざると連携が壊れる。
> `auth_time` は**再認証の要否**、TempData は**画面のメッセージ**に効く。
>
> **分けられないものが 1 つ残っている。**
>
> | Cookie | いまの扱い |
> |---|---|
> | `SessionTimeOut` | **Open棟梁 の定数**（`FxHttpCookieIndex`）。雛形は `FxSessionTimeOutCheck` を `off` にしており、**読まれないので無害**。分けるなら Open棟梁 側の対応が要る |
>
> **net48 版は、そもそも同名になりにくい**（実測）。
> セッションは `mas_session`、AntiForgery は `__RequestVerificationToken` で、
> **net10.0 版の名前と重ならない。TempData は Cookie に載らない**（セッションに載る）。
> **ただし net48 版どうしを同じホストに立てると、`__RequestVerificationToken` が衝突する。**
> **いまの構成では起きない**（上流は net10.0 版のコンテナ 1 つ）。
>
> **net48 版の下流では、もともと起きない**（Owin の既定名が `.AspNet.ApplicationCookie` で、
> net10.0 版と重ならないため）。**net10.0 版の下流でだけ出る。**
>
> **上流のコンテナを作り直す前に触っていたブラウザには、古い Cookie が残る。**
> 直したあとも直らないときは、**`localhost` の Cookie を消してから試すこと。**

| 設定 | 値 |
|---|---|
| `IdFederationAuthorizeEndpoint` | `https://localhost:44301/authorize` |
| `IdFederationTokenEndpoint` | `https://localhost:44301/token` |
| `IdFederationUserInfoEndpoint` | `https://localhost:44301/userinfo` |
| `IdFederationRedirectEndpoint` | `https://localhost:44300/MultiPurposeAuthSite/Account/IDFederationRedirectEndPoint` |

> **`/MultiPurposeAuthSite` を外した**（#250 の段階 4）。**コンテナは root で配信する。**
> 付いていたのは IIS Express の仮想ディレクトリの形で、**上流の実体が無かった。**

#### 上流側は、下流を通さずに測ってある（#250 の段階 4）

**下流がすることを、そのまま上流に対して行って確かめた。**

| 手順 | 結果 |
|---|---|
| 上流でサインイン | OK |
| `/authorize`（`prompt=none` / PKCE S256 / `response_mode=form_post`） | **200。`code` と `state` が自動送信フォームで返る** |
| `/token`（`code` ＋ `code_verifier` ＋ Basic 認証） | **`access_token` / `id_token` / `refresh_token`** |
| `id_token` の `iss` / `aud` / `nonce` | `https://ssoauth.opentouryo.com` / `06d2…`（一致）/ 一致 |
| `/userinfo` の `sub` | **`id_token` の `sub` と一致**（OIDC Core §5.3.2） |
| `/userinfo` の `email_verified` | **`true`**（C-23 の判定を通る） |
| `code_verifier` を外した `/token` | **400 で拒否**（C-22 の守り） |

**残っているのは「下流がこれを受け取って、利用者を作る／結び付ける」ところだけである。**

#### 失敗したら、下流の OPERATION ログを見る（#253）

**`Error` 画面が出たときの理由は、すべて OPERATION ログに出る**（`C:\root\files\resource\Log\OPERATION.<日付>.log`）。

```
The state of the authorization response did not match the session. (response: len=32, session: (empty))
The id_token of the ID federation was not accepted. (verified: True, nonce matched: False)
The token response of the ID federation had no id_token.
The iss of the authorization response did not match the expected issuer.
The sub of /userinfo did not match the sub of the id_token.
The id_token had no iss claim.
The ID federation redirect endpoint is locked down. (IsLockedDownTestEndpoints)
The ID federation did not complete. (the error view was returned)
```

**最後の 1 行は、経路の終わりを示す受け皿である。**
**それだけが出ていたら、利用者の作成か外部ログインの追加に失敗している**（そこは `AddErrors` するだけで画面に出ない）。

> **`state` / `nonce` の値そのものは出さない**（`(empty)` か `len=<長さ>` だけ）。
> **切り分けに要るのはそこまでである。**

> **目視で 2 つ見つけた**（#250 の段階 4）。**どちらも E2E では出なかった。**
>
> | 見つけたもの | 出る側 |
> |---|---|
> | **Cookie の名前が上流と下流で同じ**（認証 / セッション） | **net10.0 版の下流だけ**（net48 版は Owin の既定名が違う） |
> | **`OAuth2AndOIDCClient.HttpClient` が初期化されていない** | **net48 版だけ**（net10.0 版は `Program.Main` で入れている） |
>
> **後者は #140 の段階 3 の副作用である。** ID フェデレーションが `Helper` を通さなくなり、
> **`Helper` のコンストラクタが設定していた `HttpClient` が入らなくなった**（`/token` で null 参照）。
> **`Global.asax.cs` の `Application_Start` で、net10.0 版と同じように入れる**ようにした。
>
> **この 2 つは、E2E に入れていれば見つかった。** 段階 5 の理由がここにある。

> **`sub` は利用者 ID（GUID）である。** 上流の `IdFederation` クライアントに
> `subject_types` の登録が無く、**既定（`public`）に従うため**（#151 の段階 4。
> **それより前は利用者名＝メアドが入っていた**）。
> **連携キー `(iss, sub)` はこの値で作られる。**
>
> **既定を変えると、既存の連携は鍵が合わなくなる。**
> **その場合はメアドで引き直して、新しい鍵を足す**
> （下流の `IDFederationRedirectEndPoint`。**上流が `email_verified` を言っている必要がある**）。
> **つまり張り直しは自動で起きる**が、**上流が検証済みと言わない場合は結び付けない。**

> **`id_token` には `email` / `email_verified` が入らない。**
> 下流は **`/userinfo` から読む**ので、C-23 の判定はそちらで通る。

> **上流はコンテナ 1 つで、下流は 2 つとも E2E が立てるサイトである。**
> `-Launch` が立てる 2 サイト（net48 / net10.0）を、**どちらも同じ上流へ向ける。**
>
> **Cookie は 1 つの入れ物で扱う**（`IdPClient` の `CookieContainer`。ブラウザと同じ）。
> **上流と下流が同じホストでも成り立つのは、Cookie 名を分けたからである**（#250 の段階 4）。

### 画面を駆動するテスト（#257）

**サインアップ（`/Account/Register`）と管理画面（`/UsersAdmin` / `/RolesAdmin`）を、HTTP で叩いている。**
**どれも、それまで 1 件も無かった**（#151 の段階 3 の不具合 2 件が、目視まで出てこなかった）。

| | |
|---|---|
| `RT-257.1` | 利用者名とメアドを入れると、サインアップできる |
| `RT-257.2` | 利用者名に `@` → **モデル全体のエラー**になる |
| `RT-257.3` | 利用者名が空／メアドが空 → **それぞれの欄のエラー**になる（あべこべにならない） |
| `RT-257.4` | メアドの形式が不正 → メアドの欄のエラー |
| `RT-257.5` | 一覧に、利用者名とメアドが**別の列**で出る |
| `RT-257.6` | **作成の検証エラーで 500 にならず**、ロールの選択肢が出たまま再表示される |
| `RT-257.7` | 作成でき、編集画面に 2 つの値が別々に出る |
| `RT-257.8` | **編集の検証エラーで 500 にならず**、ロールのチェックボックスが出たまま再表示される |
| `RT-257.9` | **管理画面は `SystemAdmin` のときだけ開く**（付与の前後を 1 つで通す） |
| `RT-257.10` | ロールの一覧に、種データの 3 つのロールが出る |
| `RT-257.11` | ロールを作ると一覧に出て、削除すると消える |
| `RT-257.12` | ロールの詳細に、属する利用者が出る（**0 人の分岐も通す**） |
| `RT-257.13` | ロール名が空のとき、500 にならず、その欄のエラーになる |

**#258 で管理画面を net10.0 版へ移植したので、`AllTargets` で両系統を測っている。**

#### 認可は、付与の前後で測る（`RT-257.9`）

**門番（`Authorize`）とメニューの出し分けは、どちらも `SystemAdmin` を見る。**
**`Admin` では開かない**（雛形のテスト利用者は `User` / `Admin` しか持たない）。

1. 使い捨ての利用者を**管理画面から作る**（`EmailConfirmed=true` で作られるので、そのままサインインできる）
2. その利用者では**一覧が開かず、メニューに導線も出ない**
3. 管理者が **`SystemAdmin` を付与**する
4. **入り直すと開き、導線も出る**
5. 利用者を削除する

> **入り直さないと効かない。** ロールは**サインインのときに Cookie のクレームへ入る**ので、
> **付与しただけでは、その人の今のセッションは変わらない**（テストは `force: true` で入り直す）。
>
> **種データの利用者には付与しない。** 戻し忘れると、
> **DB ストアで権限が残り続け、他のテストの前提が変わる。**

#### 判定は、文言に依存させない

**画面の言語は配備（サーバの既定カルチャ）で変わる。**
**タイトルや見出しの文字列では判定しない。**

| 見るもの | 意味 |
|---|---|
| 入力欄の `name` が在るか（`Html.HasField`） | **どの画面が返ってきたか** |
| 欄に `input-validation-error` が付くか（`Html.HasFieldError`） | **その欄のエラー**（属性が足したもの） |
| 付かずに要約だけに出るか | **モデル全体のエラー**（`ModelState.AddModelError("", …)`） |

**この差で「あべこべ」を測っている。**
**空欄は欄のエラー、`@` はモデル全体のエラー**で、**それが入れ替わっていたのが元の不具合**だった。

#### 管理画面は、管理者で入る

**門番（`Authorize`）とメニューは、どちらも `SystemAdmin` ロールを見る。**
**雛形のテスト利用者（`super_tanaka`）は `User` / `Admin` しか持たない**ので開けない。
**`IdPClient.SignInAsAdministratorAsync`** が、構成ファイルの
`AdministratorUID` / `AdministratorPWD` で入り直す（**値は出力しない**）。

> **`EnableAdministrationOfUsersAndRoles` が false なら Skip される**
> （`UsersAdmin.SkipIfLockedDownAsync`）。

#### 作った利用者は、同じテストの中で消す

**`mem` では再起動で消えるが、DB ストアでは残る。**
**次の回の一覧に積み上がる**ので、**作ったテストが `UsersAdmin/Delete` で消す**
（削除そのものの確認にもなる）。利用者名には `Guid` を混ぜて、衝突を避けている。

> **net48 版は、作成でロールを選ばないと一覧へ戻らない。**
> `params string[]` に何も来ないと **null** になり、
> **利用者は作られるのに作成画面が再表示される**（net10.0 版は空の配列が来るので戻る）。
> **#257 で作った非対称ではなく、元から在る。** テストはロールを 1 つ付けて作っている。

### `subject_types` の既定（#151 の段階 4）

**既定は `public` である**（#151 の段階 4 で変え、段階 5 で独自値を廃止した）。
E2E で 2 件測っている。

| | |
|---|---|
| `RT-151.1` | **`subject_types` を書かないクライアントの `sub` が、利用者名ではなく利用者 ID**（GUID）である |
| `RT-151.2` | **`public` の `sub` は、クライアントが違っても同じ**（`pairwise` との対照） |

**使うのは `TestClient_6` / `TestClient_7`**（**構成ファイルには無い。** 種データが作る。#264）。

> **既に使った `client_id` では、既定を測れない。**
> **発行した `sub` は対応表に記録される**ので（#151 の段階 2）、
> **設定を変えても、その組み合わせでは以前の値が返る**（それが段階 2 の目的である）。
> **新しい `client_id` を使うと、表に行が無いので、新しい既定で作られる。**
>
> **だから、既定の判定は「新しい client_id でだけ」行うこと。**
> `TestClient` や `MVC_Sample` で `sub` の値を決め打ちすると、
> **`mem` では新しい既定、使い回した DB では以前の値**になり、ストアによって結果が変わる。

**`sub` の値そのもので「誰か」を判定しているテストは、すべて直した**（段階 4）。

| 直したところ | いまの判定 |
|---|---|
| `TC-6.2`（id_token の必須クレーム） | **`sub` が `/userinfo` の `sub` と一致する**（OIDC Core §5.3.2） |
| `TC-6.5` / `RT-196.7`（`/userinfo`） | **`sub` が `id_token` の `sub` と一致する** |
| `EX-4.3`（Device AuthZ） | **`/userinfo` の `email`** が承認した利用者である |
| `TC-4.1`（ROPC） | トークンの **`email`** が認証した利用者である |

> **`sub` は「同じ利用者・同じ RP なら同じ値」であることに意味がある。**
> **値の形は、配備（既定を変える前か後か）によって違う。**

### DPoP の nonce（`RT-311.13` / `RT-311.14`）と `-DPoPNonce`

**`nonce` は既定では要求しない**（**要求すると、`nonce` を知らないクライアントが全部止まる**）。
そこで `-DPoPNonce` が、**要求する設定でサイトを起動する**（#311 の段階 4）。

```powershell
.\2_RunAllTests.ps1 -Launch -DPoPNonce -Filter "FullyQualifiedName~DPoPNonceTests"
```

- **`-Filter` と併せて使う。** **`nonce` を知らない証明は全部断られる**ので、他の DPoP のテストは落ちる
- **既定の通しでは、`RT-311.13` / `RT-311.14` を除外している**（`test.ps1` が
  `FullyQualifiedName!~DPoPNonceTests` を足す）。
  **xUnit は「ケースが 0 件の Theory」を失敗として数える**ため（`-ShortLifetimes` と同じ事情）
- そのため **この 2 件は `TESTCASES.md`（原本）に載らない。**
  **`-DPoPNonce` の実行で `-UpdateTestCases` を付けないこと**
- **チャレンジのスキーム（`RT-311.12`）は、要求しない配備でも測れる**ので、
  **別のクラス**（`DPoPChallengeTests`）**に在り、通しで走る**

> **実測 2026/10/22（#311 の段階 4）** : **4 成功 / 失敗 0 / Skip 0**（`mem`。net48 版も 44302 で起動した）。
> **鍵（`DPoPNonceSecret`）も渡している** — **渡さないとプロセスごとのランダムになる。**

### 有効期限（`RT-188`）と `-ShortLifetimes`

**既定の寿命（認可コード 600 秒・Request Object 300 秒・refresh_token 14 日）を待つのは現実的でない。**
そこで `-ShortLifetimes` が、寿命をごく短くしてサイトを起動する（#188）。

```powershell
.\2_RunAllTests.ps1 -Launch -ShortLifetimes -Filter "FullyQualifiedName~LifetimeTests"
```

- **`-Filter` と併せて使う。** 寿命が短いので、他のテストは落ちる
- **既定の通しでは、`RT-188` を除外している**（`test.ps1` が `FullyQualifiedName!~LifetimeTests` を足す）。
  既定の寿命では測れず、**xUnit は「ケースが 0 件の Theory」を失敗として数える**ため
- そのため **`RT-188` は `TESTCASES.md`（原本）に載らない。**
  原本は通しの結果から作るので、`-ShortLifetimes` の実行で `-UpdateTestCases` を付けないこと
  （付けると、その 6 件だけの原本に置き換わる）

> **実測 2026/09/29（#245 の段階 3）** : **6 成功 / 失敗 0 / Skip 0**（`mem`）。
> **net48 版も 44302 で起動した。** 以前に見られた起動待ちの時間切れは、**再現しなかった**。

### 取り違えは検出する

**net48 版と net10.0 版は、構成ファイルの既定ではどちらも同じ URL を指している。**
`-Launch` は別のポートへ寄せるが、手で立てた場合や `testsettings.json` で
URL を指定した場合は、**同じ URL を 2 回測ることが起こり得る。**

そのままだと**同じアプリを 2 回測って「両方 OK」と報告する。**（実際にやった）

このため、応答ヘッダで**どちらのアプリが応答したのか**を確かめている。

| | 見分け方 |
|---|---|
| net48 | `X-AspNet-Version` が付く |
| net10.0 | `Server: Kestrel` |

期待と食い違う場合は、そのターゲットを Skip して理由を残す。

```
net10.0版 (MultiPurposeAuthSiteCore) のはずの https://localhost:44302 に、
net48版（ASP.NET Framework）が応答しました。同じURLで構成されているため取り違えます。
片方を別のURLにするか、順番に実行してください。
```

報告書の「叩いた先」も、**`-Url` の値ではなく、実際に応答したアプリ**から作る。
引数を書き写すだけでは、測れていない対象まで「叩いた」ことになってしまう。

```
| 叩いた先 | net10.0版 (MultiPurposeAuthSiteCore) (https://localhost:44300)
            / 応答: net10.0（Kestrel）
            net48版 (MultiPurposeAuthSite) (https://localhost:44302)
            / 応答: net48（ASP.NET Framework / Microsoft-IIS/10.0） |
```

個々のテストの記録にも残る。

```
対象: net48版 (MultiPurposeAuthSite) (https://localhost:44302)
      / 応答: net48（ASP.NET Framework / Microsoft-IIS/10.0）
```

### TRX を読む

コンソールの集計行（`テストの合計数: ...`）は**ロケールで変わる。**
TRX（XML）の `outcome` は `Passed` / `Failed` / `NotExecuted` で固定なので、こちらを読む。

`test.ps1 -TrxPath` が出力先を受け取る。`2_RunAllTests.ps1` がそれを渡している。

### 合否

| 条件 | 判定 |
|---|---|
| 失敗 0 件、かつ**成功 1 件以上** | `OK`（終了コード `0`） |
| 失敗 1 件以上 | `NG`（`1`） |
| **成功 0 件** | `NG`（`1`） |
| TRX が出ていない | `NG`（`1`）。テストの起動そのものに失敗している |

**成功 0 件を NG にしているのが肝。**
サイトを起動し忘れると全件 Skip になり、「失敗 0 件」で緑に見えてしまう。
それがいちばん危ない。

### Skip は失敗ではない

テストは net10.0 版と net48 版の**両方に同じものを流す**（`[SkippableTheory]` ＋ `AllTargets`）。
クロスコンパイルで下位互換版を維持しているので、
**「片方だけ直っている」状態を検出できること**を最優先にしている。

起動していない対象は Skip する。net48 版は IIS Express での手動起動が前提で、
常に動いているとは限らないため、そこで落とさない。

**Skip は 2 種類ある。混ぜて数えると、どちらも見えなくなる。**

```
  Skip 30 件の内訳
        28  netfx          ← そのサイトが起動していないだけ（環境）
         2  (対象なし)     ← 未修正と分かっている項目（仕様）
```

**いま、未修正を理由に `Skip` にしているものは無い**（最後の `RT-245.4` は #263 で外した）。
**既定の通しで残る 1 件は `RT-246.3` core** で、**mTLS フックの副作用**（#226。環境の側）である。

`2_RunAllTests.ps1` は、テスト名の `targetKey: "..."` で切り分けて内訳を出す。

## 6. 未修正の項目の扱い

**未修正だと分かっている項目は、期待する動作を書いたうえで `Skip` にする。**
消さずに残すのは、直したときに `Skip` を外すだけで検証できるようにするため。

`Skip` の理由には、**Issue 番号・実測日・実測結果**を書く。

```csharp
[SkippableTheory(Skip = "未修正（#197）。実測（2026/09/09, net10.0）では、"
    + "誤った redirect_uri を送ってもトークンが発行される。")]
```

現在 `Skip` にしているものは
[`programs/Tests/README.md`](programs/Tests/README.md) の「未修正の項目」にある。

## 7. 実行結果の例

```
================ サマリ ================

対象     結果 成功 失敗 Skip   秒
-------- ---- ---- ---- ---- ----
E2ETests OK    220    0    1 146.7

  Skip 1 件の内訳
         1  (対象なし)

  対象ごとの Skip は、そのサイトが起動していないだけのことが多い。
  (対象なし) は、未修正として Skip 指定しているもの（Tests\README.md）。

  所要時間 : 2.4 分
  TRX      : C:\MultiPurposeAuthSite\root\programs\Tests\E2ETests\Result\E2ETests.trx
  ログ     : C:\MultiPurposeAuthSite\root\programs\Tests\E2ETests\Result\E2ETests.log
  報告書   : C:\MultiPurposeAuthSite\root\programs\Tests\E2ETests\Result\E2ETests.report.md
  原本     : C:\MultiPurposeAuthSite\root\programs\Tests\TESTCASES.md

  全テスト OK
```

## 8. 前提条件

| 前提 | 備考 |
|---|---|
| ビルド済み | `1_BuildAll.ps1`、または Visual Studio |
| 設定ファイル | `appsettings.json` / `app.config`。テストは**ここから資格情報を読む** |
| `UserStoreType` | **既定は `mem`**。テスト ユーザは初回アクセスで作られ、再起動で消える。`sql` / `ora` / `npg` に切り替えるときは 1 節「ストアを切り替える」（#207） |
| `SessionStoreType` | **既定は `mem`**（#256）。**そのままで回る**— E2E は 1 インスタンスずつなので共有が要らない。`redis` / `sql` でも測れる（1 節「セッションの置き場も」）。`sql` にするなら `Create_SessionCache.sql` を流しておく。**net10.0 版だけ**（net48 版は下の `aspnet_state`） |
| 証明書 | `SpRp_RsaPfxFilePath` の pfx。Request Object の署名に使う |
| `FxContainerization` | `ON`。**待ち受け URL の上書きに要る**（4 節）。雛形には入っている |
| IIS Express | net48 版を測るときだけ。無ければその分が Skip される |
| **ASP.NET 状態サービス**（`aspnet_state`） | **net48 版を測るときだけ。** `Web.config` が `mode="StateServer"`（`tcpip=127.0.0.1:42424`）なので、**止まっていると画面が HTTP 500 になる**（下記） |

#### net48 版の画面が 500 になるのに、ログに例外が出ないとき

**`aspnet_state` が止まっていないかを見る。** **スタートアップが「手動」なので、OS の再起動で止まる。**

```powershell
Get-Service aspnet_state          # Stopped なら
Start-Service aspnet_state        # 管理者権限が要る
```

##### 毎回起動しなくて済むようにする

**スタートアップは既定で「手動」である。**
**OS を再起動すると止まる**ので、**net48 版を測る環境では「自動」にしておくと楽である。**

**管理者権限の PowerShell で、次の 2 行。**

```powershell
Set-Service aspnet_state -StartupType Automatic   # 次回以降は OS の起動と同時に上がる
Start-Service aspnet_state                        # いますぐ上げる
```

**管理者権限でないシェルからやるときは、昇格を起こす。**
**`net start aspnet_state` も `Start-Service` も、昇格していなければ断られる**
（「システム エラー 5。アクセスが拒否されました。」/ `Cannot open 'aspnet_state' service`。**実測で踏んだ**）。

```powershell
# UAC の確認が出るので、画面で承認する
Start-Process powershell -Verb RunAs -ArgumentList `
    '-NoProfile','-Command','Set-Service aspnet_state -StartupType Automatic; Start-Service aspnet_state'
```

**入ったかを確かめる**（昇格は要らない）。

```powershell
Get-Service aspnet_state | Select-Object Name, Status, StartType
#   Status = Running / StartType = Automatic なら良い
```

> **自動にしてもメモリの負担は小さい**
> （セッションを持たなければ数 MB。**DB のコンテナとは桁が違う** — 1 節「メモリの抑え方」）。

> **net48 版を測らないなら、上げなくてよい。**
> **`-NoNetFx` で回せば、その分は Skip になるだけである。**

**見分け方。** **`/.well-known/openid-configuration` は 200 を返すのに、`/Account/Login` が 500** になる。
**Web API の口はセッションを使わないが、画面は使う**ためである。
**応答の本文に理由が出る**（「セッション状態要求をセッション状態サーバーに対して作成できませんでした」）。
**アプリのログ（`root/files/resource/Log`）には出ない。** ASP.NET が先に落としている。

> **全部の口が 500 になるときは、別の原因**である（`OAuth2ClientsInformation` を
> 環境変数で渡していた頃の、環境ブロックの上限。1 節）。
> **画面だけが 500 なら、まずこのサービスを疑う。**

**`-Launch` は、mTLS のテスト（`FA-6`）のために net10.0 版にクライアント証明書を要求させる**
（`Tests\MtlsTestHook`。#226。net48 版は `-NetFxMtls` のときだけ）。
**その状態では、アプリ自身の内部呼び出し（自己テスト）も証明書を提示する**
（`Helper` の `HttpClient` が `SpRp_ClientCertPfxFilePath` を添える）。
サーバは**証明書を提示したクライアントをコンフィデンシャル扱いにする**ので、
**公開クライアントで始める自己テストが `invalid_client` になる**（`/device_authz` の `TestClient3`）。
**製品の欠陥ではなく、測り方の都合である。** そのため `RT-246.3` は、要求している側を Skip する。

**構成ファイルの既定では、net10.0 版と net48 版は同じ URL を指している。**
`-Launch` は環境変数で別のポートへ寄せるので、**同時に測れる。**
手で立てるときは、片方を別の URL にすること。
取り違えは検出して Skip する（5 節「取り違えは検出する」）。

## 9. 秘密情報を出さない

`TestUserPWD` / `client_secret` / pfx のパスワードは、
実行時に**アプリ自身の構成ファイルから読み出す。** テスト側は値を持たない。

`client_id` も直書きしない。環境ごとに違う（`CreateClientsIdentity.exe` で生成する）ので、
`client_name`（`TestClient` / `MVC_Sample` など）から引く。

**テストの出力にトークンや秘密情報を書かないこと。**
`JsonResponse.ToString()` はキー名とエラーだけを出す。

```
HTTP 200 / keys=[access_token, expires_in, id_token, refresh_token, token_type] / error=-
```

## 10. テストを足すとき

1. `programs/Tests/E2ETests/Tests/` に置く。ファイル ヘッダは既存に合わせる（[`CODING.md`](CODING.md)）
2. `TargetTestBase` を継承し、`[SkippableTheory]` ＋ `[MemberData(nameof(AllTargets))]` にする
   - net10.0 版でしか成立しないものだけ `CoreOnly` を使う
3. `client_id` は `Flows.Registration(client, KnownClients.XXX)` で引く
4. **未修正の挙動を見つけたら、期待する動作を書いて `Skip`。** Issue を起こして番号を書く
5. `ANALYSIS-IdP.md` にも反映する（あちらが適合上の穴の一覧）

**画面（HTML）の中身を日本語で判定するときは、実体参照を戻してから比べる。**
**net10.0 版の Razor は非 ASCII を数値文字参照（`&#x8A8D;` など）で出す**が、net48 版はそのまま出す。
そのため `html.Contains("認証要求が…")` は **net48 版だけ通る**（`RT-246.2` で踏んだ）。
`System.Net.WebUtility.HtmlDecode` を通してから判定する。
