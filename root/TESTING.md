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

**このリポジトリの `store/` が、3 方言をまとめて立てる**（SQL Server / Oracle / PostgreSQL）。

```powershell
cd store
.\1_DockerComposeUp.bat      # DDL を流し込んでから起動する
.\2_DockerComposeDown.bat    # -v 付き。作り直せるように残さない
```

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

> **以前は属性を潰す実装だった**（利用者名・メアドを利用者 id で塗り潰す）。
> **潰す対象の `Users.UserName` / `Users.ClientID` は、どちらも外部キーの参照先**であり、
> **`ON UPDATE` の指定は 3 方言とも 1 本も無い**（= NO ACTION）。
>
> **実測（SQL Server。トランザクションを張って試し、ロールバックした）。**
>
> | 試した `UPDATE` | 結果 |
> |---|---|
> | `UPDATE Users SET UserName = Id`（WebAuthn の資格情報を持つ利用者） | **`FK.FIDO2Data.Users_UserName` で弾かれる** |
> | `UPDATE Users SET ClientID = Id`（クライアントを登録した利用者） | **`FK.Saml2OAuth2Data.Users_ClientID` で弾かれる** |
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
**`Saml2OAuth2Data.ClientID` は `Users.ClientID` への外部キーを持っている**ので、
**古い id の利用者が残っていると、新しい id の登録を入れられない。**

```
INSERT ステートメントが FOREIGN KEY 制約 "FK.Saml2OAuth2Data.Users_ClientID" と競合しています。
```

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
Set-Service aspnet_state -StartupType Automatic   # 毎回やりたくないなら
```

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
