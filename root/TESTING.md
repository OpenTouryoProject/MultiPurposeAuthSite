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
| `-Filter` | `dotnet test` の `--filter` |
| `-Configuration` | `Debug`（既定）/ `Release` |
| `-OutputDir` | TRX とログの保存先。既定は `programs\Tests\E2ETests\Result`（`.gitignore` 済み） |
| `-UpdateTestCases` | テストケースの原本（`programs\Tests\TESTCASES.md`）を作り直す |
| `-UserStoreType` | サイトが使うストア（`mem` 既定 / `sql` / `ora` / `npg`）。**`mem` 以外は下の「ストアを切り替える」を読む**（#207） |
| `-ConnectionString` | `mem` 以外のときの接続文字列。省略時は環境変数から読む |

### ストアを切り替える（#207）

**既定は `mem`。** これは変えない。`sql` / `ora` / `npg` は、対応する DBMS が
動いていることが前提になるため、既定にすると DBMS の無い環境でテストが回らなくなる。

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
| ストア | **`mem`** | 雛形のテスト利用者が自動で作られる。上流に DB は要らない |
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

**リソースはイメージに入れず、ホストの `C:\root\files\resource` をマウントする**（読み取り専用）。
**署名鍵（`X509` の pfx、`JwkSet.json`）を含む**ため、イメージに焼くべきではない。
中身は [`Readme.ja.md`](Readme.ja.md) の手順で用意されているものを、そのまま使う。

> **雛形の設定は 15 箇所が `C:/root/files/resource/...` である**（Windows 前提）。
> **Linux ではドライブ文字が効かない**ので、`docker-compose.yml` が
> **15 個すべてをマウント先（`/resource`）に振り替えている。**
> **1 つでも漏らすと、その設定を使った瞬間に落ちる**ので、
> `appsettings.json` を `"C:/root/files` で grep した数と突き合わせること。
>
> **`log4net` だけは中身（出力先）も Windows のパス**なので、
> **差し替えた構成**（`store/app/LogConf.xml`）をイメージに入れてある。

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
Invoke-RestMethod https://localhost:44301/jwkcerts   # RS256 と ES256 の 2 つが出る
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

**実測 2026/10/03**（#260 を直した後）。ビルドは net48 / net10.0 とも エラー 0 / 警告 0。

| ストア | 成功 | 失敗 | Skip | 回数 | 備考 |
|---|---|---|---|---|---|
| `mem`（既定） | **474** | **0** | 3 | 2 | `RT-245.4` ×2（C-10 未修正）＋ `RT-246.3` core（mTLS フックの副作用） |
| `sql` | **474** | **0** | 3 | **3** | |
| `ora` | **474** | **0** | 3 | **3** | 以前は間欠で 1 件落ちていた（下記） |
| `npg` | **239** | **0** | 238 | **3** | **net48 版を起動しないぶんが Skip**（`Npgsql` が `#if NETCORE`） |

> **これは #260 を直したときの記録である。** その後に件数と Skip が変わっている。
> **#261 / #262 でケースが増え**、**#263 で `RT-245.4` の Skip が外れた**（C-10 を直したため）。
> **既定（`mem`）の最新は 487 件 / 成功 486 / 失敗 0 / Skip 1**（`RT-246.3` core だけ）。
> **ストアを変えても件数は変わらない**ので、**4 ストアを測り直すのは、ストアに触ったときでよい。**

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

報告書の一覧と詳細、原本は、この順（**SM → TC → EX → RT**）に並ぶ。

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
実測 2026/10/04 : **487 件**（原本 246 件 × 2 − 片系統だけのもの）。**成功 486 / 失敗 0 / Skip 1**。**数は増え続けるので、ここに書いた値は目安である**（正確な数は実行結果と `TESTCASES.md` を見る）。

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
| `RT-140.4` | 連携でサインインできる（**PKCE(S256)** と **`prompt=none`** を付けて要求していることも見る） |
| `RT-140.5` | **二度目の連携でも同じ利用者**になる（連携キーが `(iss, sub)` であること） |
| `RT-140.6` | **上流が未サインインなら成立しない**（`prompt=none` の意味） |
| `RT-140.7` | 連携の認可応答にも **`iss`** が付く（#252 が実経路で効いていること） |

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

**下流の設定は `test.ps1` が差し込む**（`Set-IdFederationEnv`）。

| 設定 | 値 |
|---|---|
| `OAuth2AndOidcClientID` / `Secret` | **ターゲットごとに別のクライアント**（`redirect_uri` は 1 件に 1 つのため） |
| `IdFederationRedirectEndpoint` | そのサイトの URL ＋ `/Account/IDFederationRedirectEndPoint` |

**上流のエンドポイント（`IdFederation{Authorize,Token,UserInfo}Endpoint`）は上書きしない。**
**構成ファイルの値が、そのままサイトの向き先である。**
**テストはその値を読んで上流を探す**ので、上書きすると、両者がずれたときに気付けなくなる。

**上流側のクライアント登録は `store/docker-compose.yml` にある**（`IdFederationE2ECore` / `IdFederationE2ENetFx`）。
**雛形の `IdFederation` クライアントは手動確認（VS）用**で、`/MultiPurposeAuthSite` 付きのまま残してある。

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
   **`prompt=none` で連携するので、先に上流のセッションが要る**（無いと `login_required`）。

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
| 証明書 | `SpRp_RsaPfxFilePath` の pfx。Request Object の署名に使う |
| `FxContainerization` | `ON`。**待ち受け URL の上書きに要る**（4 節）。雛形には入っている |
| IIS Express | net48 版を測るときだけ。無ければその分が Skip される |

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
