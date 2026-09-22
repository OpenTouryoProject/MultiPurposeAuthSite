# CONFIGURATION.md — 設定ファイルの扱い

対象: `root/programs`（net48 版 / net10.0 版）
配置: `root`

本書は**「設定がどこにあり、どう読まれ、どう上書きされ、どこで踏むか」**を扱う。
**個々のキーが何を意味するかは書かない。** それは値の隣（雛形のコメント）にある。

> **一次情報は本書ではない。** 迷ったら次を見ること。
>
> | 内容 | 一次情報 |
> |---|---|
> | 各キーの意味 | `_appsettings.json` / `_app.config` のコメント |
> | 秘密の報告方法 | [`../SECURITY.md`](../SECURITY.md) |
> | ビルド | [`BUILDING.md`](BUILDING.md) |
> | テストからの参照 | [`TESTING.md`](TESTING.md) |

---

## 1. 設定ファイルの種類

| ターゲット | 実体 | 雛形 | 行数 |
|---|---|---|---|
| net10.0 | `programs/MultiPurposeAuthSiteCore/MultiPurposeAuthSiteCore/appsettings.json` | `_appsettings.json` | 約 364 |
| net48 | `programs/MultiPurposeAuthSite/MultiPurposeAuthSite/app.config` | `_app.config` | 約 390 |

**実体は 2 つとも `.gitignore` 済み。** 実際の資格情報を含むため。

```
/root/programs/MultiPurposeAuthSite/MultiPurposeAuthSite/app.config
/root/programs/MultiPurposeAuthSiteCore/MultiPurposeAuthSiteCore/appsettings.json
/root/programs/Tests/E2ETests/testsettings.json
```

**設定を変えたら、雛形（`_` 付き）にも反映する。** clone した人が見るのは雛形だけである。

## 2. net10.0 — `appsettings.json`

3 つのセクションを持つ。

```json
{
  "connectionStrings": { ... },
  "sessionState":      { ... },
  "appSettings":       { ... }   ← ほとんどはここ
}
```

**コメント（`//`）と末尾カンマを含む JSONC である。** 素の `JsonSerializer` では読めない。
機械で読むときは次を指定する。

```csharp
new JsonDocumentOptions()
{
    CommentHandling  = JsonCommentHandling.Skip,
    AllowTrailingCommas = true
}
```

### 環境変数で上書きできる

**階層の区切りは `__`（アンダースコア 2 つ）。**

```
set appSettings__OAuth2AuthorizationServerEndpointsRootURI=https://localhost:44300
```

**net48 版にはこの仕組みが無い。** これは ASP.NET Core の構成の仕組みである。
ただし、次の `FxContainerization` は**両方で使える。**

> **設定ファイルに無いキーは、環境変数だけでは効かない**（実測。2026-09-17）。
> 上書きであって、追加ではない。**新しいキーを試すときは、先にファイルへ足すこと。**
>
> **ただし、「節」として読む設定は例外**（実測。2026-09-22、#224）。
> クライアント一覧（`OAuth2ClientsInformation`）は節ごと読む（`GetAnyConfigSection`）ので、
> `appSettings__OAuth2ClientsInformation__<client_id>__<項目>` で**ファイルに無いクライアントを足せる。**
> 1 個の値として読むキー（`GetConfigValue`）は、上のとおり足せない。
> net48 はクライアント一覧を 1 個の値（JSON 文字列）として読むので、
> `FxContainerization=ON` のうえで `OAuth2ClientsInformation` を**一覧ごと差し替える**必要がある。
> E2E はこれを使って、テスト専用のクライアントを差し込んでいる（`Tests/README.md`）。

### `FxContainerization` — 環境変数を優先する（net48 / net10.0 の両方）

`appSettings` の `FxContainerization` を `ON` にすると、
Open棟梁 の `GetConfigParameter` が**設定ファイルより環境変数を優先する。**

```
<add key="FxContainerization" value="ON" />   app.config
"FxContainerization": "ON",                   appsettings.json
```

**キー名がそのまま環境変数名になる。** 接頭辞は付かない。

```
set OAuth2AuthorizationServerEndpointsRootURI=https://localhost:44302
set OAuth2ClientEndpointsRootURI=https://localhost:44302
```

`root/programs/Tests/test.ps1 -Launch` は、これを使って
**2 つのサイトを別々の URL で同時に立てている**（[`TESTING.md`](TESTING.md) 4 節）。
net48 版を `app.config` の URL に置く必要がないのは、この仕組みによる。

> **`ON` にしただけでは、動きは変わらない。**
> 環境変数が定義されていなければ、設定ファイルの値が使われる。

### `FcmOutboxDirectory` — プッシュ通知の送信箱（テスト用）

**本番では空のままにする。** 設定すると、サーバはプッシュ通知（CIBA、2FA のモバイル アプリ）を FCM に送らず、
このディレクトリに JSON ファイルとして書く。E2E テストが、認証デバイスの代わりにそれを読む（#196）。
送信箱を使うときは、Firebase の資格情報（`FirebaseServiceAccountKey`）を読まない。

`root/programs/Tests/test.ps1 -Launch` が、上の `FxContainerization` の仕組みで、**環境変数として**サイトごとに設定する
（`Tests/E2ETests/Result/fcm/core`・`…/netfx`）。構成ファイルに書く必要は無い。

> **ファイルには、device_token や 2FA のコードがそのまま書かれる。**

## 3. net48 — `app.config`

**`Web.config` から取り込まれる外部 `appSettings` ファイルである。**

```xml
<!-- Web.config -->
<appSettings file="app.config" />
```

このため **`app.config` のルート要素は `<configuration>` ではなく `<appSettings>`。**
`<configuration><appSettings>` を期待して読むと、何も取れない。

```xml
<appSettings>
  <add key="OAuth2AuthorizationServerEndpointsRootURI" value="https://localhost:44300/MultiPurposeAuthSite" />
  ...
</appSettings>
```

## 4. クライアントの登録 — `OAuth2ClientsInformation`

**同じ内容が、2 つの形で入っている。**

| ターゲット | 形 |
|---|---|
| net10.0 | **入れ子の JSON オブジェクト** |
| net48 | **JSON 文字列**（`value='...'` の中に丸ごと） |

```json
"OAuth2ClientsInformation": {
  "67d328bfe8604aae83fb15fa44780d8b": {
    "client_secret": "...",
    "redirect_uri_code": "test_self_code",
    "client_name": "TestClient",
    "subject_types": "uname",         // public, pairwise, uname
    "jwk_rsa_publickey": "..."
  },
  ...
}
```

**`client_id` は環境ごとに違う。** `CommandLineTools` の `CreateClientsIdentity.exe` で生成する。
このため、**コードやテストに `client_id` を直書きしない。** `client_name` から引くこと。

| `client_name` | 用途 |
|---|---|
| `TestClient` | 自己テスト用（`redirect_uri` は `test_self_code` / `test_self_token`） |
| `TestClient1` | FAPI1 |
| `TestClient2` | FAPI2（Request Object を使う） |
| `TestClient3` | Device Authorization Grant。**`client_secret` を持たない**（パブリック クライアント） |
| `TestClient4` | CIBA |
| `TestClient5` | 登録の `scope` で、要求してよいスコープを制限した例（#198、E2E テスト用） |
| `MVC_Sample` ほか | 絶対 URL の `redirect_uri` を持つサンプル |

### `scope` — 要求してよいスコープ（任意）

**クライアントごとに、発行してよいスコープを制限する。** RFC 7591 §2 の client metadata と同じく、
スペース区切りで並べる。

```json
"scope": "openid profile email"
```

発行するスコープは、次の 3 つをすべて満たすものになる。

1. クライアントが要求した
2. Discovery の `scopes_supported` にある（認可サーバが扱う）
3. 登録の `scope` にある

| 登録 | 扱い |
|---|---|
| **項目が無い** | 3 は見ない（`scopes_supported` の範囲だけ）。**既存の登録はこのまま動く** |
| 空文字列 | どのスコープも許さない |

要求を拒否（`invalid_scope`）するのではなく、許されないスコープを外して発行する。
外したときは、トークン応答の `scope` に実際に発行したものを返す（RFC 6749 §5.1）。

> `CreateClientsIdentity` はこの項目を出力しない。必要なクライアントにだけ、手で足す。

### `redirect_uri` の記号

`test_self_code` / `test_self_token` は URL ではなく**記号**である。
サーバが `CmnEndpoints.GetRedirectUriFromConstr` で実 URL に解決する。

```
test_self_code  → OAuth2ClientEndpointsRootURI + OAuth2AuthorizationCodeGrantClient_Account
test_self_token → OAuth2ClientEndpointsRootURI + OAuth2ImplicitGrantClient_Account
```

**`OAuth2AuthorizationServerEndpointsRootURI` ではなく `OAuth2ClientEndpointsRootURI` を使う。**
既定では同じ値だが、変えるときは両方見ること。

## 5. ルート URI と、自己テストの折り返し（重要）

```
OAuth2AuthorizationServerEndpointsRootURI   認可サーバ側のエンドポイントの根
OAuth2ClientEndpointsRootURI                クライアント側（自己テストの受け口）の根
```

既定はどちらも `https://localhost:44300/MultiPurposeAuthSite`。
これは **IIS Express の仮想ディレクトリ**を前提とした値である。

**アプリ同梱の自己テスト（FAPI2 / CIBA / Device AuthZ）は、
サーバ自身がこの URL へ HTTP で折り返す。**

```
POST /Home/Saml2OAuth2Starters
  → サーバが OAuth2AuthorizationServerEndpointsRootURI + /ros へ POST（Request Object の登録）
  → 返ってきた request_uri で /authorize へリダイレクト
```

**待ち受け URL と食い違うと、この折り返しが接続不能になり HTTP 500 になる。**

### Kestrel（`dotnet run`）で動かす場合

`launchSettings.json` の `applicationUrl` はパスを含むが、
**Kestrel は仮想ディレクトリを持たない**（`UsePathBase` も呼んでいない）ので、
`/MultiPurposeAuthSite/...` は 404 になる。

環境変数で構成側を合わせる。

```
set ASPNETCORE_ENVIRONMENT=Development
set appSettings__OAuth2AuthorizationServerEndpointsRootURI=https://localhost:44300
set appSettings__OAuth2ClientEndpointsRootURI=https://localhost:44300
dotnet run --urls https://localhost:44300
```

`FxContainerization` が `ON` なら、**接頭辞なし**の `OAuth2...` でも上書きできる（2 節）。
net48 版と書き方が揃うので、両方を扱うスクリプトはそちらを使っている。

### https で動かすこと

**認証まわりの Cookie は `SameSite=None` で発行される。**
`Secure` が伴わないため、**http では保持されない。**

`max_age` を使うフロー（FAPI2）は `auth_time` Cookie を見るので、
http で動かすと認可エンドポイントがエラー画面になる。

## 6. 秘密の扱い

**`app.config` / `appsettings.json` の内容を、報告・コミット メッセージ・Issue 本文に転記しない。**

含まれるもの。

- `TestUserPWD`
- `OAuth2ClientsInformation` の各 `client_secret`
- `connectionStrings` のパスワード
- `RsaPfxPassword` / `EcdsaPfxPassword` / `SpRp_*PfxPassword`

設定の変更を共有するときは、**雛形（`_app.config` / `_appsettings.json`）側に書く。**
雛形の値はプレースホルダ（`[password of TestUser]` など）である。

E2E テストは、**実行時にアプリ自身の構成ファイルから読み出す。**
テスト コードにもテスト設定にも、秘密は書かない（[`TESTING.md`](TESTING.md) 9 節）。

## 7. `UserStoreType`

```json
"UserStoreType": "mem",   // mem / sql / ora / npg
```

| 値 | 意味 |
|---|---|
| `mem` | メモリ。**再起動で消える。** テスト ユーザは初回アクセスで作られる |
| `sql` | SQL Server |
| `ora` | Oracle |
| `npg` | PostgreSQL |

E2E テストは既定で `mem` を使う。**前後で状態を掃除する必要が無い**のが理由。
`sql` / `ora` / `npg` に切り替えても回せる（[`TESTING.md`](TESTING.md) 1 節「ストアを切り替える」、#207）。

> **`sql` / `npg` を使っている既存環境は、`CibaData` に `UserId` 列の追加が要る。**
> CIBA の返答（`/ciba_result`）は、**要求が誰宛てだったか**を照合してから結果を書き込む。
> その宛先を持つ列で、`Create_UserStore.sql` には入れてあるが、
> **作成済みのデータベースには自動では増えない。**
>
> ```sql
> ALTER TABLE [CibaData] ADD [UserId] [nvarchar](128) NULL;   -- SQL Server
> ALTER TABLE CibaData ADD UserId varchar(128) NULL;          -- PostgreSQL
> ```
>
> 列が無いと、CIBA の要求の登録（`INSERT`）が失敗する。
> なお**列を足す前の保留中の要求は、承認できない**（宛先が記録されていないため）。
> `ora` にも `DeviceAuthZData` / `CibaData` を追加した（#206）。
> **`ora` の既存環境は、列ではなく表ごと足す**（元々この 2 表が無かったため）。
> 実機（`gvenzl/oracle-free:23-slim`）で E2E を通してある（#208）。
> `NVARCHAR2(800)` の列への一意制約も、`db_block_size` 8192・`max_string_size` STANDARD の
> 既定のままで作成された。

**3 つの DDL がミラーかどうかは、機械的に確かめられる。**

```powershell
cd root
.\CompareDdl.ps1           # 差があれば赤く出て、終了コードが 1 になる
.\CompareDdl.ps1 -Detail   # 差の無いテーブルも並べる
```

`Create_UserStore.sql`（テーブルと列）と `Select_UserStore.sql`（SELECT 対象）の**両方**を見る。
**型は比べない**（`nvarchar(max)` と `NVARCHAR2(2000)` のように、対応はするが同一ではない）。
**SQL が実行できるかは分からない。** それは、ストアを切り替えて E2E を回して確かめる
（[`TESTING.md`](TESTING.md) 1 節「ストアを切り替える」、#207）。

## 8. 証明書

```json
"RsaPfxFilePath":      "C:/root/files/resource/X509/SHA256RSA_Server.pfx",
"EcdsaPfxFilePath":    "C:/root/files/resource/X509/SHA256ECDSA_Server.pfx",
"SpRp_RsaPfxFilePath": "C:/root/files/resource/X509/SHA256RSA_Client.pfx",
"SpRp_ClientCertPfxFilePath": "C:/root/files/resource/X509/SHA256RSAClientCert.pfx"
```

`RsaPfx*` はサーバ（トークンの署名）、`SpRp_*` はクライアント側（Request Object の署名、mTLS）。

**絶対パスで書かれている。** リポジトリの `root/files/resource/X509` を、
そのパスへ配置するか、値を書き換える。生成用のバッチが同じフォルダにある。

### クライアント証明書（mTLS）を受け付ける

**`fapi2` の登録は、mTLS（RFC 8705 の `tls_client_auth`）でしか通らない**（`ANALYSIS-IdP.md` C-7）。
使うには、**サーバ側で、クライアント証明書を要求させる設定が要る。雛形のままでは要求しない**（#226 で実測）。

**アプリは、証明書の Subject と、登録の `tls_client_auth_subject_dn` の一致だけを見る。**
**発行元（チェーン）と失効の検証は、TLS の層（Kestrel / IIS）に任せている。**
したがって、TLS の層で**信頼できる発行元だけを受け付ける**ように設定すること。

| | 設定 | 検証 |
|---|---|---|
| net10.0（Kestrel） | `Kestrel:EndpointDefaults:ClientCertificateMode` を `AllowCertificate`（証明書の無いクライアントも通す）または `RequireCertificate`。`appsettings.json` でも環境変数（`Kestrel__EndpointDefaults__ClientCertificateMode`）でもよい | 既定でチェーンと失効を検証する。自己署名など信頼できない証明書は、TLS の段階で切れる |
| net48（IIS） | サイトの `<access sslFlags="Ssl, SslNegotiateCert" />`（証明書を要求するが、無くても通す） | 信頼できない証明書は、アプリより前で **HTTP 403.16** になる |

- **リバース プロキシで TLS を終端する場合、アプリには証明書が届かない。** 今の実装は、プロキシが転送するヘッダ
  （`X-ARR-ClientCert` など）を読まない
- `tls_client_auth_subject_dn` は **JSON の文字列**なので、`\\` は 1 文字の `\` になる。
  照合するのは、.NET が返す `X509Certificate2.Subject` の文字列
- **E2E のテスト専用のフック（`Tests/MtlsTestHook`）は、発行元を問わずに受け付ける。本番の構成で読ませないこと**
  （`test.ps1 -Launch` が、起動したサイトにだけ `DOTNET_STARTUP_HOOKS` で渡す。Development 以外では何もしない）

## 9. 機械で読むときの落とし穴

E2E テストの `AppConfig.cs` が実際に踏んだもの。同じことをするときは注意する。

### XML の属性値は、改行が空白に潰れる

XML 1.0 §3.3.3 のとおり、パーサは属性値の改行を空白へ正規化する。
`OAuth2ClientsInformation` は **`//` コメント付きの JSON** なので、
`XDocument` から取ると 1 行になり、**最初の `//` が以降を全部飲む。**

生のファイル テキストから取り直すこと。

### `//` を含む URL

雛形のコメントを正規表現で落とそうとすると、`https://...` の `//` まで消える。
**JSON パーサのコメント処理（`JsonCommentHandling.Skip`）を使うこと。**

## 10. net48 / net10.0 の対応表

| | net48 | net10.0 |
|---|---|---|
| 設定ファイル | `app.config`（`Web.config` から `file=` で取り込み） | `appsettings.json` |
| ルート要素 / セクション | `<appSettings>` | `appSettings` |
| コメント | XML コメント ＋ JSON 文字列内の `//` | JSONC の `//` |
| 環境変数で上書き | `FxContainerization=ON`（キー名そのまま） | `appSettings__<キー>` ／ `FxContainerization=ON` |
| クライアント登録 | JSON **文字列** | JSON **オブジェクト** |
| 既定の起動 | IIS Express | IIS Express / Kestrel |
| パッケージ | `packages.config` ＋ `PackageReference` | `PackageReference` |
| 認証クッキーの設定 | `App_Start/StartupAuth.cs` | `Startup.cs` の `ConfigureApplicationCookie`（#223） |

**両者は共通ライブラリを使う別アプリである。** 片方にしか無い問題があり得る。

> **実例**: `AuthCookieExpiresFromHours` / `AuthCookieSlidingExpiration` は、
> **net10.0 では長らく読まれていなかった**（#223）。
> 設定は書かれていたが、**誰も使っていないスキームに対する指定**だったため。
> **雛形の値（`336` 時間）が Identity の既定（14 日）と偶然一致していて、表面化しなかった。**
> **「設定ファイルに在る」ことと「効いている」ことは別である。**

---

## 11. 本番へ切り替えるときに見るもの

**雛形の既定は「開発・テストで動く」状態である。** 本番へ出す前に、次を確認する。

> **一覧の目的は、読み落としを減らすこと。** 各キーの意味は雛形のコメントが一次情報。

### 設定

| キー | 雛形の既定 | 本番 | なぜ |
|---|---|---|---|
| `UserStoreType` | `mem` | `sql` / `ora` / `npg` | `mem` は**再起動で消える**。**`mem` のままだと `IsDebug` が常に true になる**（下の注意 1） |
| `IsDebug` | `true` | `false` | テスト利用者の生成、メール / SMS の送信の代替、ログの扱いが変わる |
| `EnabeDebugTraceLog` | `true` | `false` | 冗長なトレースを止める（**綴りは実装どおり `Enabe`**） |
| `TestUserPWD` | `[password of TestUser]` | **空にする** | 空なら、テスト利用者（`super_tanaka@gmail.com` / `tanaka@gmail.com`）を**作らない** |
| `AdministratorUID` / `AdministratorPWD` | `[Please fill in this input item.]` | 実運用の値 | **`IsDebug` に関係なく作られる**（下の注意 2）。既定のまま出さない |
| `IsLockedDownTestEndpoints` | `false` | `true` | **テスト用の口をまとめて閉じる。** 自己テスト画面（`/Home/Saml2OAuth2Starters`）、テスト用のリダイレクト先、`/TestHybridFlow`、`api/Values`（net10.0）。**`/Ping` は閉じない**（下の注意 3） |
| `EnableImplicitGrantType` / `EnableResourceOwnerPasswordCredentialsGrantType` | **`false`**（#220 で変更） | `false` のまま | **OAuth 2.1 で廃止されたフロー。** コードは残してあるので、必要なら `true` に戻せる |
| `RequirePkce` / `RequirePkceS256` | `false` | **任意**（下の注意 5） | **OAuth 2.1 に寄せるための締め金**（#220）。既定は従来どおり緩い |
| `FcmOutboxDirectory` | `""`（空） | **空のまま** | 設定すると、プッシュ通知を FCM に送らずファイルに書く（テスト用。2 節） |
| `OAuth2ClientsInformation` | **テスト用が 12 件** | 実運用のものだけ残す | `TestClient` `TestClient1`〜`5` `MVC_Sample` `WebForms_Sample` `SPA_Application` `Native_Application` `AuthenticationDevice_Web` `IdFederation` が**登録済みクライアントとして使える**まま |

**net48 / net10.0 で、キー名と既定値は同じ。** 書き方だけ違う（10 節）。

```xml
<!-- app.config -->
<add key="IsDebug" value="false" />
<add key="TestUserPWD" value="" />
```

```json
// appsettings.json
"IsDebug": "false",
"TestUserPWD": "",
```

### 起動したあとの確かめ方

| 見るもの | 期待 |
|---|---|
| `/Home/Saml2OAuth2Starters` | 自己テスト画面ではなく **Index が出る**（`IsLockedDownTestEndpoints`） |
| 雛形のテスト利用者でサインイン | **できない**（`TestUserPWD` が空なら作られていない） |
| `.well-known/openid-configuration` | HTTP 200 で、`issuer` が本番の URL（5 節） |
| `ACCESS` / `OPERATION` ログ | 冗長なトレースが出ていない（`EnabeDebugTraceLog`） |

### キーを改名した（`IsLockedDownRedirectEndpoint` → `IsLockedDownTestEndpoints`）

閉じる対象がリダイレクト先だけではなくなったため、名前を実態に合わせた（#219）。

- **旧いキー名も読む。** 新しいキー名が無ければ、旧いキー名を使う
- **旧いキー名だけのときは、起動時に警告する**（下の「起動時の自動確認」）
- **未設定のときは `false`（＝開く）。** だから「改名しただけ」だと、
  既存の設定ファイル（旧キーしか無い）で**本番が黙って開いてしまう。** 互換を残したのはこのため

### 起動時の自動確認

**このチェックリストの読み落としを拾うため、起動時にも確かめている**（`Co/ProductionCheck`。両アプリ）。

- 該当すると、`OPERATION` ログに `[設定の確認] …（CONFIGURATION.md 11 節）` が出る
- **起動は止めない。** 設定を直せない状況で復旧できなくなるため
- **`UserStoreType` が `mem` のときは何も言わない**（開発・テスト専用の構成なので、雑音にしかならない）。
  ただし `AdministratorUID` / `AdministratorPWD` が雛形の値のままのときだけは、ストアによらず言う
- **`RequirePkce` / `RequirePkceS256` の 1 件だけは、性質が違う**（#220）。
  `false` は「開発向けの設定が残っている」ではなく、**従来の OAuth 2.0 のまま**というだけで、
  それ自体は誤りではない。**本番では意図して選ぶべき**なので、選ばれていないことだけを知らせる

**ログに出ていないこと＝設定が正しいこと、ではない。** 確かめているのは上の表のうち、
機械で判る範囲だけ（クライアント登録の中身などは見ていない）。

### 注意（仕様上の落とし穴）

1. **`IsDebug` は `UserStoreType = mem` のとき、設定を無視して常に `true`** を返す
   （`CommonLibrary/Co/Config.cs`）。**`IsDebug=false` と書いても効かない。** 本番は DBMS 前提。
2. **管理者ユーザ（`AdministratorUID`）は、`IsDebug` に関係なく無条件で作られる。**
   テスト利用者だけが `IsDebug` と `TestUserPWD` で閉じられる。
3. **`/Ping` は閉じない。** セッションのタイムアウト防止に使われているため（#219）。
   本番で塞ぐなら、前段（リバース プロキシなど）で行う。
   `/TestHybridFlow` と `api/Values`（net10.0 のみ）は、`IsLockedDownTestEndpoints` で閉じる。
4. **STS 専用モード**（`EnableSignupProcess` / `EnableEditingOfUserAttribute` /
   `EnableAdministrationOfUsersAndRoles` を**全部 false**）にすると、サインアップ・属性の編集・
   ユーザ管理が無効になる。**利用者ストアへの書き込みも止まる**ので、切替の影響が大きい。
5. **PKCE の 2 つのキーは、別のものを締める**（#220。どちらも既定 `false`）。

   | キー | 何を求めるか | どこで弾くか | 有効にすると通らなくなるもの |
   |---|---|---|---|
   | `RequirePkce` | PKCE 自体（`code_challenge`） | 認可エンドポイント（`invalid_request`） | **PKCE を使っていない既存クライアント** |
   | `RequirePkceS256` | 使うなら `S256` に限る | トークン エンドポイント | `plain` を使っているクライアント |

   **両方 `true` が OAuth 2.1 相当。** ただし**クライアントが揃っていないと繋がらなくなる**ので、
   既存の登録を確かめてから切り替える。**Device AuthZ / CIBA は `RequirePkce` の対象外**
   （認可エンドポイントを通らないため）。

   **`RequirePkce` は、クライアント単位でも指定できる**（#221）。
   クライアント登録に `require_pkce` を書くと、**そのクライアントにだけ**必須になる。

   ```json
   "c4309326f39b1e0975fddb4bc93b56a0": {
     "client_secret": "...",
     "redirect_uri_code": "http://localhost:12347/",
     "client_name": "TestClient6",
     "require_pkce": "true"
   }
   ```

   **判定は `RequirePkce`（サーバ全体）との OR。**
   サーバ側が「全クライアント共通の床」、クライアント側は「個別の引き上げ」で、
   **クライアント側から床を下げることはできない。**
   **移行では、締められるクライアントから順に `require_pkce` を立て、
   全部揃ったらサーバの `RequirePkce` を `true` にする**、という順序が取れる。

   > **`oauth2_oidc_mode` を `fapi1` にしても PKCE は必須になるが、そちらは重い。**
   > **ROPC / `client_credentials` / `refresh_token` も巻き添えで塞がる**（実測。#222）。
   > 「PKCE だけ必須にしたい」なら `require_pkce` を使う。

> **設定を変えたら、雛形（`_app.config` / `_appsettings.json`）にも反映する**（1 節）。
> 本番の値そのものは書かない。
