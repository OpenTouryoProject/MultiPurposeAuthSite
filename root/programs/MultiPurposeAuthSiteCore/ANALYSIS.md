# ANALYSIS.md — 汎用認証サイト 主要部（MultiPurposeAuthSiteCore / net10.0）コード分析

対象: `root/programs/MultiPurposeAuthSiteCore`（**ASP.NET Core MVC / net10.0**） / ブランチ: `develop`
最終更新: 2026-09-07

本書は **コーディング・エージェントが本ディレクトリで作業する際の Context** を目的とした分析結果である。

**実装の大半は `../CommonLibrary` に在る。先に [`../CommonLibrary/ANALYSIS.md`](../CommonLibrary/ANALYSIS.md) を読むこと。**
本書は「この Web アプリ固有の部分」だけを扱う。
下位互換版（net48）は [`../MultiPurposeAuthSite/ANALYSIS.md`](../MultiPurposeAuthSite/ANALYSIS.md)。

---

## 1. これは何か

**汎用認証サイトの現行版。** ASP.NET Core Identity と JWT による
OAuth 2.0 / OpenID Connect の IdP（Identity Provider）兼 STS（Security Token Service）。
SAML2 の IdP でもある。

- ソリューション: `MultiPurposeAuthSiteCore.sln` → `MultiPurposeAuthSiteCore/MultiPurposeAuthSiteCore.csproj`
  （`Microsoft.NET.Sdk.Web` / `net10.0`、アセンブリ名 `MultiPurposeAuthSite`）
- `Startup.cs` 方式（Minimal API ではない）。`Program.Main` → `Host.CreateDefaultBuilder`。
- 上流の解説: Open棟梁 Wiki「汎用認証サイト（Multi-purpose Authentication Site）」
- プロジェクト・ポリシーは **リポジトリ ルートの `AGENTS.md`（`CLAUDE.md` はそれへのポインタ）** に定義済み。
  → **エージェントは git 操作（add/commit/push/checkout/branch/reset/restore/stash）を行わない。**

規模の目安: `.cs` 10 ファイル / 約 11,300 行、`.cshtml` 57 件。

---

## 2. 前提条件

### 2.1 Open棟梁のアセンブリを先に用意する（最重要）

`OpenTouryo.{Public,Public.Security,Framework,Business}` を
`../OpenTouryoAssemblies/Build_netcore100/net10.0/*.dll` から **`HintPath` で直接参照**する。
`ProjectReference` ではないので、**用意しないとビルドできない。**

```
../3_BuildLibsAtOtherRepos.bat                  タグ 03-20 の zip を取得 → ビルド → コピー
../3_BuildLibsAtOtherReposInTimeOfDev.bat       develop の zip で同上
mpas_dev.bat（リポジトリ ルート）               隣に clone 済みの OpenTouryo からビルド出力を xcopy
```

`OpenTouryoAssemblies/` は `.gitignore` 対象。

### 2.2 リポジトリを `C:\` 直下に配置する

`appsettings.json` は `C:/root/files/resource/...` を直書きしている。

```json
"FxXMLSPDefinition": "C:/root/files/resource/XML/SPDefinition.xml",
"FxLog4NetConfFile": "C:/root/files/resource/Log/SampleLogConf.xml",
"RsaPfxFilePath":    "C:/root/files/resource/X509/SHA256RSA_Server.pfx",
"ContentOfLetterFilePath": "C:/root/files/resource/MultiPurposeAuthSite/Txt"
```

**チェックアウト先が `C:\MultiPurposeAuthSite` 以外だと、ビルドは通るが実行時に落ちる。**
区切りは `/`（JSON のエスケープ回避）。

> **注意:** `FxXMLSPDefinition` などが指す `C:/root/files/resource/XML/` は
> **Open棟梁側のリソース**（`OpenTouryo/root/files/resource/Xml/`）であり、本リポジトリの
> `root/files/resource/MultiPurposeAuthSite/Xml/` とは別物。ケースも `XML` / `Xml` で揺れている。

### 2.3 設定ファイル

`appsettings.json` は **`.gitignore` 対象**。git に在るのは `_appsettings.json`（テンプレート）。

```
_appsettings.json  →  コピーして appsettings.json を作り、各自の値を埋める
```

**実ファイルには実在の認証情報（管理者アカウント、SMTP、Twilio、Stripe / PAY.JP、
外部ログインの ClientSecret、SaltParameter）が入っている。
報告・コミット メッセージ・Issue 本文に転記しないこと。**
設定項目を増やすときは **`_appsettings.json` を直す**（実ファイルへの反映は人が行う）。

### 2.4 UserStore

既定は `"UserStoreType": "mem"`（プロセス内メモリ）で、**DB 無しで起動できる**。
DBMS を使うなら `sql` / `ora` / `npg` に変え、`root/files/resource/MultiPurposeAuthSite/Sql/`
の DDL を流す。Docker で立てる一式は `store/`（`docker-compose.yml`）。

### 2.5 起動 URL

`Properties/launchSettings.json` の既定は **`https://localhost:44300/MultiPurposeAuthSite`**。
`launchSettings.json` はリポジトリ ルートの `.gitignore` で除外されている
（`**/Properties/launchSettings.json`）。

**`/MultiPurposeAuthSite` という仮想パス配下で動く前提でコードが書かれている**点に注意。
`Startup.ConfigureServices` の Cookie 設定にも直書きがある。

```csharp
options.LoginPath  = "/MultiPurposeAuthSite/Account/Login";
options.LogoutPath = "/MultiPurposeAuthSite/Account/LogOff";
```

---

## 3. 構成

```
MultiPurposeAuthSiteCore/
├─ MultiPurposeAuthSiteCore.sln
└─ MultiPurposeAuthSiteCore/
   ├─ Program.cs        … エントリポイント。OAuth2AndOIDCClient.HttpClient を差し込む
   ├─ Startup.cs        … DI 登録・パイプライン・ルーティング（494 行）
   ├─ Controllers/
   │   ├─ AccountController.cs          4402 行  サインイン/アップ、2FA、外部ログイン、
   │   │                                          ID 連携、SAML2/OAuth2 の認可エンドポイント
   │   ├─ ManageController.cs           3262 行  ユーザ属性・2FA・決済情報・GDPR
   │   ├─ HomeController.cs             1442 行  ★テスト用クライアント（Starters）
   │   ├─ OAuth2EndpointController.cs   1179 行  token / userinfo / revoke / introspect /
   │   │                                          jwkcerts / ros / device_authz / ciba_* /
   │   │                                          .well-known / samlmetadata
   │   ├─ OAuth2ResourceServerController.cs 222 行  リソース サーバ側の疎通用 WebAPI
   │   ├─ ErrorController.cs             85 行
   │   ├─ PingController.cs              54 行  死活監視
   │   └─ ValuesController.cs            58 行  疎通確認（`api/values/get`）
   ├─ Views/{Account,Manage,Home,Error,Shared}/*.cshtml
   ├─ wwwroot/{css,js,images,lib}/       … bootstrap / jQuery 等はリポジトリに直接格納
   ├─ _appsettings.json                  … テンプレート（git 管理下）
   ├─ appsettings.json                   … 実ファイル（.gitignore）
   └─ appsettings.Development.json
```

- `AccountController` / `ManageController` / `HomeController` / `ErrorController` は
  **Open棟梁の `MyBaseMVControllerCore` を継承**（`Touryo.Infrastructure.Business.Presentation`）。
- `OAuth2EndpointController` / `OAuth2ResourceServerController` は素の `ControllerBase`（WebAPI）。
- `PingController` / `ValuesController` は素の `Controller`。

---

## 4. 起動シーケンス（フレームワークの組み込み方）

```csharp
// Program.cs
public static void Main(string[] args)
{
    OAuth2AndOIDCClient.HttpClient = new HttpClient();   // ★静的 HttpClient を差し込む
    Program.BuildWebHost(args).Run();
}

// Startup.cs
public Startup(IConfiguration configuration)
{
    Configuration = configuration;
    GetConfigParameter.InitConfiguration(configuration); // ★必須。無いと Config.* が全て null
}

public void Configure(IApplicationBuilder app, IWebHostEnvironment env)
{
    app._UseHttpContextAccessor();   // ★必須。MyHttpContext.Current を有効化する Open棟梁の拡張
    app.UseStaticFiles();
    app.UseCookiePolicy(...);        // HttpOnly=Always / MinimumSameSitePolicy=None
    app.UseSession(...);             // IdleTimeout 30 分、Cookie 名は sessionState:SessionCookieName
    app.UseRouting();
    app.UseAuthentication();
    app.UseAuthorization();
    app.UseCors(...);                // ★認証・認可の後ろ。AllowAnyOrigin/Method/Header
    app.UseEndpoints(...);           // 5 節
}
```

**この 3 点（`InitConfiguration` / `_UseHttpContextAccessor` / `UseSession`）が
.NET (Core) で Open棟梁を動かすための定型。** Open棟梁側の `Samples4NetCore/Backend/MVC_Sample`
と同じ形なので、迷ったらそちらも参照する。

### 4.1 ASP.NET Core Identity の登録

**Entity Framework は使わない。** 自前ストア（`../CommonLibrary`）を注入する。

```csharp
// AddIdentity より前に登録しないと効かない
services.AddScoped<IPasswordHasher<ApplicationUser>, CustomPasswordHasher<ApplicationUser>>();
services.AddScoped<ISecurityStampValidator, SecurityStampValidator<ApplicationUser>>();

services.AddIdentity<ApplicationUser, ApplicationRole>()
    .AddUserStore<UserStoreCore>()
    .AddRoleStore<RoleStoreCore>()
    .AddDefaultTokenProviders();

services.AddTransient<IUserStore<ApplicationUser>, UserStoreCore>();
services.AddTransient<IRoleStore<ApplicationRole>, RoleStoreCore>();
services.AddTransient<IEmailSender, EmailSender>();
services.AddTransient<ISmsSender, SmsSender>();
```

`IdentityOptions`（ユーザ名 / パスワード / ロックアウト）は**すべて `Config.*` から取る**ので、
挙動を変えたいときは `appsettings.json` を直す。

### 4.2 外部ログイン

`Config.{MicrosoftAccount,Google,Facebook,Twitter}Authentication` が true のときだけ
`authenticationBuilder.Add***()` する。**OAuth2 / OIDC の IdP 側はスクラッチ実装**であり、
ここには何も登録されない（`#region OAuth2 / OIDC` に「スクラッチ実装」とだけ書いてある）。

### 4.3 Session は開発用のまま

```csharp
services.AddDistributedMemoryCache(); // 開発用
//services.AddDistributedSqlServerCache();
//services.AddDistributedRedisCache();
```

**複数インスタンスで動かすなら差し替えが要る。** 現状は単一プロセス前提。

---

## 5. ルーティング（設定値からエンドポイントを組み立てる）

`Startup.Configure` の `UseEndpoints` で、**`Config.*` が返すパスから動的に登録する。**
`.Substring(1)` は先頭の `/` を落とすため。

| ルート名 | 既定パス（`_appsettings.json`） | 行き先 |
|---|---|---|
| `Saml2Request` | `/saml2request` | `Account.Saml2Request` |
| `OAuth2Authorize` | `/authorize` | `Account.OAuth2Authorize` |
| `OAuth2Token` | `/token` | `OAuth2Endpoint.OAuth2Token` |
| `GetUserClaims` | `/userinfo` | `OAuth2Endpoint.GetUserClaims` |
| `RevokeToken` | `/revoke` | `OAuth2Endpoint.RevokeToken` |
| `IntrospectToken` | `/introspect` | `OAuth2Endpoint.IntrospectToken` |
| `JwksUri` | `/jwkcerts` | `OAuth2Endpoint.JwksUri` |
| `RequestObjectUri` | `/ros` | `OAuth2Endpoint.RequestObjectUri` |
| `DeviceAuthZAuthorize` | `/device_authz` | `OAuth2Endpoint.DeviceAuthZAuthorize` |
| `DeviceAuthZVerify` | `/device_verify` | `Account.DeviceAuthZVerify` |
| `CibaAuthorize` | `/ciba_authz` | `OAuth2Endpoint.CibaAuthorize` |
| `CibaPushResult` | `/ciba_result` | `OAuth2Endpoint.CibaPushResult` |
| `SetDeviceToken` | `/SetDeviceToken` | `OAuth2Endpoint.SetDeviceToken` |
| `TwoFactorAuthPushResult` | `/TwoFactorAuthPushResult` | `OAuth2Endpoint.TwoFactorAuthPushResult` |
| `TestHybridFlow` | `/TestHybridFlowWebAPI` | `OAuth2ResourceServer.TestHybridFlow` |
| `ChageToUser` | `/ChageToUser` | `OAuth2ResourceServer.ChageToUser` |
| `default` | `{controller=Home}/{action=Index}/{id?}` | — |

固定パスは `[Route]` 属性で 2 つだけ。

- `.well-known/openid-configuration` → `OAuth2Endpoint.OpenIDConfig`
- `samlmetadata` → `OAuth2Endpoint.SamlMetadata`

> **設定でパスを変えると、ルーティングが丸ごと変わる。**
> エンドポイントを足すときは「`Config` にプロパティ追加 →
> `_appsettings.json` にキー追加 → `Startup` に `MapControllerRoute` 追加」の 3 点セット。
> **`../MultiPurposeAuthSite`（net48）側の `App_Start/WebApiConfig.cs` / `RouteConfig.cs`
> にも同じ登録が要る。**

---

## 6. 初期データの生成（気付きにくい）

**ロールと管理者ユーザは、`GET /Account/Login` と `GET /Account/Register` の初回アクセスで
遅延生成される。** 起動時ではない。

```
AccountController.Login/Register  →  CreateData()   （SemaphoreSlim で 1 本に絞る）
   ├ STS 専用モードなら何もしない
   ├ Memory Provider …… static フラグ HasCreated で 1 回だけ
   ├ DBMS Provider  …… DataAccess.IsDBMSInitialized()（[Roles] の件数）で判定
   ├ ロール作成: SystemAdmin / Admin / User
   ├ 管理者作成: Config.AdministratorUID / AdministratorPWD → 3 ロール全付与
   └ Config.IsDebug かつ TestUserPWD が非空なら
        super_tanaka@gmail.com（User+Admin） / tanaka@gmail.com（User）を作成
```

- **`IsDebug` を true のまま公開すると、テスト ユーザが作られる。**
- `AdministratorPWD` は初期化後に設定から消してよい（`_appsettings.json` のコメントに明記）。

---

## 7. テスト用クライアント（`HomeController` / `Views/Home`）

**この認証サイトは、自分自身のクライアントも兼ねている。**
`HomeController`（1442 行）はほぼ全部が「各フローを画面から叩くためのテスト用クライアント」。

- `Saml2OAuth2Starters.cshtml` … SAML2 / Authorization Code / Implicit / Hybrid / PKCE /
  FAPI1 / FAPI2 / その他を、クライアントと response_mode を選んで開始する画面
- `DeviceAuthZResponse.cshtml` … Device Authorization Grant の user_code 表示（QR は `qrcode.js`）
- `OAuth2ClientAuthenticationFlow.cshtml` / `PostBinding.cshtml` / `Scroll.cshtml`
- 対応する Redirect 先は `Account` / `Manage` 側
  （`OAuth2AuthorizationCodeGrantClient` / `OAuth2ImplicitGrantClient`）

`_appsettings.json` の `OAuth2ClientsInformation` には
`test_self_code` / `test_self_token` という**予約 redirect_uri** を持つテスト用クライアントが
定義されている。**本番では `IsLockedDownRedirectEndpoint` を true にして塞ぐ。**

---

## 8. net48 版との機能差（重要）

同じ機能を両系統で提供するのが原則だが、**現状は次の差がある。**

| 機能 | net10.0（本ディレクトリ） | net48（`../MultiPurposeAuthSite`） |
|---|---|---|
| TOTP（Authenticator アプリ 2FA） | **✓ あり**（`EnableTwoFactorAuthenticator` / リカバリ コード / `ManageTwoFactorAuthenticator`） | ✗ 無し |
| ユーザ・ロール管理画面 | **✗ 無し**（`Config.EnableAdministrationOfUsersAndRoles` を読む Controller が無い） | ✓ `UsersAdminController` / `RolesAdminController` |
| FIDO2 サーバ用 WebAPI | ✗ 無し | △ `Fido2ServerController.cs` は在るが**ビルド対象外** |
| 疎通用 WebAPI | ✓ `ValuesController` | ✗ |
| WebAuthn / MS Passport | ✗（`../CommonLibrary` 側ごと無効） | ✗（同左） |

> **`EnableAdministrationOfUsersAndRoles` は .NET 側では「STS 専用モードの判定」にしか
> 効いていない。** 管理画面そのものが無いため、true にしても net10.0 では画面は出ない。

---

## 9. ビルドと実行

```
dotnet build MultiPurposeAuthSiteCore.sln
dotnet run --project MultiPurposeAuthSiteCore/MultiPurposeAuthSiteCore.csproj
```

`../10_MultiPurposeAuthSiteCore.bat` は `../z_Common.bat` を読んでから
`dotnet restore` → `dotnet msbuild` する（`CommandLineToolsCore.sln` も併せてビルドする）。

> **`10_MultiPurposeAuthSiteCore.bat` は現状そのままでは通らない。**
> `RestoreLib1.bat`（`npm i`）と `RestoreLib2.bat` を `call` しているが、
> **この 2 ファイルはコミット `Reboot:2`（0c9a757）で削除済み。**
> `node_modules` を消す行も含めて、npm による静的ファイル取得は廃止され、
> **`wwwroot/lib/`（bootstrap / jquery / jquery-validation / jquery-validation-unobtrusive）は
> リポジトリに直接格納する方式に変わっている。**
> エージェントは bat を経由せず `dotnet build` を直接使うのが確実。

### 9.1 現状のビルド結果（実測 2026-09-07）

`dotnet build MultiPurposeAuthSiteCore.sln` … **0 エラー / 警告あり**

| 警告 | 内容 | 対処の目安 |
|---|---|---|
| `NU1902`（中） | `log4net` **3.2.0** に既知の脆弱性（`GHSA-4f7c-pmjv-c25w`） | `MultiPurposeAuthSiteCore.csproj` の `log4net` を **3.3.0** へ。Open棟梁本体は既に 3.3.0 |
| `NU1901`（低） | `NuGet.Packaging` / `NuGet.Protocol` 6.12.1（`GHSA-g4vj-cjjj-v7hg`） | `Microsoft.VisualStudio.Web.CodeGeneration.Design` からの推移的依存 |
| `MSB3277` | `log4net` 3.2.0 と 3.3.0、`Microsoft.Data.SqlClient` 6.1.4 と 7.0.0 の版競合 | 上と同根。Open棟梁アセンブリが期待する版と本プロジェクトの `PackageReference` がズレている |

**`log4net` の版を上げると `MSB3277` も同時に減る。**

---

## 10. 落とし穴 / 既知の不整合

1. **`10_MultiPurposeAuthSiteCore.bat` が存在しない `RestoreLib1/2.bat` を呼ぶ**（9 節）。
2. **`log4net` 3.2.0 に既知の脆弱性**（9.1 節）。Open棟梁側は 3.3.0 で、版が割れている。
3. **`C:\` 直下配置が前提**（2.2 節）。`appsettings.json` は絶対パスを直書きしている。
4. **`/MultiPurposeAuthSite` 仮想パス前提**（2.5 節）。Cookie の `LoginPath` などが直書き。
5. **初期データは `/Account/Login` の初回アクセスで作られる**（6 節）。
   「起動しただけでは管理者が居ない」ことに気付きにくい。
6. **`IsDebug: true` でテスト ユーザが作られる**（6 節）。
7. **CORS が `AllowAnyOrigin` / `AllowAnyMethod` / `AllowAnyHeader`。**
   `Startup` で `UseCors` と `AddCors("AllowAllOrigins")` の**二重定義**になっている。
8. **Session が `AddDistributedMemoryCache`（開発用）のまま**（4.3 節）。
9. **UTF-8 でないファイルが 2 件ある**（Shift_JIS）。
   - `Views/_ViewImports.cshtml`（ヘッダ コメントが文字化けする）
   - `Views/Manage/ManageTwoFactorAuthenticator.cshtml`

   他は BOM 付き UTF-8。**編集ツールによっては保存時に壊すので注意。**
10. **`ManageController` / `AccountController` の WebAuthn 分岐はコメント アウト済み。**
    View（`Add{WebAuthn,MsPass}Data.cshtml`）と JS（`wwwroot/js/multiauthsite/{ff,ms}Webauthn.js`）
    は残っているが、機能しない（`../CommonLibrary/ANALYSIS.md` 12 節）。
11. **`AccountController.cs` は 4402 行、`ManageController.cs` は 3262 行と巨大。**
    変更は該当 `#region` に閉じ、全体リファクタは避ける。
12. **`ErrorController` は `MyBaseMVControllerCore` を継承するが、net48 側は素の `Controller`。**
    両系統でエラー処理の基底が違う。
13. **`_appsettings.json` と `appsettings.json` の差分は「秘密情報」だけではない。**
    テスト用クライアントの `redirect_uri_code` も実環境向けに書き換えられている
    （SPA / Native の redirect_uri）。テンプレートを直すときに取り違えないこと。

---

## 11. エージェント向け作業チェックリスト

- [ ] `AGENTS.md` のポリシー遵守（**git 操作をしない**）
- [ ] 変更が `../CommonLibrary` 側の話でないか確認する
      （ストア・トークン・設定・通知・リソースは全て向こう）
- [ ] エンドポイントを足す → `Config` ＋ `_appsettings.json` ＋ `Startup.UseEndpoints`
      ＋ **net48 側の `WebApiConfig` / `RouteConfig`** の 4 点
- [ ] 画面を足す → View ＋ ViewModel（`../CommonLibrary/ViewModels`）＋
      リソース（`../CommonLibrary/Resources`）
- [ ] 文言は直書きせずリソースへ
- [ ] `appsettings.json`（実ファイル）を直したら、**同じ変更を `_appsettings.json` にも**入れる。
      **秘密情報は転記しない**
- [ ] 新規 `.cs` / `.cshtml` は **BOM 付き UTF-8**で保存する
- [ ] 新規 `.cs` にはヘッダ コメント（Apache License ＋ クラス名・日本語名・更新履歴）を付与。
      既存 `.cs` の変更時は更新履歴に 1 行追記
- [ ] ビルド確認: `dotnet build MultiPurposeAuthSiteCore.sln`
      （警告本数が増えていないかも見る）
- [ ] net48 版に同じ変更が要るか判断し、要否を報告する
