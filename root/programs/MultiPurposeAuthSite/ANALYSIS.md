# ANALYSIS.md — 汎用認証サイト 下位互換版（MultiPurposeAuthSite / net48）コード分析

対象: `root/programs/MultiPurposeAuthSite`（**ASP.NET MVC5 + Web API2 + OWIN / net48**） / ブランチ: `develop`
最終更新: 2026-09-07

本書は **コーディング・エージェントが本ディレクトリで作業する際の Context** を目的とした分析結果である。

**実装の大半は `../CommonLibrary` に在る。先に [`../CommonLibrary/ANALYSIS.md`](../CommonLibrary/ANALYSIS.md) を読むこと。**
本書は「この Web アプリ固有の部分」だけを扱う。
主要部（net10.0）は [`../MultiPurposeAuthSiteCore/ANALYSIS.md`](../MultiPurposeAuthSiteCore/ANALYSIS.md)。

---

## 1. これは何か

**汎用認証サイトの下位互換版。** `../MultiPurposeAuthSiteCore`（net10.0）と**同じ機能を
.NET Framework 4.8 上で提供する**ための系列であり、
ASP.NET MVC5 / Web API2 / OWIN / ASP.NET Identity 2.x で書かれている。

Contributing.ja.md の「下位互換は高く維持し、破壊的な変更は最小限にします」に対応する側であり、
**新機能はまず net10.0 側に入り、こちらは追随する**（8 節に現時点の差分）。

- ソリューション: `MultiPurposeAuthSite.sln` → `MultiPurposeAuthSite/MultiPurposeAuthSite.csproj`
  （**旧形式 csproj** / `v4.8` / アセンブリ名 `MultiPurposeAuthSite`）
- プロジェクト・ポリシーは **リポジトリ ルートの `AGENTS.md`（`CLAUDE.md` はそれへのポインタ）** に定義済み。
  → **エージェントは git 操作（add/commit/push/checkout/branch/reset/restore/stash）を行わない。**

規模の目安: `.cs` 18 ファイル / 約 12,800 行、`.cshtml` 60 件。

---

## 2. 前提条件

### 2.1 Open棟梁のアセンブリを先に用意する（最重要）

`OpenTouryo.{Public,Public.Security,Framework,Business}` を
`../OpenTouryoAssemblies/Build_net48/*.dll` から **`HintPath` で直接参照**する
（`../CommonLibrary` 経由。本プロジェクトは `NetFxLibrary.csproj` を `ProjectReference`）。

```
../3_BuildLibsAtOtherRepos.bat                  タグ 03-20 の zip を取得 → ビルド → コピー
../3_BuildLibsAtOtherReposInTimeOfDev.bat       develop の zip で同上
mpas_dev.bat（リポジトリ ルート）               隣に clone 済みの OpenTouryo からビルド出力を xcopy
```

**`1_BuildAll.ps1` は、無ければ 2 番目（`develop`）を自動で呼ぶ**（`-Libs Force` で取り直す）。

`OpenTouryoAssemblies/` は `.gitignore` 対象。

### 2.2 NuGet パッケージは `packages.config` 方式

`MultiPurposeAuthSite/packages.config` ＋ `packages/`（リポジトリ内、`.gitignore` 対象）。
**`nuget.exe restore` が要る**（`dotnet restore` では復元されない）。
`../10_MultiPurposeAuthSite.bat` がこれを行う。

> **`../CommonLibrary/NetFxLibrary.csproj` は `PackageReference` 方式**であり、
> 同じ net48 でも復元方式が違う。両方が必要。

### 2.3 リポジトリを `C:\` 直下に配置する

`app.config` は `C:\root\files\resource\...` を直書きしている（**区切りは `\`**。
.NET 側の `appsettings.json` は `/` で、ここが両者の書式差）。

### 2.4 設定ファイル

```
Web.config          … <appSettings file="app.config" /> で外だしを読み込む
app.config          … 実ファイル。★.gitignore 対象
_app.config         … テンプレート（git 管理下）
```

**`_app.config` をコピーして `app.config` を作る。**
実ファイルには実在の認証情報が入っている。
**報告・コミット メッセージ・Issue 本文に転記しないこと。**
設定項目を増やすときは **`_app.config` を直す**（実ファイルへの反映は人が行う）。

### 2.5 セッションはステート サーバ前提

```xml
<sessionState cookieName="mas_session" timeout="20" cookieless="false"
              mode="StateServer" stateConnectionString="tcpip=127.0.0.1:42424" />
```

**Windows の「ASP.NET 状態サービス」を開始していないと起動直後に落ちる。**
`Web.config` には InProc / SQLServer / Oracle 版がコメントで併記してある。

### 2.6 起動 URL

`MultiPurposeAuthSite.csproj` の `<IISUrl>` は **`https://localhost:44300/MultiPurposeAuthSite/`**、
IIS Express の SSL ポートは 44300。

> **net10.0 版とポートも仮想パスも同じ。同時起動はできない。**
> ID フェデレーションのテストのように 2 台必要な場合は、片方を 44301 に変える
> （`_app.config` / `_appsettings.json` の `IdFederation*EndPoint` が 44301 を指している）。

---

## 3. 構成

```
MultiPurposeAuthSite/
├─ MultiPurposeAuthSite.sln
├─ packages/                          … NuGet（.gitignore）
└─ MultiPurposeAuthSite/
   ├─ Global.asax(.cs)                349 行  Application_Error で ACCESS ログ、性能測定
   ├─ Startup.cs                       65 行  OWIN のエントリ（StartupAuth.Configure を呼ぶ）
   ├─ App_Start/
   │   ├─ StartupAuth.cs              373 行  ★OWIN 認証ミドルウェアの設定
   │   ├─ WebApiConfig.cs             177 行  Web API のルーティング
   │   ├─ RouteConfig.cs               83 行  MVC のルーティング
   │   ├─ BundleConfig.cs              90 行  バンドル＆ミニフィケーション
   │   └─ FilterConfig.cs              49 行
   ├─ Controllers/
   │   ├─ AccountController.cs        4145 行
   │   ├─ ManageController.cs         2971 行
   │   ├─ HomeController.cs           1450 行  ★テスト用クライアント（Starters）
   │   ├─ OAuth2EndpointController.cs 1163 行
   │   ├─ UsersAdminController.cs      596 行  ★net48 のみ
   │   ├─ RolesAdminController.cs      431 行  ★net48 のみ
   │   ├─ Fido2ServerController.cs     260 行  ★ファイルは在るがビルド対象外（10 節）
   │   ├─ ErrorController.cs           232 行
   │   ├─ OAuth2ResourceServerController.cs 202 行
   │   └─ PingController.cs             56 行
   ├─ Views/{Account,Manage,Home,UsersAdmin,RolesAdmin,Error,Shared}/*.cshtml
   ├─ Content/ Scripts/ fonts/ images/  … NuGet で入る静的ファイル（リポジトリに直接格納）
   ├─ Web.config / Web.{Debug,Release}.config
   ├─ _app.config                       … テンプレート（git 管理下）
   └─ app.config                        … 実ファイル（.gitignore）
```

- `AccountController` / `ManageController` / `HomeController` /
  `UsersAdminController` / `RolesAdminController` は
  **Open棟梁の `MyBaseMVController` を継承**（`Touryo.Infrastructure.Business.Presentation`）。
- `OAuth2EndpointController` / `OAuth2ResourceServerController` / `Fido2ServerController` は
  `ApiController`（Web API2）。
- **`ErrorController` は素の `Controller`**（net10.0 版は `MyBaseMVControllerCore` 継承。非対称）。

---

## 4. 起動シーケンス

```
Global.asax.cs        Application_Start / Application_Error（ACCESS ログ）/ Session イベント
Startup.cs            OWIN の Configuration(IAppBuilder) → StartupAuth.Configure(app)
App_Start/*.cs        RouteConfig / WebApiConfig / BundleConfig / FilterConfig
```

`App_Start/StartupAuth.cs` が **OWIN 認証の全設定**を持つ。要点は次の 4 つ。

```csharp
// 1) PerOwinContext に自前ストア・マネージャを載せる（EF は使わない）
app.CreatePerOwinContext<UserStore>(() => new UserStore());
app.CreatePerOwinContext<ApplicationUserManager>(ApplicationUserManager.Create);
app.CreatePerOwinContext<ApplicationRoleManager>(ApplicationRoleManager.Create);
app.CreatePerOwinContext<ApplicationSignInManager>(ApplicationSignInManager.Create);

// 2) Cookie 認証（SecurityStamp 検証つき）
app.UseCookieAuthentication(new CookieAuthenticationOptions { ... });

// 3) 2FA 用の Cookie 2 種
app.UseExternalSignInCookie(DefaultAuthenticationTypes.ExternalCookie);
app.UseTwoFactorSignInCookie(DefaultAuthenticationTypes.TwoFactorCookie, ...);
app.UseTwoFactorRememberBrowserCookie(DefaultAuthenticationTypes.TwoFactorRememberBrowserCookie);

// 4) 外部ログイン（Config.***Authentication が true のときだけ）
app.UseMicrosoftAccountAuthentication / UseGoogleAuthentication
   / UseFacebookAuthentication / UseTwitterAuthentication
```

- `ApplicationUserManager` / `ApplicationRoleManager` / `ApplicationSignInManager` は
  **`../CommonLibrary/Manager/`（net48 のみ）**。.NET 側には無い（DI で代替）。
- 外部ログインには `CreateProxy.GetInternetProxy()` で **プロキシ設定が効く**
  （`BackchannelHttpHandler`）。.NET 側にはこの配慮が無い。
- Twitter だけ `BackchannelCertificateValidator` に**証明書の拇印を 6 個ハードコード**している。
  期限切れで疎通しなくなる類の記述なので、Twitter ログインが落ちたらここを疑う。
- **`OAuth2 / OIDC` の IdP 側はスクラッチ実装**であり、`Microsoft.Owin.Security.OAuth` の
  `OAuthAuthorizationServer` ミドルウェアは使っていない
  （`StartupAuth.OAuthOptions` プロパティは残っているが未使用）。

---

## 5. ルーティング（.NET 側と 2 箇所に分かれる）

net10.0 版は `Startup.UseEndpoints` の 1 箇所だが、**net48 は MVC と Web API で別**。

| ファイル | 登録するもの |
|---|---|
| `App_Start/RouteConfig.cs` | `Saml2Request` / `OAuth2Authorize` / `DeviceAuthZVerify` ＋ Default |
| `App_Start/WebApiConfig.cs` | `OAuth2Token` `GetUserClaims` `RevokeToken` `IntrospectToken` `JwksUri` `RequestObjectUri` `DeviceAuthZAuthorize` `CibaAuthorize` `CibaPushResult` `SetDeviceToken` `TwoFactorAuthPushResult` `TestHybridFlow` `ChageToUser` ＋ `api/{controller}/{action}/{id}` |

いずれもパスは `Config.*`（＝ `app.config`）から取り、`.Substring(1)` で先頭 `/` を落とす。
固定パスは `[Route]` 属性の 2 つ（`.well-known/openid-configuration` / `samlmetadata`）。

> **エンドポイントを足すときは、net10.0 側の `Startup.cs` と、こちらの
> `RouteConfig.cs` / `WebApiConfig.cs` の該当する方の両方**を直す。
> `Config` へのプロパティ追加と `_app.config` / `_appsettings.json` へのキー追加も必要。

### 5.1 CIBA のアクション名が系統で違う

```
net48 : defaults: new { controller = "OAuth2Endpoint", action = "CibaAuthorizeAsync" }
net10 : defaults: new { controller = "OAuth2Endpoint", action = "CibaAuthorize" }
```

**メソッド名は両系統とも `CibaAuthorizeAsync`。**
ASP.NET Core が `Async` サフィックスを既定で落とすため、こう書き分けてある。
片方だけ真似すると 404 になる。

---

## 6. 静的ファイル（バンドル）

`App_Start/BundleConfig.cs` の `System.Web.Optimization`。
`BundleTable.EnableOptimizations = !Config.IsDebug` / `UseCdn = true`。

| バンドル | 中身 | `_Layout` で Render |
|---|---|---|
| `~/bundles/css` | bootstrap / font-awesome / touryo / app | ✓ |
| `~/bundles/modernizr` `~/bundles/jquery` `~/bundles/bootstrap` `~/bundles/touryo` `~/bundles/app` | — | ✓ |
| `~/bundles/multiauthsite` | `oauthimplicit.js` `arrayBufferUtil.js` `msWebauthn.js` `ffWebauthn.js` | ✗（個別 View で Render） |
| `~/bundles/jqueryval` | `jquery.validate*` | ✗ |

- `ScriptBundle` の仮想パスは**実在するパスと衝突すると壊れる**（コード中のコメント）。
  そのため `~/bundles/...` という実在しないパスにしてある。
- **JS の置き場所が系統で違う。** net48 は `Scripts/touryo/`、net10.0 は
  `wwwroot/js/multiauthsite/`。同じファイル名で場所だけ違うので、片方を直したら両方直す。
- `Scripts/README.md` は popper.js の README が NuGet で降ってきたもの。本プロジェクトの文書ではない。

---

## 7. 初期データの生成

net10.0 版と同じく、**`GET /Account/Login` / `GET /Account/Register` の初回アクセスで
`AccountController.CreateData()` が走る**（起動時ではない）。
ロール 3 種（`SystemAdmin` / `Admin` / `User`）と管理者ユーザ、
`Config.IsDebug` が true なら テスト ユーザ 2 名を作る。
詳細は [`../MultiPurposeAuthSiteCore/ANALYSIS.md`](../MultiPurposeAuthSiteCore/ANALYSIS.md) 6 節。

---

## 8. net10.0 版との機能差（重要）

| 機能 | net48（本ディレクトリ） | net10.0（`../MultiPurposeAuthSiteCore`） |
|---|---|---|
| ユーザ・ロール管理画面 | **✓ `UsersAdminController` / `RolesAdminController`**（`Config.EnableAdministrationOfUsersAndRoles` で開閉） | ✗ 無し |
| TOTP（Authenticator アプリ 2FA） | **✗ 無し** | ✓ あり（登録 / リカバリ コード / 管理） |
| FIDO2 サーバ用 WebAPI | △ `Fido2ServerController.cs` は在るが**ビルド対象外** | ✗ 無し |
| 疎通用 WebAPI | ✗ | ✓ `ValuesController`（`api/values/get`） |
| 外部ログインのプロキシ対応 | ✓（`BackchannelHttpHandler`） | ✗ |
| セッション | StateServer（既定） | 分散メモリ キャッシュ（開発用） |
| エラー画面の基底 | 素の `Controller` | `MyBaseMVControllerCore` |
| WebAuthn / MS Passport | ✗（`../CommonLibrary` 側ごと無効） | ✗（同左） |

**net48 側の View には、対応する機能が無いものが残っている。**
`Views/Home/WebAuthnStarters.cshtml` / `Views/Manage/Add{WebAuthn,MsPass}Data.cshtml` /
`Views/Manage/RemoveWebAuthnData.cshtml` は、FIDO が無効なので動かない（10 節）。

---

## 9. ビルドと実行

**Windows ＋ Visual Studio（MSBuild）が必須。** `dotnet build` では通らない（旧形式 csproj ＋ ASP.NET）。

```
../10_MultiPurposeAuthSite.bat        ← ../z_Common.bat で MSBuild を解決してから実行
  nuget.exe restore CommandLineTools\CommandLineTools.sln
  %BUILDFILEPATH% %COMMANDLINE% CommandLineTools\CommandLineTools.sln
  nuget.exe restore MultiPurposeAuthSite\MultiPurposeAuthSite.sln
  %BUILDFILEPATH% %COMMANDLINE% /t:Restore MultiPurposeAuthSite\MultiPurposeAuthSite.sln
```

- `../z_Common.bat` は VS 2017 / 2019 / 2022 / 18 の MSBuild パスを順に探し、
  **最後に `BUILDFILEPATH18`（VS 18 = 2026）を採る**。`BUILD_CONFIG=Debug` / `DEBUG_TYPE=full` 固定。
- `../z_Common2.bat` は devenv 版の差し替え用（現状どの bat からも呼ばれていない）。
- 実行は Visual Studio から IIS Express で。

> **Release 構成でビルドしないこと。**
> `../CommonLibrary/NetFxLibrary.csproj` の Release 構成には `NETFX` が定義されておらず、
> 条件コンパイルが .NET 側に落ちる（[`../CommonLibrary/ANALYSIS.md`](../CommonLibrary/ANALYSIS.md) 2.1 節）。
> 直すなら、まず csproj の `DefineConstants` を直す。

---

## 10. 落とし穴 / 既知の不整合

1. **`Controllers/Fido2ServerController.cs` は csproj の `<Compile Include>` に無い＝ビルドされない。**
   併せて FIDO / WebAuthn は**全面的に無効**である。
   - `AccountController` / `ManageController` の WebAuthn 分岐は `/* */` でコメント アウト
   - `../CommonLibrary/Extensions/FIDO/**` は net48 / net10.0 のどちらでもビルドされない
   - `../CommonLibrary/Co/Config.cs` の `FIDOServerMode` プロパティもコメント アウト
   - それでも `app.config` の `FIDOServerMode` キー、`Fido2` 4.0.0 の `PackageReference`、
     View と JS（`Scripts/touryo/{ms,ff}Webauthn.js` `webauthn.js`）は残っている

   詳細は [`../CommonLibrary/ANALYSIS.md`](../CommonLibrary/ANALYSIS.md) 12 節。
2. **`NetFxLibrary.csproj` の Release で `NETFX` が定義されない**（9 節）。
3. **ASP.NET 状態サービスが要る**（2.5 節）。落ちる原因として気付きにくい。
4. **`C:\` 直下配置が前提**（2.3 節）。`app.config` は `\` 区切り、`appsettings.json` は `/` 区切り。
5. **net10.0 版とポート・仮想パスが同じ**（2.6 節）。同時起動不可。
6. **CIBA のアクション名の書き分け**（5.1 節）。
7. **エンドポイント登録が MVC と Web API の 2 ファイルに分かれる**（5 節）。片方だけ直すと 404。
8. **Twitter の証明書拇印がハードコード**（4 節）。
9. **`packages.config` と `PackageReference` の混在**（2.2 節）。復元手段が 2 つ要る。
10. **`Scripts/` / `Content/` には NuGet 由来のファイルが大量に入っている**
    （bootstrap 5.3.8 / jQuery 3.7.1 / popper / modernizr / respond ほか）。
    自前のコードは `Scripts/app/` と `Scripts/touryo/` だけ。
11. **`.vs/` `bin/` `obj/` `packages/` が作業ツリーに残る。** いずれも `.gitignore` 済み。
12. **`Startup.cs` に `MultiPurposeAuthSite/Startup.cs` と
    `App_Start/StartupAuth.cs` の 2 つがある。** 前者は OWIN のエントリだけで、中身は後者。
13. **`ErrorController` の基底が系統で違う**（8 節）。エラー処理を触るときは両方を見る。

---

## 11. エージェント向け作業チェックリスト

- [ ] `AGENTS.md` のポリシー遵守（**git 操作をしない**）
- [ ] 変更が `../CommonLibrary` 側の話でないか確認する
      （ストア・トークン・設定・通知・リソースは全て向こう）
- [ ] **新規 `.cs` / `.cshtml` は `MultiPurposeAuthSite.csproj` に `<Compile Include>` /
      `<Content Include>` を明示追記する**（旧形式 csproj のため、置くだけでは含まれない）
- [ ] エンドポイントを足す → `Config` ＋ `_app.config` ＋
      `RouteConfig.cs` または `WebApiConfig.cs` ＋ **net10.0 側の `Startup.cs`**
- [ ] JS / CSS を足す → `Scripts/` or `Content/` ＋ `BundleConfig.cs` ＋
      **net10.0 側の `wwwroot/`**（配置が違う点に注意）
- [ ] 文言は直書きせずリソース（`../CommonLibrary/Resources`）へ
- [ ] `app.config`（実ファイル）を直したら、**同じ変更を `_app.config` にも**入れる。
      **秘密情報は転記しない**
- [ ] 新規 `.cs` にはヘッダ コメント（Apache License ＋ クラス名・日本語名・更新履歴）を付与。
      既存 `.cs` の変更時は更新履歴に 1 行追記
- [ ] ビルド確認: `../10_MultiPurposeAuthSite.bat`（**Debug 構成で**）
- [ ] net10.0 版に同じ変更が要るか判断し、要否を報告する
