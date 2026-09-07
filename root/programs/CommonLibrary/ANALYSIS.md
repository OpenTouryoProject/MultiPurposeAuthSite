# ANALYSIS.md — 汎用認証サイト ライブラリ部（CommonLibrary）コード分析

対象: `root/programs/CommonLibrary`（**net10.0 / net48 の 2 系統**） / ブランチ: `develop`
最終更新: 2026-09-07

本書は **コーディング・エージェントが本ディレクトリで作業する際の Context** を目的とした分析結果である。
「どこに何があるか」「どの規約に従うべきか」「何を壊しやすいか」を記す。

関連: `../MultiPurposeAuthSiteCore/ANALYSIS.md`（net10.0 の主要部）、
`../MultiPurposeAuthSite/ANALYSIS.md`（net48 の下位互換版）、
`../CommandLineTools/ANALYSIS.md`、`../authentication_device/ANALYSIS.md`。

---

## 1. これは何か

**汎用認証サイト（MultiPurposeAuthSite）の実装の実体は、ほぼ全てここに在る。**
`MultiPurposeAuthSiteCore`（net10.0）と `MultiPurposeAuthSite`（net48）の 2 つの Web アプリは
Controller / View / 起動処理だけを持ち、**ASP.NET Identity のストア、OAuth2/OIDC/SAML2 の
プロトコル実装、設定、通知、ロギングはすべて本ライブラリが持つ**。

- 立ち位置: Open棟梁（`OpenTouryo.*`）の上に乗るアプリケーション側のライブラリ。
  フレームワークではなく **アプリの一部**である。
- ライセンス: Apache-2.0（全 `.cs` の先頭に `#region Apache License` ヘッダ）。
- プロジェクト・ポリシーは **リポジトリ ルートの `AGENTS.md`（`CLAUDE.md` はそれへのポインタ）** に定義済み。
  → **エージェントは git 操作（add/commit/push/checkout/branch/reset/restore/stash）を行わない。**
  作業結果はワーキング ツリーに残し、変更内容を報告するに留める。

規模の目安: `.cs` 99 ファイル（`obj/` `bin/` 除く、`*.Designer.cs` 10 を含む）／
実装コード約 22,000 行（`*.Designer.cs` を除く）。

---

## 2. 1 つのソースから 2 つのアセンブリ（**最も事故りやすい箇所**）

**同じディレクトリのソースを、2 つの csproj が別々にビルドする。**
ディレクトリを分けず、`#if NETFX` と csproj のファイル選択で書き分ける方式である。

| | `NetFxLibrary.csproj` | `NetCoreLibrary.csproj` |
|---|---|---|
| csproj 形式 | **旧形式**（`ToolsVersion="15.0"` / `Microsoft.CSharp.targets`） | **SDK 形式**（`Microsoft.NET.Sdk`） |
| TFM | `v4.8` | `net10.0` |
| アセンブリ名 | `MultiPurposeAuthSite.NetFxLibrary` | `MultiPurposeAuthSite.NetCoreLibrary` |
| ルート名前空間 | `MultiPurposeAuthSite` | `MultiPurposeAuthSite` |
| 出力先 | `bin\netfx\{Debug,Release}\` | `bin\netcore\{Debug,Release}\net10.0\` |
| ファイルの選び方 | **`<Compile Include>` の明示列挙** | **ワイルドカード＋`<Compile Remove>`** |
| Identity | `Microsoft.AspNet.Identity.*` 2.2.4（OWIN） | `Microsoft.AspNetCore.App`（FrameworkReference） |
| 条件シンボル | `NETFX` | `NETCORE` |

### 2.1 プリプロセッサ シンボル

`#if NETFX` / `#else` の 2 分岐だけで書かれている（`NETCORE` は定義はされるが
`#if NETCORE` として使われる箇所はごく僅か）。該当は **27 ファイル / 71 箇所**。

> **不具合: `NetFxLibrary.csproj` の Release 構成で `NETFX` が定義されていない。**
>
> ```xml
> <!-- Debug|AnyCPU  -->  <DefineConstants>TRACE;DEBUG;NETFX</DefineConstants>
> <!-- Release|AnyCPU -->  <DefineConstants>TRACE</DefineConstants>   <!-- ★ NETFX が無い -->
> ```
>
> `NetCoreLibrary.csproj` は Debug / Release の**両方**で `NETCORE` を定義しており、非対称。
> Release でビルドすると全ての `#if NETFX` が `#else`（.NET Core 側）に落ちる。
> **net48 側は実質 Debug 構成でしかビルドできない**（`z_Common.bat` の既定も `Debug`）。
> 直すなら Release 側にも `NETFX` を足す。**影響が広いので、直したら必ず両構成をビルドして確かめること。**

### 2.2 名前空間が系統で違う（見落としやすい）

`Entity/ApplicationUser.cs` と `Entity/ApplicationRole.cs` は、**名前空間そのものを切り替えている。**

```csharp
#if NETFX
namespace MultiPurposeAuthSite.Entity
#else
namespace MultiPurposeAuthSite // ルートでないとダメ？
#endif
```

- net48 側は `IUser<string>` / `IRole<string>` を実装、.NET 側は素の POCO。
- 他ファイルの `using` も `#if NETFX` で振り分けてある。
  **エンティティに触るときは、両系統の `using` を確認すること。**

### 2.3 どちらでもビルドされないファイルがある

| ファイル | net48 | net10.0 |
|---|---|---|
| `Extensions/FIDO/{DataProvider,EnumFidoType,MsPassHelper,WebAuthnHelper}.cs` | **✗ 列挙されていない** | **✗ `Compile Remove`** |
| `Data/UserStore.cs` | ✓ | ✗ `Compile Remove` |
| `Data/{UserStoreCore,RoleStoreCore}.cs` | ✗ | ✓ |
| `Manager/**`（`Application{User,Role,SignIn}Manager`） | ✓ | ✗ `Compile Remove` |
| `Notifications/{EmailService,SmsService}.cs` | ✓ | ✗ `Compile Remove` |
| `Notifications/{IEmailSender,EmailSender,ISmsSender,SmsSender}.cs` | ✗ | ✓ |
| `Util/IdP/ExternalLoginStarter.cs` | ✓ | ✗ `Compile Remove` |
| `Properties/AssemblyInfo.cs` | ✓ | ✗ `Compile Remove` |
| `ViewModels/*TwoFactorAuthenticator*.cs`（TOTP 系 5 件） | ✗ | ✓ |

**→ `Extensions/FIDO/**` は 4 ファイルとも死んでいる（12 節）。**

**新規ファイルを足すときの注意:**
- .NET 側は SDK 形式なので**黙って含まれる**。net48 専用 API を使うなら `Compile Remove` が要る。
- net48 側は明示列挙なので**書かないと含まれない**。追加を忘れると「.NET では通るが net48 で
  型が見つからない」という形で出る。

---

## 3. ディレクトリと責務

| ディレクトリ | 中身 | 主なクラス |
|---|---|---|
| `Co/` | 設定と定数 | `Config`(1723 行) `Const` |
| `Data/` | ASP.NET Identity のストア実装とデータ アクセス | `CmnUserStore`(3089) `CmnRoleStore` `CmnStore` `UserStore`(net48) `UserStoreCore`/`RoleStoreCore`(.NET) `DataAccess` `EnumUserStoreType` `TraceDbProfiler` `CompositeDbProfiler` `StopUserStoreException` |
| `Entity/` | エンティティ | `ApplicationUser` `ApplicationRole` |
| `Extensions/Sts/` | OAuth2 拡張フローの実装 | `Helper`(1249) `DeviceAuthZProvider`(646) `CibaProvider`(505) `DataProvider` `RevocationProvider` `RequestObjectProvider` `IssuedTokenProvider` |
| `Extensions/FIDO/` | WebAuthn / MS Passport | **現在ビルド対象外**（12 節） |
| `Log/` | ロギングの façade | `Logging`（`ACCESS` / `SQLTRACE` ロガー） |
| `Manager/` | ASP.NET Identity の Manager（**net48 のみ**） | `ApplicationUserManager` `ApplicationRoleManager` `ApplicationSignInManager` |
| `Network/` | HTTP まわり | `WebAPIHelper` `CreateProxy` |
| `Notifications/` | メール / SMS / プッシュ通知 | `CmnEmail` `CmnSms` `FcmService`、net48 は `*Service`、.NET は `*Sender` |
| `Password/` | パスワード ハッシュ | `CustomPasswordHasher`（両系統の型を 1 ファイルに同居） |
| `Resources/` | 多言語リソース | `*.resx` / `*.ja.resx` の 10 組 |
| `SamlProviders/` | SAML2 のエンドポイント実装 | `CmnEndpoints` |
| `TokenProviders/` | OAuth2/OIDC の中核 | `CmnEndpoints`(2162) `CmnAccessToken`(682) `CmnIdToken` `CmnResponseObject` `AuthorizationCodeProvider` `RefreshTokenProvider` |
| `Util/` | 雑多なユーティリティ | `IdP/CheckRole` `IdP/CustomizedConfirmationProvider` `IdP/GetContentOfLetter` `PPIDExtension` `UriExtension` `Sts/OnlySts` |
| `ViewModels/` | 画面のモデル 32 件 | `BaseViewModel` ほか |

---

## 4. ASP.NET Identity のストア（Entity Framework を使わない）

**EF は使わず、Dapper による自前ストアを実装している。** 構造は 3 層。

```
[net48]                                  [.NET 10]
UserStore : IUserStore<...> ほか          UserStoreCore : IUserStore<ApplicationUser> ほか
        \                                /
         \                              /
          → CmnUserStore（3089 行）←──┘      … 実処理はここに集約
                    ↓
             CmnStore（Memory の実体 ＋ 子テーブル読み込み）
                    ↓
             DataAccess.CreateConnection() → Dapper
```

- `UserStore` / `UserStoreCore` は **インターフェイス実装のアダプタ**であり、
  中身は `CmnUserStore` の static メソッドを呼ぶだけ。**ロジックを足すなら `CmnUserStore` 側。**
- 実装済みインターフェイス（ファイル冒頭のコメントが一次情報）:
  `IUserStore` `IQueryableUserStore` `IUserPasswordStore` `IUserEmailStore` `IUserPhoneNumberStore`
  `IUserRoleStore` `IUserSecurityStampStore` `IUserLockoutStore` `IUserTwoFactorStore`
  `IUserAuthenticatorKeyStore` `IUserAuthenticationTokenStore` `IUserTwoFactorRecoveryCodeStore`
  `IUserLoginStore` `IUserClaimStore`
- ロール側も同じ形（`CmnRoleStore` ← `RoleStoreCore` / net48 は `UserStore` と同居）。

### 4.1 UserStore の 4 プロバイダ

`Config.UserStoreType`（`appSettings:UserStoreType`）で切り替わる。

| 設定値 | `EnumUserStoreType` | 接続文字列キー | 備考 |
|---|---|---|---|
| `mem` | `Memory` | — | `CmnStore` の `static List<>` 3 本。**プロセス内のみ。既定** |
| `sql` | `SqlServer` | `ConnectionString_SQL` | `Microsoft.Data.SqlClient`(.NET) / `System.Data.SqlClient`(net48) |
| `ora` | `ODPManagedDriver` | `ConnectionString_ODP` | `Oracle.ManagedDataAccess` |
| `npg` | `PostgreSQL` | `ConnectionString_NPS` | `Npgsql`。**`#if NETCORE` で囲まれており net48 では選べない** |

- 接続は必ず `DataAccess.CreateConnection()` を通す。`ProfiledDbConnection`（MiniProfiler）で
  `TraceDbProfiler` を挟み、SQL を `SQLTRACE` ロガーへ落としている。
- **DBMS ごとに識別子の引用規則が違う**（SQL Server は `[Roles]`、Oracle は `"Roles"`、
  PostgreSQL は `"roles"` と**小文字**）。SQL を足すときは 3 通り書くことになる。
  `DataAccess.IsDBMSInitialized()` がその最小例。
- DDL は `root/files/resource/MultiPurposeAuthSite/Sql/{sqlserver,oracle,pstgrs}/Create_UserStore.sql`。
  テーブルは 16 本（`Users` `Roles` `UserRoles` `UserLogins` `UserClaims` `TotpTokens`
  `AuthenticationCodeDictionary` `RefreshTokenDictionary` `CustomizedConfirmation`
  `Saml2OAuth2Data` `FIDO2Data` `DeviceAuthZData` `CibaData` `OAuth2Revocation`
  `IssuedToken` `RequestObject`）。**3 方言すべてを直すこと。**
- Docker で DBMS を立てる一式は `store/`（`docker-compose.yml` ＋ `0_CopyInitSql.ps1`）。
  `0_CopyInitSql.ps1` が上記 DDL を `store/*/init/` へコピーし、**CRLF を LF に変換**する
  （Linux コンテナの初期化スクリプトが読むため）。

### 4.2 STS 専用モード（機能ロックダウン）

`Util/Sts/OnlySts` が、次の 3 つが**すべて false のとき**「STS 専用モード」と判定する。

```
Config.EnableSignupProcess / EnableEditingOfUserAttribute / EnableAdministrationOfUsersAndRoles
```

- `OnlySts.STSOnly_P`（bool）と `OnlySts.STSOnly_M()`（`StopUserStoreException` を投げる）の 2 形態。
- `CmnStore.SelectChildTablesOfUser` などが `STSOnly_P` を見て**子テーブルを読まない**。
- **呼び出しの多くはコメント アウトされている**（`//OnlySts.STSOnly_M();`）。
  「効いているつもり」で読まないこと。実際に効いている箇所を grep で確かめてから触る。

---

## 5. 設定（`Co/Config.cs`）

**設定値の入口は 1 つ。全て `Config` の static プロパティで、`GetConfigParameter`（Open棟梁）を呼ぶ。**

```csharp
public static bool RequireUniqueEmail
    => Convert.ToBoolean(GetConfigParameter.GetConfigValue("RequireUniqueEmail"));
```

- net48 は `app.config` / `Web.config` の `<appSettings>`、.NET は `appsettings.json` の
  `"appSettings"` セクション。**キー名は両者で共通**なので、設定を足すときは**両方**に足す。
- `#if NETFX` で `Newtonsoft.Json` / `Microsoft.Extensions.Configuration` を切り替えている。
- 主な区分（`#region` の並び）: Proxy / IsDebug / UserStore / 事前登録ユーザ / Notification Provider /
  ログイン（ユーザ名・パスワード検証、ロックアウト、Cookie、2FA、外部ログイン）/ SecurityStamp /
  属性編集の可否 / FIDO / STS（証明書・SAML2・OAuth2）/ 外部サービス（Stripe・PAY.JP）/
  機能ロックダウン / IDフェデレーション。

> **`Config` にプロパティを足したら、`_app.config` と `_appsettings.json`（テンプレート）にも
> 既定値を足すこと。** テンプレートを更新しないと、他の開発者の環境では `null` になる（6 節）。

---

## 6. 設定ファイルは 2 系統ある（**秘密情報の扱い**）

| 実ファイル | テンプレート | git |
|---|---|---|
| `../MultiPurposeAuthSite/MultiPurposeAuthSite/app.config` | `_app.config` | **実ファイルは `.gitignore`** |
| `../MultiPurposeAuthSiteCore/MultiPurposeAuthSiteCore/appsettings.json` | `_appsettings.json` | **実ファイルは `.gitignore`** |

- テンプレート側は `"[Please fill in this input item.]"` などのプレースホルダで、
  外部サービスの有効化フラグはすべて `false`。
- **実ファイル側には、実在する認証情報が入っている**（管理者アカウント、SMTP、Twilio、
  Stripe / PAY.JP、外部ログインの ClientSecret、`SaltParameter` など）。

> **エージェントの禁止事項:**
> - `app.config` / `appsettings.json` の**中身を報告やコミット メッセージに転記しない**。
> - これらを git 管理下へ戻さない（`.gitignore` を緩めない）。
> - 設定項目を増やすときは **`_app.config` / `_appsettings.json` を直し**、
>   実ファイルへの反映は人に依頼する。

---

## 7. OAuth2 / OIDC / SAML2 の実装

Open棟梁の `Touryo.Infrastructure.Framework.Authentication`（`OAuth2AndOIDCConst` /
`OAuth2AndOIDCParams` / `CmnClientParams` / `JwtAssertion` / `SAML2Client` ほか）の上に、
**認可サーバ側（AuthZ Server / STS）をスクラッチで実装**している。

### 7.1 中核

| ファイル | 役割 |
|---|---|
| `TokenProviders/CmnEndpoints.cs`（2162 行） | **本体。** `.well-known/openid-configuration` の生成、認可要求の検証（`ValidateAuthZReqParam` / `ValidateCibaAuthZReqParam` / `CheckRedirectUri`）、応答の生成（`CreateCodeInAuthZNRes` / `CreateAuthZRes4ImplicitFlow` / `CreateAuthNRes4HybridFlow`）、Token エンドポイントの各グラント（`GrantAuthorizationCodeCredentials` / `GrantRefreshTokenCredentials` / `GrantResourceOwnerCredentials` ほか） |
| `TokenProviders/CmnAccessToken.cs` | アクセス トークンの生成（Claim 集合の組み立て → JWS 化）と検証 |
| `TokenProviders/CmnIdToken.cs` | id_token |
| `TokenProviders/CmnResponseObject.cs` | JARM（Response Object） |
| `TokenProviders/AuthorizationCodeProvider.cs` / `RefreshTokenProvider.cs` | code / refresh_token の保管（Memory or DBMS） |
| `Extensions/Sts/Helper.cs`（1249 行） | **クライアント情報のレジストリ**。`OAuth2ClientsInformation` から client_secret / redirect_uri / JWK 公開鍵 / `tls_client_auth_subject_dn` / subject_types / client mode を引く。加えて各フローの WebAPI 呼び出しヘルパ（シングルトン、`GetInstance`） |
| `Extensions/Sts/DeviceAuthZProvider.cs` | Device Authorization Grant |
| `Extensions/Sts/CibaProvider.cs` | CIBA（FAPI）。FCM プッシュと連携 |
| `Extensions/Sts/RevocationProvider.cs` / `IssuedTokenProvider.cs` | revoke / introspect の裏付けデータ |
| `Extensions/Sts/RequestObjectProvider.cs` | Request Object の登録（`/ros`） |
| `SamlProviders/CmnEndpoints.cs` | SAML2 の Request / Response |
| `Util/PPIDExtension.cs` | `subject_types`（`public` / `pairwise` / `uname`）に応じた sub の生成 |

### 7.2 対応しているグラント / 拡張

`Config` の `Enable*GrantType` で個別に有効・無効を切り替える。

- Authorization Code（PKCE 含む）／ Implicit ／ Hybrid
- Resource Owner Password Credentials ／ Client Credentials
- JWT Bearer Token Flow ／ Refresh Token
- Device Authorization Grant ／ CIBA
- Revocation ／ Introspection ／ UserInfo ／ JWK Set ／ Request Object ／ JARM
- FAPI1 / FAPI2（クライアント個別に `oauth2_oidc_mode` で指定）
- SAML2（IdP 側）
- ID フェデレーション（`IdFederation*EndPoint` で別の汎用認証サイトへ委譲）

### 7.3 クライアント定義

`appSettings:OAuth2ClientsInformation` に **client_id をキーとした JSON 辞書**で持つ。

```json
"67d328bf...": {
  "client_secret": "...", "client_name": "TestClient",
  "redirect_uri_code": "test_self_code", "redirect_uri_token": "test_self_token",
  "subject_types": "uname",          // public / pairwise / uname
  "oauth2_oidc_mode": "fapi1",       // fapi1 / fapi2 / device / fapi_ciba
  "jwk_rsa_publickey": "...", "jwk_ecdsa_publickey": "...",
  "tls_client_auth_subject_dn": "..."
}
```

- `test_self_code` / `test_self_token` は**自己テスト用の予約値**（`Const.TestSelfCode` ほか）。
  `IsLockedDownRedirectEndpoint` で本番時に閉じられる。
- この節は `../CommandLineTools/CreateClientsIdentity` で雛形を生成できる。

### 7.4 署名鍵

`root/files/resource/X509/` の `.pfx` / `.cer` を `Config.RsaPfxFilePath` などで参照する。
JWK Set（`/jwkcerts` が返す `JwkSet.json`）は
`../CommandLineTools/CreateJwkSetJson` が `.cer` から生成する。
**証明書を差し替えたら JwkSet.json を作り直すこと。**

---

## 8. 通知（メール / SMS / プッシュ）

| | net48 | .NET 10 |
|---|---|---|
| メール | `Notifications/EmailService`（`IIdentityMessageService`） | `Notifications/EmailSender`（`IEmailSender`、DI 登録） |
| SMS | `Notifications/SmsService` | `Notifications/SmsSender`（`ISmsSender`、DI 登録） |
| 実体 | **`CmnEmail` / `CmnSms` は共通**（SMTP / Twilio） | 同左 |
| プッシュ | `Notifications/FcmService`（Firebase Admin SDK） | 同左（共通） |

- FCM は 2FA のプッシュ承認と CIBA の同意要求に使う。宛先は `Users.DeviceToken`
  （`../authentication_device` が `/SetDeviceToken` で登録する）。
- メール文面は `root/files/resource/MultiPurposeAuthSite/Txt/*.txt`（`.ja` 付きで日英）。
  読み出しは `Util/IdP/GetContentOfLetter`。

---

## 9. ロギング

`Log/Logging` が Open棟梁の `LogIF` を包む。**ロガー名は `"ACCESS"` と `"SQLTRACE"` の 2 つ。**

| メソッド | 出力先 | 制御 |
|---|---|---|
| `MyDebugTrace` / `MyDebugLogForEx` | `ACCESS` | `Config.IsDebug` で `Debug.WriteLine`、`Config.EnabeDebugTraceLog` で `LogIF.DebugLog` |
| `MyDebugSQLTrace` / `MySQLLogForEx` | `SQLTRACE` | 同上 |

- log4net の構成は `appSettings:FxLog4NetConfFile`
  （既定 `C:/root/files/resource/Log/SampleLogConf.xml`）。
- **設定キー名の綴りは `EnabeDebugTraceLog`**（`Enable` ではない）。設定ファイル側もこの綴り。
  直すなら `Config.cs` と `_app.config` / `_appsettings.json` を同時に。

---

## 10. 多言語リソース

`Resources/` に 10 組の `.resx`（既定＝英語）＋ `.ja.resx`。
`PublicResXFileCodeGenerator` で `*.Designer.cs` を生成している（`public` 可視性）。

`AccountController` `AccountViews` `AdminController` `AdminViews`
`ApplicationOAuthBearerTokenProvider` `ApplicationUserManager` `CommonViewModels`
`ManageController` `ManageViews` `SharedViews`

- **文言は必ずリソースへ。** Controller / View に直書きしない。
- net48 側は `.resx` / `.ja.resx` を `<EmbeddedResource Include>` で明示列挙している。
  **新しい resx を足したら `NetFxLibrary.csproj` に 2 行足すこと**（.NET 側は自動）。

---

## 11. 依存パッケージ

| | net48（`NetFxLibrary.csproj`、`PackageReference` 形式） | net10.0（`NetCoreLibrary.csproj`） |
|---|---|---|
| ORM | `Dapper` 2.1.66 | `Dapper` 2.1.66 |
| DB | `Oracle.ManagedDataAccess` 23.26.0 | `Microsoft.Data.SqlClient` 6.1.4 / `System.Data.SqlClient` 4.9.0 / `Npgsql` 10.0.1 / `Oracle.ManagedDataAccess.Core` 23.26.0 |
| 計測 | `MiniProfiler` 4.5.4 | `MiniProfiler.AspNetCore.Mvc` 4.5.4 |
| JSON | `Newtonsoft.Json` 13.0.4 | `Newtonsoft.Json` 13.0.4 |
| Identity | `Microsoft.AspNet.Identity.{Core,Owin}.ja` 2.2.4 / `Microsoft.Owin.Security.{Cookies,OAuth}` 4.2.3 | `Microsoft.AspNetCore.App`（FrameworkReference） |
| 暗号 | `System.IdentityModel.Tokens.Jwt` 8.15.0 | `BouncyCastle.NetCore` 2.2.1 |
| 通知 | `FirebaseAdmin` 3.4.0 / `Twilio` 7.14.0 | `FirebaseAdmin` 3.4.0 / `Twilio` 7.14.1 |
| FIDO | `Fido2` 4.0.0（**参照だけ残り、使うコードは無い**） | — |
| Open棟梁 | `../OpenTouryoAssemblies/Build_net48/*.dll` を `HintPath` | `../OpenTouryoAssemblies/Build_netcore100/net10.0/*.dll` を `HintPath` |

**版が微妙にズレている**（`Twilio` 7.14.0 / 7.14.1 など）。揃えるかどうかは別途判断。
正確な値は csproj を直接見ること。

### 11.1 Open棟梁アセンブリは `ProjectReference` ではない

`OpenTouryo.{Public,Public.Security,Framework,Business}` は
`../OpenTouryoAssemblies/` を **`HintPath` で直接参照**する。
`OpenTouryoAssemblies/` は `.gitignore` 対象で、次のいずれかで用意する。

- `../3_BuildLibsAtOtherRepos.bat` … 指定タグ（`03-20`）の zip を取得してビルド＆コピー
- `../3_BuildLibsAtOtherReposInTimeOfDev.bat` … `develop` の zip で同上
- `mpas_dev.bat`（リポジトリ ルート）… 隣に clone 済みの OpenTouryo からビルド出力を xcopy

**Open棟梁を更新したら、必ずコピーし直してからビルドすること。**

---

## 12. 落とし穴 / 既知の不整合（作業前に把握しておく）

1. **`NetFxLibrary.csproj` の Release 構成に `NETFX` が無い**（2.1 節）。
   Release でビルドすると全ての条件コンパイルが .NET 側に落ちる。
2. **`ApplicationUser` / `ApplicationRole` は名前空間が系統で違う**（2.2 節）。
3. **`Extensions/FIDO/**` は 4 ファイルとも、どちらの csproj からもビルドされない。**
   併せて次も**すべて無効化されている**。
   - `Co/Config.cs` の `FIDOServerMode` プロパティは `/* */` でコメント アウト。
   - `../MultiPurposeAuthSite` / `../MultiPurposeAuthSiteCore` の
     `AccountController` / `ManageController` の WebAuthn 分岐もコメント アウト
     （`//using FIDO = MultiPurposeAuthSite.Extensions.FIDO;`）。
   - net48 側の `Controllers/Fido2ServerController.cs` は**ファイルは在るが csproj の
     `<Compile Include>` に無い**（＝ビルドされない）。
   - それでも `_app.config` / `_appsettings.json` には `FIDOServerMode` キーが残り、
     `NetFxLibrary.csproj` には `Fido2` 4.0.0 の `PackageReference` が残り、
     `Views/Manage/Add{WebAuthn,MsPass}Data.cshtml` などの View も残っている。

   **FIDO/WebAuthn は「設定は在るが動かない」状態である。** 復活させるなら
   csproj への追加・`Config` のコメント解除・Controller のコメント解除がセットで要る。
4. **`Data/UserStore.cs` と `Data/UserStoreCore.cs` は薄いアダプタ。**
   実装を足すなら `CmnUserStore`。片方だけ直すと系統間で挙動がズレる。
5. **TOTP（Authenticator アプリによる 2FA）は .NET 側にしか無い。**
   `ViewModels/*TwoFactorAuthenticator*.cs` 5 件は net48 の csproj に載っていない
   （`../MultiPurposeAuthSite/ANALYSIS.md` 参照）。
6. **DBMS 3 方言の識別子引用が違う**（4.1 節）。SQL を足したら 3 つとも直す。
7. **`OnlySts.STSOnly_M()` の呼び出しは多くがコメント アウト済み。**
   STS 専用モードの効き方を前提にした変更をする前に、実際の呼び出しを grep すること。
8. **設定ファイルは実ファイルとテンプレートの 2 本立て**（6 節）。実ファイルは秘密情報を含む。
9. **`EnabeDebugTraceLog` の綴り**（9 節）。
10. **`Password/CustomPasswordHasher.cs` は 1 ファイルに 2 つの型を持つ**
    （net48 用 `CustomPasswordHasher : IPasswordHasher` と
    .NET 用 `CustomPasswordHasher<TUser> : PasswordHasher<TUser>`）。
11. **`Notifications/` の命名が系統で違う**（`*Service` / `*Sender`）。共通処理は `Cmn*` 側。
12. **`ViewModels/ErrorViewModel.cs` だけ Shift_JIS。** 他は BOM 付き UTF-8。
    編集ツールによっては保存時に壊れる。**新規ファイルは BOM 付き UTF-8 で作ること。**
    （`../MultiPurposeAuthSiteCore` 側にも同種のファイルが 2 件ある。）
13. **`bin/` `obj/` が作業ツリーに残る。** `.gitignore` 済みだが、
    `bin\netfx\` と `bin\netcore\` の 2 系統が並ぶ点に注意。

---

## 13. エージェント向け作業チェックリスト

- [ ] `AGENTS.md` のポリシー遵守（**git 操作をしない**）
- [ ] 変更対象が net48 / net10.0 / 両方のどれか判定する
      （**net48 は `<Compile Include>` への追記、.NET は `<Compile Remove>` の要否**）
- [ ] 条件コンパイルは `#if NETFX` / `#else` の 2 分岐で書く。
      **Release で `NETFX` が定義されない問題を踏まないよう、net48 は Debug でビルドして確かめる**
- [ ] 実装は `Cmn*`（`CmnUserStore` / `CmnRoleStore` / `CmnEmail` / `CmnEndpoints`）に置く。
      `UserStore` / `UserStoreCore` はアダプタに留める
- [ ] 設定を足したら `Co/Config.cs` ＋ `_app.config` ＋ `_appsettings.json` の 3 点セット
- [ ] 文言はリソース（`Resources/*.resx` ＋ `*.ja.resx`）へ。
      **新規 resx は `NetFxLibrary.csproj` にも 2 行足す**
- [ ] SQL を足したら `sqlserver` / `oracle` / `pstgrs` の 3 方言すべて
- [ ] 新規 `.cs` にはヘッダ コメント（Apache License ＋ クラス名・日本語名・更新履歴）を付与。
      既存 `.cs` の変更時は更新履歴に 1 行追記
- [ ] public / protected メンバに日本語 `<summary>` を付与
- [ ] 新規 `.cs` は **BOM 付き UTF-8** で保存する
- [ ] ビルド確認:
      `dotnet build root/programs/MultiPurposeAuthSiteCore/MultiPurposeAuthSiteCore.sln`
      （net48 は MSBuild ＋ `../10_MultiPurposeAuthSite.bat`）
- [ ] **`app.config` / `appsettings.json` の中身を報告に転記しない**
